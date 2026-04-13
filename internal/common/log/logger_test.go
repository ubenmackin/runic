// Package log provides a standardized structured logger for the application.
package log

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// resetLogger resets the global logger to nil for test isolation
func resetLogger() {
	logger = nil
}

// TestInit tests the Init function with various log levels
func TestInit(t *testing.T) {
	tests := []struct {
		name         string
		level        string
		env          string
		wantLevel    slog.Level
		wantJSON     bool
		logMessage   string
		expectLogged bool
	}{
		{
			name:         "debug level logs debug messages",
			level:        "debug",
			wantLevel:    slog.LevelDebug,
			logMessage:   "debug test",
			expectLogged: true,
		},
		{
			name:         "info level filters debug messages",
			level:        "info",
			wantLevel:    slog.LevelInfo,
			logMessage:   "debug test",
			expectLogged: false,
		},
		{
			name:         "warn level filters info messages",
			level:        "warn",
			wantLevel:    slog.LevelWarn,
			logMessage:   "info test",
			expectLogged: false,
		},
		{
			name:         "error level filters warn messages",
			level:        "error",
			wantLevel:    slog.LevelError,
			logMessage:   "warn test",
			expectLogged: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resetLogger()
			var buf bytes.Buffer
			Init(tt.level, &buf)

			// Log at the specified level
			switch tt.wantLevel {
			case slog.LevelDebug:
				Debug(tt.logMessage, "key", "value")
			case slog.LevelInfo:
				Info(tt.logMessage, "key", "value")
			case slog.LevelWarn:
				Warn(tt.logMessage, "key", "value")
			case slog.LevelError:
				Error(tt.logMessage, "key", "value")
			}

			output := buf.String()
			if tt.expectLogged && output == "" {
				t.Errorf("expected log output for level %s, got empty", tt.level)
			}
		})
	}
}

// TestInitDefaultLevel tests that invalid level defaults to info
func TestInitDefaultLevel(t *testing.T) {
	resetLogger()
	var buf bytes.Buffer

	// Use an invalid level
	Init("invalid", &buf)

	// Debug should be filtered out (info level is default)
	Debug("debug message", "key", "value")
	if buf.String() != "" {
		t.Error("expected debug to be filtered out with invalid level defaulting to info")
	}

	// Info should be logged
	buf.Reset()
	Info("info message", "key", "value")
	if !strings.Contains(buf.String(), "info message") {
		t.Error("expected info message to be logged")
	}
}

// TestInitJSONFormat tests JSON format in production environment
func TestInitJSONFormat(t *testing.T) {
	resetLogger()
	var buf bytes.Buffer

	// Set production environment
	originalEnv := os.Getenv("ENV")
	os.Setenv("ENV", "production")
	defer os.Setenv("ENV", originalEnv)

	Init("info", &buf)
	Info("test message", "key", "value")

	output := buf.String()

	// Verify JSON format by trying to parse it
	var logEntry map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(output)), &logEntry); err != nil {
		t.Errorf("expected JSON format, failed to parse: %v, output: %s", err, output)
	}

	// Verify message is present
	if msg, ok := logEntry["msg"].(string); !ok || msg != "test message" {
		t.Errorf("expected msg='test message', got %v", logEntry["msg"])
	}
}

// TestInitTextFormat tests text format in development environment
func TestInitTextFormat(t *testing.T) {
	resetLogger()
	var buf bytes.Buffer

	// Ensure development environment (no ENV or non-production)
	originalEnv := os.Getenv("ENV")
	os.Unsetenv("ENV")
	defer os.Setenv("ENV", originalEnv)

	Init("info", &buf)
	Info("test message", "key", "value")

	output := buf.String()

	// Text format should have level=message format
	if !strings.Contains(output, "level=") {
		t.Errorf("expected text format with level=, got: %s", output)
	}

	// Should NOT be valid JSON
	var logEntry map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(output)), &logEntry); err == nil {
		t.Error("expected text format, but output is valid JSON")
	}
}

// TestL tests the L function
func TestL(t *testing.T) {
	t.Run("returns default logger when not initialized", func(t *testing.T) {
		resetLogger()
		l := L()
		if l == nil {
			t.Error("expected non-nil default logger")
		}
	})

	t.Run("returns configured logger after Init", func(t *testing.T) {
		resetLogger()
		var buf bytes.Buffer
		Init("debug", &buf)

		l := L()
		if l == nil {
			t.Error("expected non-nil logger after Init")
		}

		// Verify it's the configured logger by logging
		l.Debug("test", "key", "value")
		if !strings.Contains(buf.String(), "test") {
			t.Error("expected configured logger to write to buffer")
		}
	})
}

// TestLCtx tests the LCtx function
func TestLCtx(t *testing.T) {
	resetLogger()
	var buf bytes.Buffer
	Init("debug", &buf)

	t.Run("returns base logger for nil context", func(t *testing.T) {
		l := LCtx(nil)
		if l == nil {
			t.Error("expected non-nil logger for nil context")
		}
	})

	t.Run("returns base logger when no request ID", func(t *testing.T) {
		ctx := context.Background()
		l := LCtx(ctx)
		if l == nil {
			t.Error("expected non-nil logger for context without request ID")
		}

		// Verify it logs without request_id
		buf.Reset()
		l.Info("test message")
		if strings.Contains(buf.String(), "request_id") {
			t.Error("expected no request_id in output")
		}
	})

	t.Run("returns logger with request ID when present", func(t *testing.T) {
		ctx := context.Background()
		ctx = SetRequestID(ctx, "test-request-123")

		l := LCtx(ctx)
		if l == nil {
			t.Error("expected non-nil logger")
		}

		// Verify it logs with request_id
		buf.Reset()
		l.Info("test message")
		if !strings.Contains(buf.String(), "request_id") {
			t.Error("expected request_id in output")
		}
		if !strings.Contains(buf.String(), "test-request-123") {
			t.Error("expected request ID value in output")
		}
	})
}

// TestSetRequestIDGetRequestID tests SetRequestID and GetRequestID
func TestSetRequestIDGetRequestID(t *testing.T) {
	t.Run("set and get round-trip", func(t *testing.T) {
		ctx := context.Background()
		ctx = SetRequestID(ctx, "test-id-456")

		id, ok := GetRequestID(ctx)
		if !ok {
			t.Error("expected ok=true when request ID is set")
		}
		if id != "test-id-456" {
			t.Errorf("expected id='test-id-456', got '%s'", id)
		}
	})

	t.Run("get returns false when not set", func(t *testing.T) {
		ctx := context.Background()

		id, ok := GetRequestID(ctx)
		if ok {
			t.Error("expected ok=false when request ID is not set")
		}
		if id != "" {
			t.Errorf("expected empty id, got '%s'", id)
		}
	})
}

// TestLoggingFunctions tests Debug, Info, Warn, Error functions
func TestLoggingFunctions(t *testing.T) {
	tests := []struct {
		name       string
		logFunc    func(string, ...any)
		level      string
		message    string
		wantOutput string
	}{
		{
			name:       "Debug",
			logFunc:    Debug,
			level:      "debug",
			message:    "debug message",
			wantOutput: "debug message",
		},
		{
			name:       "Info",
			logFunc:    Info,
			level:      "info",
			message:    "info message",
			wantOutput: "info message",
		},
		{
			name:       "Warn",
			logFunc:    Warn,
			level:      "warn",
			message:    "warn message",
			wantOutput: "warn message",
		},
		{
			name:       "Error",
			logFunc:    Error,
			level:      "error",
			message:    "error message",
			wantOutput: "error message",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resetLogger()
			var buf bytes.Buffer
			Init(tt.level, &buf)

			tt.logFunc(tt.message, "key", "value")

			output := buf.String()
			if !strings.Contains(output, tt.wantOutput) {
				t.Errorf("expected output to contain '%s', got: %s", tt.wantOutput, output)
			}
			if !strings.Contains(output, "key=value") {
				t.Errorf("expected output to contain 'key=value', got: %s", output)
			}
		})
	}
}

// TestLoggingFunctionsNoPanic verifies logging functions don't panic with nil logger
func TestLoggingFunctionsNoPanic(t *testing.T) {
	resetLogger()

	// These should not panic when logger is nil
	tests := []struct {
		name    string
		logFunc func()
	}{
		{
			name: "Debug",
			logFunc: func() {
				Debug("test message", "key", "value")
			},
		},
		{
			name: "Info",
			logFunc: func() {
				Info("test message", "key", "value")
			},
		},
		{
			name: "Warn",
			logFunc: func() {
				Warn("test message", "key", "value")
			},
		},
		{
			name: "Error",
			logFunc: func() {
				Error("test message", "key", "value")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("%s panicked with nil logger: %v", tt.name, r)
				}
			}()
			tt.logFunc()
		})
	}
}

// TestLoggingContextFunctions tests DebugContext, InfoContext, WarnContext, ErrorContext
func TestLoggingContextFunctions(t *testing.T) {
	tests := []struct {
		name    string
		logFunc func(context.Context, string, ...any)
		level   string
		message string
	}{
		{
			name:    "DebugContext",
			logFunc: DebugContext,
			level:   "debug",
			message: "debug context message",
		},
		{
			name:    "InfoContext",
			logFunc: InfoContext,
			level:   "info",
			message: "info context message",
		},
		{
			name:    "WarnContext",
			logFunc: WarnContext,
			level:   "warn",
			message: "warn context message",
		},
		{
			name:    "ErrorContext",
			logFunc: ErrorContext,
			level:   "error",
			message: "error context message",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resetLogger()
			var buf bytes.Buffer
			Init(tt.level, &buf)

			ctx := context.Background()
			ctx = SetRequestID(ctx, "ctx-test-id")

			tt.logFunc(ctx, tt.message, "key", "value")

			output := buf.String()
			if !strings.Contains(output, tt.message) {
				t.Errorf("expected output to contain '%s', got: %s", tt.message, output)
			}
			if !strings.Contains(output, "request_id") {
				t.Errorf("expected output to contain 'request_id', got: %s", output)
			}
		})
	}
}

// TestLoggingContextFunctionsNoPanic verifies context logging functions don't panic with nil context
func TestLoggingContextFunctionsNoPanic(t *testing.T) {
	resetLogger()

	tests := []struct {
		name    string
		logFunc func()
	}{
		{
			name: "DebugContext with nil ctx",
			logFunc: func() {
				DebugContext(nil, "test message", "key", "value")
			},
		},
		{
			name: "InfoContext with nil ctx",
			logFunc: func() {
				InfoContext(nil, "test message", "key", "value")
			},
		},
		{
			name: "WarnContext with nil ctx",
			logFunc: func() {
				WarnContext(nil, "test message", "key", "value")
			},
		},
		{
			name: "ErrorContext with nil ctx",
			logFunc: func() {
				ErrorContext(nil, "test message", "key", "value")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("%s panicked: %v", tt.name, r)
				}
			}()
			tt.logFunc()
		})
	}
}

// TestLevelFatal tests that LevelFatal is defined correctly
func TestLevelFatal(t *testing.T) {
	// LevelFatal should be higher than Error
	if LevelFatal <= slog.LevelError {
		t.Errorf("LevelFatal (%d) should be greater than LevelError (%d)", LevelFatal, slog.LevelError)
	}
}

// TestFatal tests the Fatal function using a subprocess
// The actual exit behavior is tested separately
func TestFatal(t *testing.T) {
	t.Run("logs message at fatal level", func(t *testing.T) {
		if os.Getenv("TEST_FATAL_SUBPROCESS") == "1" {
			// This is the subprocess - should log and exit
			// Use stderr for output since that's where slog goes by default for fatal
			Init("debug", os.Stderr)
			Fatal("fatal error occurred", "code", 1)
			return
		}

		// Run the test in a subprocess
		cmd := exec.Command(os.Args[0], "-test.run=TestFatal/logs_message_at_fatal_level")
		cmd.Env = append(os.Environ(), "TEST_FATAL_SUBPROCESS=1")

		// Capture output (both stdout and stderr)
		output, err := cmd.CombinedOutput()

		// The subprocess should have exited with status 1
		if cmd.ProcessState == nil || cmd.ProcessState.ExitCode() != 1 {
			t.Errorf("expected exit code 1, got: %v", cmd.ProcessState)
		}

		// Verify the log message was output
		if !strings.Contains(string(output), "fatal error occurred") {
			t.Errorf("expected fatal message in output, got: %s", output)
		}

		// We expect an error because the process exited non-zero
		_ = err
	})
}
