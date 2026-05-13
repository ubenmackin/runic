// Package log provides a standardized structured logger for the application.
package log

import (
	"context"
	"io"
	"log/slog"
	"os"
	"sync"
)

// mu protects the logger variable for concurrent access.
var mu sync.RWMutex

// A global slog logger instance, configurable at init time
var logger *slog.Logger

type requestIDKey struct{}

// Init initializes the global logger. Call this at application startup.
func Init(level string, output io.Writer) {
	var logLevel slog.Level
	switch level {
	case "debug":
		logLevel = slog.LevelDebug
	case "info":
		logLevel = slog.LevelInfo
	case "warn":
		logLevel = slog.LevelWarn
	case "error":
		logLevel = slog.LevelError
	default:
		logLevel = slog.LevelInfo
	}

	opts := &slog.HandlerOptions{
		Level: logLevel,
	}

	var newLogger *slog.Logger
	// Determine output format based on environment
	// JSON format for production, text format for development
	if os.Getenv("ENV") == "production" {
		handler := slog.NewJSONHandler(output, opts)
		newLogger = slog.New(handler)
	} else {
		handler := slog.NewTextHandler(output, opts)
		newLogger = slog.New(handler)
	}

	mu.Lock()
	logger = newLogger
	mu.Unlock()
	slog.SetDefault(newLogger)
}

func L() *slog.Logger {
	mu.RLock()
	l := logger
	mu.RUnlock()
	if l == nil {
		return slog.Default()
	}
	return l
}

func LCtx(ctx context.Context) *slog.Logger {
	baseLogger := L()
	if ctx == nil {
		return baseLogger
	}

	requestID, ok := ctx.Value(requestIDKey{}).(string)
	if !ok || requestID == "" {
		return baseLogger
	}

	return baseLogger.With("request_id", requestID)
}

// SetRequestID adds a request ID to the context. This is for external packages to add request ID to context.
func SetRequestID(ctx context.Context, requestID string) context.Context {
	return context.WithValue(ctx, requestIDKey{}, requestID)
}

// GetRequestID extracts the request ID from the context. Returns the request ID and true if found, otherwise returns empty string and false.
func GetRequestID(ctx context.Context) (string, bool) {
	if requestID, ok := ctx.Value(requestIDKey{}).(string); ok {
		return requestID, true
	}
	return "", false
}

func Debug(msg string, args ...any) {
	L().Debug(msg, args...)
}

func Info(msg string, args ...any) {
	L().Info(msg, args...)
}

func Warn(msg string, args ...any) {
	L().Warn(msg, args...)
}

func Error(msg string, args ...any) {
	L().Error(msg, args...)
}

func DebugContext(ctx context.Context, msg string, args ...any) {
	LCtx(ctx).Debug(msg, args...)
}

func InfoContext(ctx context.Context, msg string, args ...any) {
	LCtx(ctx).Info(msg, args...)
}

func WarnContext(ctx context.Context, msg string, args ...any) {
	LCtx(ctx).Warn(msg, args...)
}

func ErrorContext(ctx context.Context, msg string, args ...any) {
	LCtx(ctx).Error(msg, args...)
}

const LevelFatal = slog.Level(12)

// Fatal logs a message at fatal level and exits. Use only in main packages for truly unrecoverable errors.
func Fatal(msg string, args ...any) {
	L().Log(context.Background(), LevelFatal, msg, args...)
	os.Exit(1)
}
