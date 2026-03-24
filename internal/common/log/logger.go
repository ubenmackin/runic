package log

import (
	"context"
	"io"
	"log/slog"
	"os"
)

// A global slog logger instance, configurable at init time
var logger *slog.Logger

// requestIDKey is the context key for request ID.
type requestIDKey struct{}

// Init initializes the structured logging system.
// Call this at application startup.
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

	// Determine output format based on environment
	// JSON format for production, text format for development
	if os.Getenv("ENV") == "production" {
		handler := slog.NewJSONHandler(output, opts)
		logger = slog.New(handler)
	} else {
		handler := slog.NewTextHandler(output, opts)
		logger = slog.New(handler)
	}

	// Set default
	slog.SetDefault(logger)
}

// L returns the configured logger instance
func L() *slog.Logger {
	if logger == nil {
		// Fallback to default if not initialized
		return slog.Default()
	}
	return logger
}

// LCtx returns a logger with request ID from the context
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

// SetRequestID sets the request ID in the context.
// This is for external packages to add request ID to context.
func SetRequestID(ctx context.Context, requestID string) context.Context {
	return context.WithValue(ctx, requestIDKey{}, requestID)
}

// GetRequestID extracts the request ID from the context.
// Returns the request ID and true if found, otherwise returns empty string and false.
func GetRequestID(ctx context.Context) (string, bool) {
	if requestID, ok := ctx.Value(requestIDKey{}).(string); ok {
		return requestID, true
	}
	return "", false
}

// Debug logs a message at DebugLevel with key-value pairs.
func Debug(msg string, args ...any) {
	L().Debug(msg, args...)
}

// Info logs a message at InfoLevel with key-value pairs.
func Info(msg string, args ...any) {
	L().Info(msg, args...)
}

// Warn logs a message at WarnLevel with key-value pairs.
func Warn(msg string, args ...any) {
	L().Warn(msg, args...)
}

// Error logs a message at ErrorLevel with key-value pairs.
func Error(msg string, args ...any) {
	L().Error(msg, args...)
}

// DebugContext logs a message at DebugLevel with context and key-value pairs.
func DebugContext(ctx context.Context, msg string, args ...any) {
	LCtx(ctx).Debug(msg, args...)
}

// InfoContext logs a message at InfoLevel with context and key-value pairs.
func InfoContext(ctx context.Context, msg string, args ...any) {
	LCtx(ctx).Info(msg, args...)
}

// WarnContext logs a message at WarnLevel with context and key-value pairs.
func WarnContext(ctx context.Context, msg string, args ...any) {
	LCtx(ctx).Warn(msg, args...)
}

// ErrorContext logs a message at ErrorLevel with context and key-value pairs.
func ErrorContext(ctx context.Context, msg string, args ...any) {
	LCtx(ctx).Error(msg, args...)
}
