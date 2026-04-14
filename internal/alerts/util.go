// Package alerts provides alert and notification functionality.
package alerts

import (
	"log/slog"
	"time"

	"runic/internal/common/log"
)

// LoadTimezoneOrDefault loads a timezone location from an IANA timezone string.
// If the timezone string is empty or invalid, it logs a warning and returns time.UTC.
//
// Parameters:
//   - tz: The IANA timezone string (e.g., "America/New_York", "Europe/London").
//     If empty, returns time.UTC without logging a warning.
//
// Returns:
//   - The loaded *time.Location if valid, or time.UTC as fallback.
func LoadTimezoneOrDefault(tz string) *time.Location {
	if tz == "" {
		return time.UTC
	}

	loc, err := time.LoadLocation(tz)
	if err != nil {
		log.L().Warn("failed to load timezone, defaulting to UTC",
			"timezone", tz,
			"error", err,
		)
		return time.UTC
	}

	return loc
}

// LoadTimezoneOrDefaultWithLogger is like LoadTimezoneOrDefault but accepts a custom logger
// for context-specific logging (e.g., including user_id in log messages).
//
// Parameters:
//   - tz: The IANA timezone string (e.g., "America/New_York", "Europe/London").
//     If empty, returns time.UTC without logging a warning.
//   - logger: The logger to use for warning messages. If nil, uses the default logger.
//   - logAttrs: Optional key-value pairs to include in the log message.
//
// Returns:
//   - The loaded *time.Location if valid, or time.UTC as fallback.
func LoadTimezoneOrDefaultWithLogger(tz string, logger *slog.Logger, logAttrs ...any) *time.Location {
	if tz == "" {
		return time.UTC
	}

	loc, err := time.LoadLocation(tz)
	if err != nil {
		if logger != nil {
			logger.Warn("failed to load timezone, defaulting to UTC",
				append([]any{"timezone", tz, "error", err}, logAttrs...)...,
			)
		} else {
			log.L().Warn("failed to load timezone, defaulting to UTC",
				append([]any{"timezone", tz, "error", err}, logAttrs...)...,
			)
		}
		return time.UTC
	}

	return loc
}
