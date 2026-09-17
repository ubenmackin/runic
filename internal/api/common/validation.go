// Package common provides domain / semantic validators. The functions here
// answer questions of the form "is this string a known value in the
// application's domain?" — e.g. valid entity type, valid policy
// direction. For structural / format validators (hostname syntax, IP
// parsing, name character class), see validate.go.
package common

import (
	"fmt"

	"runic/internal/resolve"
)

// IsValidEntityType reports whether value is a known policy entity type.
// It delegates to resolve.IsValidEntityType, the single source of truth shared with the engine.
func IsValidEntityType(value string) bool {
	return resolve.IsValidEntityType(value)
}

// IsValidDirection reports whether value is a known policy direction.
// It delegates to resolve.IsValidDirection, the single source of truth shared with the engine.
func IsValidDirection(value string) bool {
	return resolve.IsValidDirection(value)
}

// IsValidTargetScope reports whether value is a known policy target scope.
// It delegates to resolve.IsValidTargetScope, the single source of truth shared with the engine.
func IsValidTargetScope(value string) bool {
	return resolve.IsValidTargetScope(value)
}

// IsValidAction reports whether value is a known policy action.
// It delegates to resolve.IsValidAction, the single source of truth shared with the engine.
func IsValidAction(value string) bool {
	return resolve.IsValidAction(value)
}

// ValidatePeerOverrideIPs validates source_ip/target_ip scope and format
// for policy input and preview requests. It enforces that overrides are
// only set when the corresponding entity type is peer, and that any
// non-empty override is a valid peer CIDR (plain-or-CIDR, /0 rejected via
// ValidatePeerCIDR so an override cannot become allow-all; use __any_ip__
// instead). Error messages match the
// historical fail-closed strings used by the policies handlers so callers
// can surface them directly.
func ValidatePeerOverrideIPs(sourceIP, targetIP, sourceType, targetType string) error {
	if sourceIP != "" && sourceType != "peer" {
		return fmt.Errorf("source_ip is only valid when source_type is peer")
	}
	if targetIP != "" && targetType != "peer" {
		return fmt.Errorf("target_ip is only valid when target_type is peer")
	}
	if sourceIP != "" {
		if err := ValidatePeerCIDR(sourceIP); err != nil {
			return fmt.Errorf("invalid source_ip: %w", err)
		}
	}
	if targetIP != "" {
		if err := ValidatePeerCIDR(targetIP); err != nil {
			return fmt.Errorf("invalid target_ip: %w", err)
		}
	}
	return nil
}
