package common

// IsValidSourceType validates that the source type is one of the allowed values.
func IsValidSourceType(value string) bool {
	return value == "peer" || value == "group" || value == "special"
}

// IsValidTargetType validates that the target type is one of the allowed values.
func IsValidTargetType(value string) bool {
	return value == "peer" || value == "group" || value == "special"
}

// IsValidDirection validates that the direction is one of the allowed values.
func IsValidDirection(value string) bool {
	return value == "both" || value == "forward" || value == "backward"
}
