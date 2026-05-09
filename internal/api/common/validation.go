package common

func IsValidSourceType(value string) bool {
	return value == "peer" || value == "group" || value == "special"
}

func IsValidTargetType(value string) bool {
	return value == "peer" || value == "group" || value == "special"
}

func IsValidDirection(value string) bool {
	return value == "both" || value == "forward" || value == "backward"
}
