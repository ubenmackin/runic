// Package common provides domain / semantic validators. The functions here
// answer questions of the form "is this string a known value in the
// application's domain?" — e.g. valid entity type, valid policy
// direction. For structural / format validators (hostname syntax, IP
// parsing, name character class), see validate.go.
package common

func IsValidEntityType(value string) bool {
	return value == "peer" || value == "group" || value == "special"
}

func IsValidDirection(value string) bool {
	return value == "both" || value == "forward" || value == "backward"
}
