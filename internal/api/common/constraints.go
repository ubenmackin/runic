// Package common provides shared utilities and constants.
package common

import (
	"runic/internal/change"
)

// PolicyRef is an alias for change.PolicyRef. The definition lives in the
// low-level internal/change package so the store layer can return delete
// constraints without importing the API layer.
type PolicyRef = change.PolicyRef

// DeleteConstraintError is an alias for change.DeleteConstraintError, kept
// for backward compatibility with API handlers that map it to 409.
type DeleteConstraintError = change.DeleteConstraintError
