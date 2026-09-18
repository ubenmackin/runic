package change

// PolicyRef identifies a policy that blocks a delete via a constraint.
type PolicyRef struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
}

// A DeleteConstraintError represents an error when attempting to delete an entity
// that is in use by one or more policies.
type DeleteConstraintError struct {
	Message  string      `json:"error"`
	Policies []PolicyRef `json:"policies"`
}

func (e *DeleteConstraintError) Error() string {
	return e.Message
}

func (e *DeleteConstraintError) ToResponse() map[string]any {
	return map[string]any{
		"error":    e.Message,
		"policies": e.Policies,
	}
}
