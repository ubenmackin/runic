package imports

// ImportSession represents the API response for an import session.
type ImportSession struct {
	ID              int64  `json:"id"`
	PeerID          int64  `json:"peer_id"`
	PeerHostname    string `json:"peer_hostname"`
	Status          string `json:"status"`
	TotalRulesFound int    `json:"total_rules_found"`
	ImportableRules int    `json:"importable_rules"`
	SkippedRules    int    `json:"skipped_rules"`
	CreatedAt       string `json:"created_at"`
	UpdatedAt       string `json:"updated_at"`
}

// ImportRule represents a parsed rule from an import session.
type ImportRule struct {
	ID          int64  `json:"id"`
	SessionID   int64  `json:"session_id"`
	Chain       string `json:"chain"`
	RuleOrder   int    `json:"rule_order"`
	RawRule     string `json:"raw_rule"`
	Status      string `json:"status"`
	SkipReason  string `json:"skip_reason,omitempty"`
	SourceType  string `json:"source_type,omitempty"`
	SourceName  string `json:"source_name,omitempty"`
	TargetType  string `json:"target_type,omitempty"`
	TargetName  string `json:"target_name,omitempty"`
	ServiceName string `json:"service_name,omitempty"`
	Action      string `json:"action,omitempty"`
	Priority    int    `json:"priority,omitempty"`
	Direction   string `json:"direction,omitempty"`
	TargetScope string `json:"target_scope,omitempty"`
	PolicyName  string `json:"policy_name,omitempty"`
	Enabled     bool   `json:"enabled,omitempty"`
}

// ImportGroupMapping represents a group mapping in an import session.
type ImportGroupMapping struct {
	ID                int64    `json:"id"`
	SessionID         int64    `json:"session_id"`
	GroupName         string   `json:"group_name"`
	IpsetName         string   `json:"ipset_name,omitempty"`
	Status            string   `json:"status"`
	ExistingGroupID   *int64   `json:"existing_group_id,omitempty"`
	ExistingGroupName string   `json:"existing_group_name,omitempty"`
	MemberIPs         []string `json:"member_ips"`
	MemberPeerNames   []string `json:"member_peer_names,omitempty"`
}

// ImportPeerMapping represents a peer mapping in an import session.
type ImportPeerMapping struct {
	ID               int64  `json:"id"`
	SessionID        int64  `json:"session_id"`
	IPAddress        string `json:"ip_address"`
	Hostname         string `json:"hostname,omitempty"`
	Status           string `json:"status"`
	ExistingPeerID   *int64 `json:"existing_peer_id,omitempty"`
	ExistingPeerName string `json:"existing_peer_name,omitempty"`
}

// ImportServiceMapping represents a service mapping in an import session.
type ImportServiceMapping struct {
	ID                  int64  `json:"id"`
	SessionID           int64  `json:"session_id"`
	Name                string `json:"name"`
	Ports               string `json:"ports"`
	Protocol            string `json:"protocol"`
	Status              string `json:"status"`
	ExistingServiceID   *int64 `json:"existing_service_id,omitempty"`
	ExistingServiceName string `json:"existing_service_name,omitempty"`
}
