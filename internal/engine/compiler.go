// Package engine provides policy compilation and resolution.
package engine

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"runic/internal/common"
	"runic/internal/common/constants"
	"runic/internal/common/log"
	"runic/internal/db"
	"runic/internal/models"
	"runic/internal/resolve"
)

// Well-known system service names. These names are reserved and must match
// the services inserted as system services (is_system = 1). They are used
// instead of display names to avoid breaking when a user renames a service.
const (
	systemServiceMulticast        = "Multicast"
	systemServiceSubnetBroadcast  = "Subnet Broadcast"
	systemServiceLimitedBroadcast = "Limited Broadcast"
	systemServiceIGMP             = "IGMP"
	systemServiceVRRP             = "VRRP"
)

// Well-known iptables chain names. Used as typed string constants so that
// rule construction reads as `chain = ChainInput` rather than as bare literals,
// without breaking callers that compare against plain strings.
const (
	ChainInput      = "INPUT"
	ChainOutput     = "OUTPUT"
	ChainForward    = "FORWARD"
	ChainDockerUser = "DOCKER-USER"
)

// Policy direction values stored in the policies.direction column.
const (
	DirBoth     = "both"
	DirForward  = "forward"
	DirBackward = "backward"
)

// Protocol and scope values that share the literal "both" with direction
// but are semantically distinct. Separate constants prevent accidental
// coupling between direction, protocol, and scope comparisons.
const (
	ProtoBoth = "both"
	ScopeBoth = "both"
)

// Policy action values stored in the policies.action column.
const (
	ActionAccept  = "ACCEPT"
	ActionDrop    = "DROP"
	ActionLogDrop = "LOG_DROP"
)

// ruleDir discriminates the three rule-generation paths inside writeRules.
// It is a distinct string type for readability only; it provides no
// compile-time safety (untyped string constants are assignable to it and an
// explicit ruleDir(s) conversion bypasses the typed constants entirely).
// Enforcement is runtime-only: the builders reject any other value with an
// unknown-ruleDir error. Callers must pass one of the typed constants below.
type ruleDir string

const (
	ruleDirTarget   ruleDir = "target"
	ruleDirSource   ruleDir = "source"
	ruleDirInternet ruleDir = "internet"
)

// Ipset name conventions.
const (
	ipsetPrivateRanges = "runic_private_ranges"
	ipsetGroupPrefix   = "runic_group_"
)

// privateFallbackCIDRs is the single source of truth for the IPv4 private
// ranges excluded from internet egress. It backs both the
// runic_private_ranges ipset definitions in writeIpsetDefinitions and the
// explicit four-negation fallback matches in internetFallbackDstMatch and
// internetFallbackSrcMatch, so the two cannot diverge. Must not be mutated:
// frozen as an array and read via privateFallbackCIDRList which returns a
// copy, so concurrent Compile/PreviewCompile readers never share mutable state.
var privateFallbackCIDRs = [4]string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8"}

// privateFallbackCIDRList returns a copy of privateFallbackCIDRs so callers
// cannot mutate the shared table.
func privateFallbackCIDRList() []string {
	return append([]string(nil), privateFallbackCIDRs[:]...)
}

// ErrPreviewValidation marks PreviewCompile errors caused by user-controlled
// input (bad action/entity/direction/scope, unknown or pending-delete
// service, bad service ports, invalid IP overrides, unknown special
// targets, unresolvable peers/groups, IP override on a non-peer entity).
// The policies preview handler maps it to 400 via errors.Is. All other
// PreviewCompile errors are internal (500). The Compile path wraps its
// stored-policy invalid-action error with the same sentinel so both paths
// map identically via errors.Is; Compile bundle handlers still surface it
// as 500 because a stored invalid action indicates DB corruption
// (internal), not direct user input. Internal wiring invariants (unknown
// ruleDir, assertInternetIpset, invalid peer IP in the self-CIDR filter)
// likewise wrap this sentinel so errors.Is works; Compile handlers surface
// them as 500 (they map all Compile errors to 500).
//
// ErrPreviewFailClosed marks fail-closed policy semantics (internet without
// ipset support, ingress-from-internet, sentinel leaks). The preview
// handler maps it to 400. Both sentinels travel through %w wrapping so
// errors.Is keeps working across the resolver chain.
var (
	ErrPreviewValidation = errors.New("preview validation error")
	ErrPreviewFailClosed = errors.New("preview fail-closed")
)

// failClosedEmptyIPErr returns the fail-closed error for egress-to-internet
// on a peer with no IP address. It carries the policy name and reports the
// empty-IP reason (not has_ipset=0) so peers with ipset support are not
// misreported when they have no host address to validate.
func failClosedEmptyIPErr(policyName string) error {
	return fmt.Errorf("policy %s targets internet but peer has empty IP: fail-closed: %w", policyName, ErrPreviewFailClosed)
}

// failClosedIngressInternetErr returns the fail-closed error for
// ingress-from-internet policies, which have no ipset semantics on the INPUT
// path even when the peer has ipset support.
func failClosedIngressInternetErr(policyName string) error {
	return fmt.Errorf("policy %s has ingress-from-internet which has no ipset semantics: fail-closed: %w", policyName, ErrPreviewFailClosed)
}

// failClosedSentinelLeakErr returns the fail-closed error for a defensive
// sentinel leak: the resolve.InternetSentinel marker reached the CIDR path
// outside the internet path. Both the ipset and fallback branches are valid
// internet paths; this by construction only triggers on a CIDR-path wiring
// mistake when the internet gates were bypassed.
func failClosedSentinelLeakErr(policyName string) error {
	return fmt.Errorf("policy %s resolved internet sentinel outside internet path: fail-closed: %w", policyName, ErrPreviewFailClosed)
}

// failClosedInternetIPv6Err returns the fail-closed error for egress-to-internet
// on an IPv6 peer. runic_private_ranges is IPv4-only (family inet with RFC1918
// + loopback CIDRs), so its OUTPUT dst / INPUT src negation would let IPv6
// internet traffic (including ULA fc00::/7, link-local fe80::/10, ::1/128)
// bypass the policy. Fail closed until a separate ip6tables-restore bundle
// with an inet6 private-ranges set exists.
func failClosedInternetIPv6Err(policyName string) error {
	return fmt.Errorf("policy %s targets internet from IPv6 peer: runic_private_ranges is IPv4-only: fail-closed: %w", policyName, ErrPreviewFailClosed)
}

// isIPv6Address reports whether s is an IPv6 literal or CIDR. IPv6 text always
// contains ":", so a substring check suffices for normalized CIDRs (/128,
// subnets) and bare addresses. Empty strings report false; empty-IP peers
// fail closed via explicit gates except peerID 0 which keeps canonical ipset form.
func isIPv6Address(s string) bool {
	return strings.Contains(s, ":")
}

// isInternetSentinelCIDR reports whether a resolved CIDR carries the
// resolve.InternetSentinel marker, either bare ("__internet__") or normalized
// ("__internet__/32" via NormalizeToCIDR). The sentinel must never reach a
// "-s"/"-d" rule literal.
func isInternetSentinelCIDR(cidr string) bool {
	return cidr == resolve.InternetSentinel || strings.HasPrefix(cidr, resolve.InternetSentinel+"/")
}

// checkInternetPeer validates the host context for egress-to-internet
// rendering. It fails closed on empty-IP peers via failClosedEmptyIPErr and
// on IPv6 peers via failClosedInternetIPv6Err, bypassing the gates for
// peerID 0 which keeps the canonical ipset form with no host to validate.
// The ipset vs fallback branch selection remains with the callers
// (writeSourceSection and previewForward select the fallback when !hasIPSet,
// previewAppendRules is ipset-only defense and never sees user-facing
// no-ipset, which goes via buildInternetFallbackRules).
func checkInternetPeer(ipAddress string, peerID int, policyName string) error {
	if peerID == 0 {
		return nil
	}
	if ipAddress == "" {
		return failClosedEmptyIPErr(policyName)
	}
	if isIPv6Address(ipAddress) {
		return failClosedInternetIPv6Err(policyName)
	}
	return nil
}

// Preview validation uses internal/resolve
// (IsValidDirection, IsValidTargetScope, IsValidEntityType, IsValidAction),
// the single source of truth shared with internal/api/common, called directly.
// They live in resolve (rather than api/common) to avoid an import cycle:
// internal/api/common imports internal/engine
// (tracker/pushworker/recompile), so the engine cannot import it.

// assertInternetIpset rejects any ipset wiring on the internet (ruleDir-only)
// path to catch caller wiring mistakes. Both useIpset and ipsetName must be
// unset (false,"") since the builders select the internet branch solely on
// ruleDir and always emit the hardcoded runic_private_ranges negation matches.
// This assertion applies only to the ipset internet branch; the no-ipset
// fallback emits no ipset reference by construction and never calls this helper.
//
// Internal wiring invariant: never triggered by user input (callers always
// pass false,"" here by construction). Wraps ErrPreviewValidation so
// errors.Is works across the call chain; Compile bundle handlers still
// surface it as 500 (they map all Compile errors to 500), while
// PreviewCompile maps it to 400 via isPreviewValidationError. By
// construction this only fires on programmer error.
func assertInternetIpset(useIpset bool, ipsetName string) error {
	if useIpset {
		return fmt.Errorf("internet ruleDir requires useIpset=false, got true: %w", ErrPreviewValidation)
	}
	if ipsetName != "" {
		return fmt.Errorf("internet ruleDir requires empty ipsetName, got %q: %w", ipsetName, ErrPreviewValidation)
	}
	return nil
}

// DefaultControlPlanePort aliases the shared default control plane port so
// compiler callers can reference it without importing the constants package.
const DefaultControlPlanePort = constants.DefaultControlPlanePort

func isMulticastSpecialID(id int) bool {
	return id == resolve.SpecialIDAllHosts || id == resolve.SpecialIDmDNS || id == resolve.SpecialIDIGMPv3
}

func isBroadcastSpecialID(id int) bool {
	return id == resolve.SpecialIDSubnetBroadcast || id == resolve.SpecialIDLimitedBroadcast
}

// PeerHostnameLookup is the shared type for hostname resolution by peer ID.
type PeerHostnameLookup = common.PeerHostnameLookup

// GroupNameLookup retrieves a group name by ID. Returns ("", sql.ErrNoRows) if not found.
type GroupNameLookup func(ctx context.Context, groupID int) (string, error)

type Compiler struct {
	db              db.Querier
	beginner        db.Beginner
	resolver        *Resolver
	lookupHostname  PeerHostnameLookup
	lookupGroupName GroupNameLookup
}

func NewCompiler(database db.Querier, hostnameLookup PeerHostnameLookup, groupNameLookup GroupNameLookup) *Compiler {
	return &Compiler{
		db:              database,
		resolver:        &Resolver{db: database},
		lookupHostname:  hostnameLookup,
		lookupGroupName: groupNameLookup,
	}
}

// SetBeginner sets the transaction beginner for the Compiler.
// This must be called before CompileAndStore, which needs transactions.
func (c *Compiler) SetBeginner(b db.Beginner) {
	c.beginner = b
}

type policyInfo struct {
	ID          int
	Name        string
	SourceID    int
	SourceType  string
	ServiceID   int
	TargetID    int
	TargetType  string
	SourceIP    string
	TargetIP    string
	Action      string
	Priority    int
	TargetScope string
	Direction   string
	IsTarget    bool
	IsSource    bool
}

// The match parameter contains everything between "-A CHAIN" and "-j ACTION".
//
// ruleWriter is NOT safe for concurrent use; it holds a single *strings.Builder
// and emits iptables rule text sequentially. Each compilation must use its own
// ruleWriter instance.
type ruleWriter struct{ buf *strings.Builder }

func (rw *ruleWriter) accept(chain, match string) {
	fmt.Fprintf(rw.buf, "-A %s %s -j ACCEPT\n", chain, match)
}

func (rw *ruleWriter) drop(chain, match string) {
	fmt.Fprintf(rw.buf, "-A %s %s -j DROP\n", chain, match)
}

func (rw *ruleWriter) logDrop(chain, match string) {
	// Use direction-specific log prefix: RUNIC-DROP-I for INPUT, RUNIC-DROP-O for OUTPUT
	prefix := dropPrefixFor(chain)
	fmt.Fprintf(rw.buf, "-A %s %s -j LOG --log-prefix \"%s\" --log-level 4\n", chain, match, prefix)
	rw.drop(chain, match)
}

// dropPrefixFor returns the iptables log prefix used for the given chain.
// Returns the ingress prefix for INPUT/DOCKER-USER, the egress prefix otherwise.
// This is shared by both ruleWriter.logDrop and the logDropRule helper to keep
// the prefix selection logic in a single place.
func dropPrefixFor(chain string) string {
	if chain == ChainInput || chain == ChainDockerUser {
		return "[RUNIC-DROP-I] "
	}
	return "[RUNIC-DROP-O] "
}

func (rw *ruleWriter) writeAction(action, chain, match string) {
	switch action {
	case ActionAccept:
		rw.accept(chain, match)
	case ActionDrop:
		rw.drop(chain, match)
	case ActionLogDrop:
		rw.logDrop(chain, match)
	}
}

// If the string already contains a "/", it is returned as-is.
func (c *Compiler) formatEntityName(ctx context.Context, entityType string, entityID int) string {
	switch entityType {
	case "special":
		return c.getSpecialDisplayName(entityID)
	case "peer":
		var hostname string
		var err error
		hostname, err = c.lookupHostname(ctx, entityID)
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Sprintf("peer %d (not found)", entityID)
		}
		if err != nil {
			log.WarnContext(ctx, "lookup peer hostname failed", "peer_id", entityID, "error", err)
			return fmt.Sprintf("peer %d", entityID)
		}
		return hostname
	case "group":
		var name string
		var err error
		name, err = c.lookupGroupName(ctx, entityID)
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Sprintf("group %d (not found)", entityID)
		}
		if err != nil {
			log.WarnContext(ctx, "lookup group name failed", "group_id", entityID, "error", err)
			return fmt.Sprintf("group %d", entityID)
		}
		return name
	default:
		return fmt.Sprintf("%s %d", entityType, entityID)
	}
}

// specialDisplayNames maps special target IDs to their human-readable display names.
// Hoisted to package scope so it is not rebuilt on every call.
var specialDisplayNames = map[int]string{
	resolve.SpecialIDSubnetBroadcast:  "Subnet Broadcast",
	resolve.SpecialIDLimitedBroadcast: "Limited Broadcast",
	resolve.SpecialIDAllHosts:         "All Hosts (IGMP)",
	resolve.SpecialIDmDNS:             "mDNS",
	resolve.SpecialIDLoopback:         "Loopback",
	resolve.SpecialIDAnyIP:            "Any IP",
	resolve.SpecialIDAllPeers:         "All Peers",
	resolve.SpecialIDIGMPv3:           "IGMPv3",
	resolve.SpecialIDInternet:         "Internet",
}

func (c *Compiler) getSpecialDisplayName(specialID int) string {
	if name, ok := specialDisplayNames[specialID]; ok {
		return name
	}
	return fmt.Sprintf("special %d", specialID)
}

func (rw *ruleWriter) newline() {
	rw.buf.WriteString("\n")
}

func (rw *ruleWriter) writeStandardRules(hasDocker bool, controlPlanePort string) {
	// loopback
	rw.buf.WriteString("# --- Standard: loopback ---\n")
	rw.buf.WriteString("-A INPUT -i lo -j ACCEPT\n")
	rw.buf.WriteString("-A OUTPUT -o lo -j ACCEPT\n")
	rw.newline()

	// ICMP RELATED
	rw.buf.WriteString("# --- Standard: ICMP RELATED ---\n")
	rw.buf.WriteString("-A INPUT -p icmp -m conntrack --ctstate RELATED -j ACCEPT\n")
	rw.buf.WriteString("-A OUTPUT -p icmp -m conntrack --ctstate RELATED -j ACCEPT\n")
	rw.newline()

	// INVALID
	rw.buf.WriteString("# --- Standard: INVALID packet drop ---\n")
	rw.buf.WriteString("-A INPUT -m conntrack --ctstate INVALID -j DROP\n")
	rw.buf.WriteString("-A OUTPUT -m conntrack --ctstate INVALID -j DROP\n")
	rw.newline()

	// Control Plane Communication
	if controlPlanePort != "" {
		rw.buf.WriteString("# --- Standard: Control Plane Communication ---\n")
		fmt.Fprintf(rw.buf, "# Allows agent to communicate with control plane on port %s\n", controlPlanePort)
		fmt.Fprintf(rw.buf, "-A INPUT -p tcp --dport %s -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT\n", controlPlanePort)
		fmt.Fprintf(rw.buf, "-A OUTPUT -p tcp --sport %s -m conntrack --ctstate ESTABLISHED -j ACCEPT\n", controlPlanePort)
		fmt.Fprintf(rw.buf, "-A OUTPUT -p tcp --dport %s -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT\n", controlPlanePort)
		fmt.Fprintf(rw.buf, "-A INPUT -p tcp --sport %s -m conntrack --ctstate ESTABLISHED -j ACCEPT\n", controlPlanePort)
		rw.newline()
	}

	// Docker standard rules
	if hasDocker {
		rw.buf.WriteString("# --- Docker: Standard rules for DOCKER-USER ---\n")
		rw.buf.WriteString("-A DOCKER-USER -p icmp -m conntrack --ctstate RELATED -j ACCEPT\n")
		rw.buf.WriteString("-A DOCKER-USER -m conntrack --ctstate INVALID -j DROP\n")
		rw.newline()
	}
}

// Compile produces a complete iptables-restore payload for the given peer.

// scanBool converts a SQLite driver value to bool, accepting both the bool
// representation (returned by some drivers/builds in tests) and the INTEGER
// 0/1 representation (production mattn/go-sqlite3). NULL maps to false
// (fail-closed for capability flags). []byte/string forms ("0"/"1",
// "true"/"false") are parsed case-insensitively with surrounding whitespace
// trimmed.
func scanBool(v any) bool {
	switch t := v.(type) {
	case nil:
		return false
	case bool:
		return t
	case int:
		return t != 0
	case int8:
		return t != 0
	case int16:
		return t != 0
	case int32:
		return t != 0
	case int64:
		return t != 0
	case uint:
		return t != 0
	case uint8:
		return t != 0
	case uint16:
		return t != 0
	case uint32:
		return t != 0
	case uint64:
		return t != 0
	case float32:
		return t != 0
	case float64:
		return t != 0
	case []byte:
		s := strings.TrimSpace(strings.ToLower(string(t)))
		return s == "1" || s == "true" || s == "t" || s == "yes" || s == "y"
	case string:
		s := strings.TrimSpace(strings.ToLower(t))
		return s == "1" || s == "true" || s == "t" || s == "yes" || s == "y"
	default:
		return false
	}
}

// --- Compiler Sub-routines ---

func (c *Compiler) loadPeerData(ctx context.Context, peerID int) (hostname string, ipAddress string, hasDocker bool, hasIPSet bool, err error) {
	// SQLite stores BOOLEAN as INTEGER 0/1 (has_ipset is nullable, hence the
	// COALESCE). The driver may return bool (tests) or int64 (prod), so scan
	// into any and convert via scanBool instead of scanning directly into
	// *bool or int, both of which are driver-fragile.
	var hasDockerRaw, hasIPSetRaw any
	err = c.db.QueryRowContext(ctx,
		"SELECT hostname, ip_address, has_docker, COALESCE(has_ipset, 0) FROM peers WHERE id = ?", peerID,
	).Scan(&hostname, &ipAddress, &hasDockerRaw, &hasIPSetRaw)
	if err != nil {
		err = fmt.Errorf("load peer %d: %w", peerID, err)
		return
	}
	hasDocker = scanBool(hasDockerRaw)
	hasIPSet = scanBool(hasIPSetRaw)
	return
}

// loadApplicablePolicies returns the set of enabled, non-pending-delete policies
// that reference the peer as either source, target, or via a group membership.
//
// RISK: The query is a single 25-arg, 14-SELECT-COLUMN monster. It mixes
// peer-as-target, peer-as-source, special-source-when-target-is-peer/group, and
// group-target cases in one CASE expression. Future schema changes (e.g.,
// adding a new entity type) require touching multiple CASE branches. A
// refactor that splits this into one query per case (and unions the results
// in Go) would be more maintainable but would lose the single round-trip and
// require a transactional snapshot. The current shape is preserved because
// (a) the existing unit tests assert the per-peer policy set, and (b) the
// query is the hot path during bulk recompiles.
func (c *Compiler) loadApplicablePolicies(ctx context.Context, peerID int) ([]policyInfo, []int, map[int]string, error) {
	rows, err := c.db.QueryContext(ctx,
		`SELECT DISTINCT p.id, p.name, p.source_id, p.source_type, p.service_id, p.target_id, p.target_type, COALESCE(p.source_ip, ''), COALESCE(p.target_ip, ''), p.action, p.priority, p.target_scope, COALESCE(p.direction, 'both'),
		CASE WHEN p.target_type = 'peer' AND p.target_id = ? THEN 1
		WHEN p.target_type = 'group' AND EXISTS (SELECT 1 FROM group_members gm JOIN groups g ON gm.group_id = g.id WHERE gm.group_id = p.target_id AND gm.peer_id = ? AND g.is_pending_delete = 0) THEN 1
		WHEN p.target_type = 'special' AND p.source_type = 'group' AND EXISTS (SELECT 1 FROM group_members gm JOIN groups g ON gm.group_id = g.id WHERE gm.group_id = p.source_id AND gm.peer_id = ? AND g.is_pending_delete = 0) THEN 1
		WHEN p.target_type = 'special' AND p.source_type = 'peer' AND p.source_id = ? THEN 1
		ELSE 0 END as is_target,
		CASE WHEN p.source_type = 'peer' AND p.source_id = ? THEN 1
		WHEN p.source_type = 'group' AND EXISTS (SELECT 1 FROM group_members gm JOIN groups g ON gm.group_id = g.id WHERE gm.group_id = p.source_id AND gm.peer_id = ? AND g.is_pending_delete = 0) THEN 1
		WHEN p.source_type = 'special' AND p.target_type = 'group' AND p.source_id NOT IN (?, ?, ?, ?, ?) AND EXISTS (SELECT 1 FROM group_members gm JOIN groups g ON gm.group_id = g.id WHERE gm.group_id = p.target_id AND gm.peer_id = ? AND g.is_pending_delete = 0) THEN 1
		WHEN p.source_type = 'special' AND p.target_type = 'peer' AND p.source_id NOT IN (?, ?, ?, ?, ?) AND p.target_id = ? THEN 1
		ELSE 0 END as is_source
		FROM policies p
		WHERE p.enabled = 1 AND p.is_pending_delete = 0 AND (
		(p.target_type = 'peer' AND p.target_id = ?) OR
		(p.target_type = 'group' AND EXISTS (SELECT 1 FROM group_members gm JOIN groups g ON gm.group_id = g.id WHERE gm.group_id = p.target_id AND gm.peer_id = ? AND g.is_pending_delete = 0)) OR
		(p.source_type = 'peer' AND p.source_id = ?) OR
		(p.source_type = 'group' AND EXISTS (SELECT 1 FROM group_members gm JOIN groups g ON gm.group_id = g.id WHERE gm.group_id = p.source_id AND gm.peer_id = ? AND g.is_pending_delete = 0)) OR
		(p.target_type = 'special' AND p.source_type = 'group' AND EXISTS (SELECT 1 FROM group_members gm JOIN groups g ON gm.group_id = g.id WHERE gm.group_id = p.source_id AND gm.peer_id = ? AND g.is_pending_delete = 0)) OR
		(p.target_type = 'special' AND p.source_type = 'peer' AND p.source_id = ?) OR
		(p.source_type = 'special' AND p.target_type = 'group' AND EXISTS (SELECT 1 FROM group_members gm JOIN groups g ON gm.group_id = g.id WHERE gm.group_id = p.target_id AND gm.peer_id = ? AND g.is_pending_delete = 0)) OR
		(p.source_type = 'special' AND p.target_type = 'peer' AND p.target_id = ?)
		)
		ORDER BY p.priority ASC`,
		peerID, peerID, peerID, peerID, peerID, peerID, resolve.SpecialIDSubnetBroadcast, resolve.SpecialIDLimitedBroadcast, resolve.SpecialIDAllHosts, resolve.SpecialIDmDNS, resolve.SpecialIDIGMPv3, peerID, resolve.SpecialIDSubnetBroadcast, resolve.SpecialIDLimitedBroadcast, resolve.SpecialIDAllHosts, resolve.SpecialIDmDNS, resolve.SpecialIDIGMPv3, peerID, peerID, peerID, peerID, peerID, peerID, peerID, peerID, peerID)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("load policies: %w", err)
	}
	defer func() {
		if err := rows.Close(); err != nil {
			log.WarnContext(ctx, "failed to close rows", "error", err)
		}
	}()

	var policies []policyInfo
	for rows.Next() {
		var p policyInfo
		var isTargetInt, isSourceInt int
		if err := rows.Scan(&p.ID, &p.Name, &p.SourceID, &p.SourceType, &p.ServiceID, &p.TargetID, &p.TargetType, &p.SourceIP, &p.TargetIP, &p.Action, &p.Priority, &p.TargetScope, &p.Direction, &isTargetInt, &isSourceInt); err != nil {
			return nil, nil, nil, fmt.Errorf("scan policy: %w", err)
		}
		p.IsTarget = isTargetInt == 1
		p.IsSource = isSourceInt == 1
		policies = append(policies, p)
	}
	if err := rows.Err(); err != nil {
		return nil, nil, nil, fmt.Errorf("iterate policies: %w", err)
	}

	groupIDToName := make(map[int]string)
	var groupOrder []int // preserve insertion order
	for i := range policies {
		pol := &policies[i]
		if pol.SourceType == "group" {
			if _, exists := groupIDToName[pol.SourceID]; !exists {
				var groupName string
				var err error
				groupName, err = c.lookupGroupName(ctx, pol.SourceID)
				if err == nil {
					groupIDToName[pol.SourceID] = groupName
					groupOrder = append(groupOrder, pol.SourceID)
				}
			}
		}
		if pol.TargetType == "group" {
			if _, exists := groupIDToName[pol.TargetID]; !exists {
				var groupName string
				var err error
				groupName, err = c.lookupGroupName(ctx, pol.TargetID)
				if err == nil {
					groupIDToName[pol.TargetID] = groupName
					groupOrder = append(groupOrder, pol.TargetID)
				}
			}
		}
	}

	return policies, groupOrder, groupIDToName, nil
}

type ServiceInfo struct {
	Name, Ports, SourcePorts, Protocol string
	NoConntrack                        bool
}

func (c *Compiler) preloadRequiredServices(ctx context.Context, policies []policyInfo) (map[int]ServiceInfo, error) {
	serviceIDs := make(map[int]struct{})
	for i := range policies {
		p := &policies[i]
		serviceIDs[p.ServiceID] = struct{}{}
	}
	services := make(map[int]ServiceInfo)
	if len(serviceIDs) > 0 {
		serviceIDList := make([]int, 0, len(serviceIDs))
		for id := range serviceIDs {
			serviceIDList = append(serviceIDList, id)
		}

		placeholders := make([]string, len(serviceIDList))
		args := make([]interface{}, len(serviceIDList))
		for i, id := range serviceIDList {
			placeholders[i] = "?"
			args[i] = id
		}
		query := "SELECT id, name, ports, COALESCE(source_ports,''), protocol, COALESCE(no_conntrack, 0) FROM services WHERE is_pending_delete = 0 AND id IN (" + strings.Join(placeholders, ",") + ")"

		rows, err := c.db.QueryContext(ctx, query, args...)
		if err != nil {
			return nil, fmt.Errorf("batch load services: %w", err)
		}
		defer func() {
			if err := rows.Close(); err != nil {
				log.WarnContext(ctx, "failed to close rows", "error", err)
			}
		}()

		for rows.Next() {
			var sid int
			var s ServiceInfo
			// SQLite stores BOOLEAN as INTEGER 0/1, but the driver may
			// return bool (tests) or int64 (prod). Scan into any and
			// convert via scanBool to accept both.
			var noConntrackRaw any
			if err := rows.Scan(&sid, &s.Name, &s.Ports, &s.SourcePorts, &s.Protocol, &noConntrackRaw); err != nil {
				return nil, fmt.Errorf("scan service: %w", err)
			}
			s.NoConntrack = scanBool(noConntrackRaw)
			services[sid] = s
		}
		if err := rows.Err(); err != nil {
			return nil, fmt.Errorf("iterate services: %w", err)
		}
	}
	return services, nil
}

type ipsetData struct {
	Name    string // sanitized ipset name (e.g. runic_group_webservers)
	SetType string // always hash:net: members are normalized CIDRs (/32, /128, subnets)
	Members []string
}

func (c *Compiler) resolveIPSetDefinitions(ctx context.Context, hasIPSet bool, groupOrder []int, groupIDToName map[int]string) ([]ipsetData, map[int]string, error) {
	var ipsets []ipsetData
	groupIDToIpsetName := make(map[int]string)
	if hasIPSet && len(groupOrder) > 0 {
		for _, gid := range groupOrder {
			members, err := c.resolver.resolveGroupForIpset(ctx, gid)
			if err != nil {
				return nil, nil, fmt.Errorf("resolve group %d for ipset: %w", gid, err)
			}
			sanitizedName := ipsetGroupPrefix + sanitizeForIpset(groupIDToName[gid])
			if err := ValidateIPSetName(sanitizedName); err != nil {
				return nil, nil, fmt.Errorf("group %d (%q): %w", gid, groupIDToName[gid], err)
			}
			var addrs []string
			for _, m := range members {
				addrs = append(addrs, m.Address)
			}
			// Fail closed here (in addition to writeIpsetDefinitions) so the
			// error carries the group ID for debugging. IPv4-only: any IPv6
			// member, including mixed v4+v6 groups, is rejected with
			// ErrPreviewValidation until an ip6tables bundle exists.
			if _, err := ipsetFamilyForMembers(addrs); err != nil {
				return nil, nil, fmt.Errorf("resolve group %d (%q) for ipset: %w", gid, groupIDToName[gid], err)
			}
			ipsets = append(ipsets, ipsetData{
				Name:    sanitizedName,
				SetType: "hash:net",
				Members: addrs,
			})
			groupIDToIpsetName[gid] = sanitizedName
		}
	}
	return ipsets, groupIDToIpsetName, nil
}

func (c *Compiler) Compile(ctx context.Context, peerID int) (string, error) {
	hostname, ipAddress, hasDocker, hasIPSet, err := c.loadPeerData(ctx, peerID)
	if err != nil {
		return "", err
	}

	policies, groupOrder, groupIDToName, err := c.loadApplicablePolicies(ctx, peerID)
	if err != nil {
		return "", err
	}

	services, err := c.preloadRequiredServices(ctx, policies)
	if err != nil {
		return "", err
	}

	ipsets, groupIDToIpsetName, err := c.resolveIPSetDefinitions(ctx, hasIPSet, groupOrder, groupIDToName)
	if err != nil {
		return "", err
	}

	// Load control plane port up-front (was previously a hidden side-effect inside generateIptablesPayload)
	var controlPlanePort string
	if err := c.db.QueryRowContext(ctx, "SELECT value FROM system_config WHERE key = 'control_plane_port'").Scan(&controlPlanePort); err != nil {
		log.WarnContext(ctx, "failed to load control_plane_port, using default "+DefaultControlPlanePort, "error", err)
		controlPlanePort = DefaultControlPlanePort
	}
	if controlPlanePort == "" {
		controlPlanePort = DefaultControlPlanePort
	}

	return c.generateIptablesPayload(ctx, peerID, hostname, ipAddress, hasDocker, hasIPSet, policies, services, ipsets, groupIDToIpsetName, controlPlanePort)
}

func (c *Compiler) generateIptablesPayload(
	ctx context.Context,
	peerID int,
	hostname, ipAddress string,
	hasDocker, hasIPSet bool,
	policies []policyInfo,
	services map[int]ServiceInfo,
	ipsets []ipsetData,
	groupIDToIpsetName map[int]string,
	controlPlanePort string,
) (string, error) {
	var buf strings.Builder
	rw := &ruleWriter{buf: &buf}

	c.writePayloadHeader(&buf, hostname, policies, hasIPSet, ipsets)
	if err := c.writeIpsetDefinitions(&buf, hasIPSet, ipsets); err != nil {
		return "", err
	}
	c.writeFilterTableHeader(&buf, hasDocker)
	rw.writeStandardRules(hasDocker, controlPlanePort)

	if err := c.writePolicySection(ctx, &buf, rw, peerID, policies, services, groupIDToIpsetName, hasDocker, hasIPSet, ipAddress); err != nil {
		return "", err
	}

	c.writeLoggingSection(&buf, hasDocker)
	buf.WriteString("\nCOMMIT\n")

	return buf.String(), nil
}

// writePayloadHeader writes the comment header at the top of the bundle.
func (c *Compiler) writePayloadHeader(buf *strings.Builder, hostname string, policies []policyInfo, hasIPSet bool, ipsets []ipsetData) {
	// The generated timestamp is included in the signed payload (the rule bundle
	// content is signed by CompileAndStore via SignWithVersion), so callers should
	// not expect this header to be stable across regenerations of the same
	// policies. It is a human-readable audit trail, not a content-addressed key.
	now := time.Now().UTC().Format(time.RFC3339)
	buf.WriteString("# Runic rule bundle\n")
	fmt.Fprintf(buf, "# Host: %s\n", hostname)
	fmt.Fprintf(buf, "# Generated: %s\n", now)
	fmt.Fprintf(buf, "# Policies: %d\n", len(policies))
	if hasIPSet && len(ipsets) > 0 {
		fmt.Fprintf(buf, "# Ipsets: %d\n", len(ipsets))
	}
}

// ipsetFamilyForMembers selects the ipset address family for a group set.
//
// This bundle is IPv4-only (iptables-restore *filter): every group set is
// created family inet. hash:net sets are single-family, so an inet6 member
// would make the whole set unloadable (the agent creates sets family inet),
// and a mixed v4+v6 group cannot be represented in one hash:net set at all.
// Fail closed with ErrPreviewValidation on any IPv6 member, including mixed
// groups, until a separate ip6tables-restore bundle exists. The
// resolve.InternetSentinel marker (bare or normalized) is explicitly rejected
// here: it carries no ":" so without the check it would classify as IPv4 and
// return inet instead of failing closed.
func ipsetFamilyForMembers(members []string) (string, error) {
	hasV4 := false
	hasV6 := false
	var firstV6 string
	for _, m := range members {
		if isInternetSentinelCIDR(m) {
			return "", fmt.Errorf("internet sentinel %q must use runic_private_ranges ipset path, not group ipsets: %w", m, ErrPreviewValidation)
		}
		if isIPv6Address(m) {
			hasV6 = true
			if firstV6 == "" {
				firstV6 = m
			}
		} else {
			hasV4 = true
		}
	}
	switch {
	case hasV4 && hasV6:
		return "", fmt.Errorf("mixed IPv4/IPv6 group members (e.g. %q): hash:net is single-family, group ipsets are IPv4-only (family inet) until an ip6tables bundle exists: %w", firstV6, ErrPreviewValidation)
	case hasV6:
		return "", fmt.Errorf("IPv6 group member %q: group ipsets are IPv4-only (family inet) until an ip6tables bundle exists: %w", firstV6, ErrPreviewValidation)
	default:
		return "inet", nil
	}
}

// writeIpsetDefinitions writes ipset create/add definitions (before *filter).
//
// IPv4-only: group sets are always family inet; any IPv6 member fails closed
// with ErrPreviewValidation (see ipsetFamilyForMembers). runic_private_ranges
// is IPv4-only (RFC1918 + loopback) family inet; egress-to-internet on IPv6
// peers is rejected fail-closed in writeSourceSection/previewAppendRules
// because the IPv6 internet (ULA fc00::/7, link-local fe80::/10, ::1/128)
// would otherwise bypass the negation.
func (c *Compiler) writeIpsetDefinitions(buf *strings.Builder, hasIPSet bool, ipsets []ipsetData) error {
	if hasIPSet && len(ipsets) > 0 {
		buf.WriteString("\n# --- Ipset Definitions ---\n")
		for _, is := range ipsets {
			family, err := ipsetFamilyForMembers(is.Members)
			if err != nil {
				return fmt.Errorf("ipset %s: %w", is.Name, err)
			}
			fmt.Fprintf(buf, "create %s %s family %s\n", is.Name, is.SetType, family)
			for _, member := range is.Members {
				fmt.Fprintf(buf, "add %s %s\n", is.Name, member)
			}
			buf.WriteString("\n")
		}
	}

	privateCIDRs := privateFallbackCIDRList()
	if hasIPSet {
		buf.WriteString("# --- Ipset: Private Ranges for __internet__ exclusion (IPv4-only) ---\n")
		buf.WriteString("create runic_private_ranges hash:net family inet\n")
		for _, cidr := range privateCIDRs {
			fmt.Fprintf(buf, "add runic_private_ranges %s\n", cidr)
		}
		buf.WriteString("\n")
	}
	return nil
}

// writeFilterTableHeader writes the *filter table declaration and chain policies.
func (c *Compiler) writeFilterTableHeader(buf *strings.Builder, hasDocker bool) {
	buf.WriteString("*filter\n")
	buf.WriteString(":INPUT DROP [0:0]\n")
	buf.WriteString(":OUTPUT DROP [0:0]\n")
	buf.WriteString(":FORWARD DROP [0:0]\n")
	if hasDocker {
		buf.WriteString(":DOCKER-USER - [0:0]\n")
	}
	buf.WriteString("\n")
}

// writePolicySection iterates over all policies and generates corresponding iptables rules.
func (c *Compiler) writePolicySection(
	ctx context.Context,
	buf *strings.Builder,
	rw *ruleWriter,
	peerID int,
	policies []policyInfo,
	services map[int]ServiceInfo,
	groupIDToIpsetName map[int]string,
	hasDocker bool,
	hasIPSet bool,
	ipAddress string,
) error {
	for i := range policies {
		if err := c.writeSinglePolicy(ctx, buf, rw, peerID, &policies[i], services, groupIDToIpsetName, hasDocker, hasIPSet, ipAddress); err != nil {
			return err
		}
	}
	return nil
}

// writeSinglePolicy generates iptables rules for a single policy.
func (c *Compiler) writeSinglePolicy(
	ctx context.Context,
	buf *strings.Builder,
	rw *ruleWriter,
	peerID int,
	pol *policyInfo,
	services map[int]ServiceInfo,
	groupIDToIpsetName map[int]string,
	hasDocker bool,
	hasIPSet bool,
	ipAddress string,
) error {
	// Stored-policy invalid action indicates DB corruption, so Compile bundle
	// handlers surface it as 500. It still wraps ErrPreviewValidation so the
	// same user-controlled enum maps identically via errors.Is on both the
	// Compile and PreviewCompile paths (preview maps it to 400).
	if pol.Action != ActionAccept && pol.Action != ActionDrop && pol.Action != ActionLogDrop {
		return fmt.Errorf("invalid action %q for policy %s: must be one of ACCEPT, DROP, LOG_DROP: %w", pol.Action, pol.Name, ErrPreviewValidation)
	}
	writeToHost, writeToDocker := c.scopeFlags(pol.TargetScope, hasDocker)

	svc, ok := services[pol.ServiceID]
	if !ok {
		return fmt.Errorf("service %d not found", pol.ServiceID)
	}
	serviceName := svc.Name
	ports := svc.Ports
	sourcePorts := svc.SourcePorts
	protocol := svc.Protocol
	noConntrack := svc.NoConntrack

	// Expand ports for non-multicast, non-broadcast, and non-IGMP/VRRP services.
	// portClauses is nil when service is multicast/broadcast/IGMP/VRRP — these
	// services don't use transport-layer ports and rely on special rule types
	// (writeMulticastRule, writeBroadcastRule, writeIGMPRules, writeVRRPRules).
	var portClauses []PortClause
	isBroadcastService := serviceName == systemServiceSubnetBroadcast || serviceName == systemServiceLimitedBroadcast
	isIGMPorVRRP := strings.EqualFold(serviceName, systemServiceIGMP) || strings.EqualFold(serviceName, systemServiceVRRP)
	if !strings.EqualFold(serviceName, systemServiceMulticast) && !isBroadcastService && !isIGMPorVRRP {
		var err error
		portClauses, err = ExpandPorts(ports, sourcePorts, protocol)
		if err != nil {
			return fmt.Errorf("expand ports for policy %s: %w", pol.Name, err)
		}
	}

	fmt.Fprintf(buf, "# --- Policy: %s ---\n", pol.Name)

	// IG-001: Special IGMP handling - skip normal source/target resolution
	// VRRP-001: Special VRRP handling - skip normal source/target resolution
	if strings.EqualFold(serviceName, systemServiceIGMP) || strings.EqualFold(serviceName, systemServiceVRRP) {
		if writeToHost {
			if strings.EqualFold(serviceName, systemServiceIGMP) {
				c.writeIGMPRules(rw, pol.TargetScope, hasDocker)
			} else if strings.EqualFold(serviceName, systemServiceVRRP) {
				c.writeVRRPRules(rw, pol.TargetScope, hasDocker)
			}
		}
		buf.WriteString("\n")
		return nil
	}

	// Process as TARGET (Ingress traffic)
	if err := c.writeTargetSection(ctx, buf, rw, pol, portClauses, serviceName, protocol, groupIDToIpsetName, hasDocker, hasIPSet, ipAddress, writeToHost, writeToDocker, noConntrack); err != nil {
		return err
	}

	// Process as SOURCE (Egress traffic)
	if err := c.writeSourceSection(ctx, buf, rw, peerID, pol, portClauses, serviceName, groupIDToIpsetName, hasDocker, hasIPSet, ipAddress, writeToHost, writeToDocker, noConntrack); err != nil {
		return err
	}

	buf.WriteString("\n")
	return nil
}

// resolveEntityCIDRs looks up the CIDRs that represent the given entity (peer, group, or
// special target). It centralizes the special-case fallbacks for peer-with-IP and bare
// special targets. entityType and entityID identify the entity; the optional overrideIP is
// used for policies that pin a specific source or target IP (e.g., manual peer IPs).
// Override contract: plain-or-CIDR accepted like peers.ip_address, /0
// rejected (use __any_ip__ for allow-all). The override is validated with
// resolve.ValidatePeerCIDR before NormalizeToCIDR per the NormalizeToCIDR
// contract, so corrupt values fail closed instead of emitting "<bad>/32".
func (c *Compiler) resolveEntityCIDRs(ctx context.Context, entityType string, entityID int, overrideIP string, ipAddress string) ([]string, error) {
	// Defense: overrides only apply to peer entities. A non-peer entity with
	// a non-empty override would otherwise silently ignore the override and
	// compile against the entity's resolved CIDRs, hiding user error. Fail
	// closed with ErrPreviewValidation (400 in preview; 500 in Compile where
	// a stored override on a non-peer row indicates DB corruption).
	if overrideIP != "" && entityType != "peer" {
		return nil, fmt.Errorf("IP override %q for non-peer entity %q %d: overrides only apply to peer entities: %w", common.TruncateString(overrideIP, resolve.MaxLoggedIPLen), entityType, entityID, ErrPreviewValidation)
	}
	switch {
	case entityType == "special":
		return c.resolver.ResolveSpecialTarget(ctx, entityID, ipAddress)
	case entityType == "peer" && overrideIP != "":
		if err := resolve.ValidatePeerCIDR(overrideIP); err != nil {
			return nil, fmt.Errorf("invalid IP override %q: %w: %w", common.TruncateString(overrideIP, resolve.MaxLoggedIPLen), err, ErrPreviewValidation)
		}
		return []string{resolve.NormalizeToCIDR(overrideIP)}, nil
	default:
		return c.resolver.ResolveEntity(ctx, entityType, entityID)
	}
}

// writeTargetSection handles the "As Target" (Ingress) processing for a single policy.
func (c *Compiler) writeTargetSection(
	ctx context.Context,
	buf *strings.Builder,
	rw *ruleWriter,
	pol *policyInfo,
	portClauses []PortClause,
	serviceName, protocol string,
	groupIDToIpsetName map[int]string,
	hasDocker, hasIPSet bool,
	ipAddress string,
	writeToHost, writeToDocker bool,
	noConntrack bool,
) error {
	// MD-001: Skip "As Target" when target is a multicast/broadcast special.
	isSpecialMulticastOrBroadcastTarget := pol.TargetType == "special" &&
		(isMulticastSpecialID(pol.TargetID) || isBroadcastSpecialID(pol.TargetID))
	if !pol.IsTarget || (pol.Direction != "both" && pol.Direction != "backward") || isSpecialMulticastOrBroadcastTarget {
		return nil
	}

	// Fail closed: ingress-from-internet has no ipset negation semantics on
	// the INPUT path. The resolver would return the resolve.InternetSentinel
	// marker, which must never reach a "-s" literal.
	if pol.SourceType == "special" && pol.SourceID == resolve.SpecialIDInternet {
		return failClosedIngressInternetErr(pol.Name)
	}

	sourceName := c.formatEntityName(ctx, pol.SourceType, pol.SourceID)
	fmt.Fprintf(buf, "# As Target (Ingress from %s)\n", sourceName)

	isMulticastSource := pol.SourceType == "special" && isMulticastSpecialID(pol.SourceID)
	isBroadcastSource := pol.SourceType == "special" && isBroadcastSpecialID(pol.SourceID)

	canUseIpset := hasIPSet && pol.SourceType == "group"
	var ipsetName string
	if canUseIpset {
		ipsetName = groupIDToIpsetName[pol.SourceID]
	}
	useIpset := canUseIpset && ipsetName != ""

	switch {
	case isMulticastSource:
		c.writeMulticastRule(rw, pol.Action, pol.TargetScope, hasDocker)
	case isBroadcastSource:
		cidrs, err := c.resolver.ResolveSpecialTarget(ctx, pol.SourceID, ipAddress)
		if err != nil {
			return fmt.Errorf("resolve broadcast source for policy %s: %w", pol.Name, err)
		}
		for _, cidr := range cidrs {
			c.writeBroadcastRule(rw, pol.Action, pol.TargetScope, hasDocker, cidr, protocol)
		}
	case useIpset:
		if strings.EqualFold(serviceName, systemServiceMulticast) {
			c.writeMulticastRule(rw, pol.Action, pol.TargetScope, hasDocker)
		} else {
			rules, err := c.writeRules(pol, portClauses, true, ipsetName, nil, ipAddress, writeToHost, writeToDocker, noConntrack, ruleDirTarget, false)
			if err != nil {
				return err
			}
			for _, rule := range rules {
				buf.WriteString(rule + "\n")
			}
		}
	default:
		cidrs, err := c.resolveEntityCIDRs(ctx, pol.SourceType, pol.SourceID, pol.SourceIP, ipAddress)
		if err != nil {
			return fmt.Errorf("resolve source for policy %s: %w", pol.Name, err)
		}
		if strings.EqualFold(serviceName, systemServiceMulticast) {
			c.writeMulticastRule(rw, pol.Action, pol.TargetScope, hasDocker)
		} else {
			rules, err := c.writeRules(pol, portClauses, false, "", cidrs, ipAddress, writeToHost, writeToDocker, noConntrack, ruleDirTarget, false)
			if err != nil {
				return err
			}
			for _, rule := range rules {
				buf.WriteString(rule + "\n")
			}
		}
	}
	return nil
}

// writeSourceSection handles the "As Source" (Egress) processing for a single policy.
func (c *Compiler) writeSourceSection(
	ctx context.Context,
	buf *strings.Builder,
	rw *ruleWriter,
	peerID int,
	pol *policyInfo,
	portClauses []PortClause,
	serviceName string,
	groupIDToIpsetName map[int]string,
	hasDocker, hasIPSet bool,
	ipAddress string,
	writeToHost, writeToDocker bool,
	noConntrack bool,
) error {
	if !pol.IsSource || (pol.Direction != "both" && pol.Direction != "forward") {
		return nil
	}

	isInternetTarget := pol.TargetType == "special" && pol.TargetID == resolve.SpecialIDInternet
	// Internet targets share the host-context gate via checkInternetPeer:
	// peers with ipset support use the hardened runic_private_ranges
	// negation, while peers without ipset support render the explicit
	// four-negation fallback (anchored at 0.0.0.0/0) so the resolver's
	// resolve.InternetSentinel marker never leaks into a "-d" literal.
	// IPv4-only: both the ipset and the fallback negations cover only IPv4
	// private CIDRs, so an IPv6 peer would bypass the OUTPUT dst negation
	// for IPv6 internet destinations. Fail closed on IPv6 peers until an
	// inet6 private-ranges set with ip6tables rules exists. Empty peer IP
	// fails closed via the shared helper.
	if isInternetTarget {
		if err := checkInternetPeer(ipAddress, peerID, pol.Name); err != nil {
			return err
		}
	}

	targetName := c.formatEntityName(ctx, pol.TargetType, pol.TargetID)
	fmt.Fprintf(buf, "# As Source (Egress to %s)\n", targetName)

	canUseIpset := hasIPSet && pol.TargetType == "group"
	var ipsetName string
	if canUseIpset {
		ipsetName = groupIDToIpsetName[pol.TargetID]
	}
	useIpset := canUseIpset && ipsetName != ""

	switch {
	case useIpset:
		if strings.EqualFold(serviceName, systemServiceMulticast) {
			isMulticastTarget := pol.TargetType == "special" && isMulticastSpecialID(pol.TargetID)
			if isMulticastTarget && pol.Action == "ACCEPT" {
				if writeToHost {
					buf.WriteString("-A OUTPUT -d 224.0.0.0/4 -m pkttype --pkt-type multicast -j ACCEPT\n")
				}
				if writeToDocker {
					buf.WriteString("-A DOCKER-USER -d 224.0.0.0/4 -m pkttype --pkt-type multicast -j ACCEPT\n")
				}
			}
		} else {
			isMulticastTarget := pol.TargetType == "special" && isMulticastSpecialID(pol.TargetID)
			rules, err := c.writeRules(pol, portClauses, true, ipsetName, nil, ipAddress, writeToHost, writeToDocker, noConntrack, ruleDirSource, isMulticastTarget)
			if err != nil {
				return err
			}
			for _, rule := range rules {
				buf.WriteString(rule + "\n")
			}
		}
	case isInternetTarget:
		if hasIPSet {
			// ruleDir-only: keep useIpset/ipsetName unset so the builders take
			// the internet branch purely on ruleDir (mirrors previewAppendRules).
			isMulticastTarget := false
			rules, err := c.writeRules(pol, portClauses, false, "", nil, ipAddress, writeToHost, writeToDocker, noConntrack, ruleDirInternet, isMulticastTarget)
			if err != nil {
				return err
			}
			for _, rule := range rules {
				buf.WriteString(rule + "\n")
			}
		} else {
			// No-ipset fallback: explicit four-negation match anchored at
			// 0.0.0.0/0. Emits no runic_private_ranges reference.
			for _, rule := range c.buildInternetFallbackRules(pol, portClauses, writeToHost, writeToDocker, noConntrack) {
				buf.WriteString(rule + "\n")
			}
		}
	default:
		cidrs, err := c.resolveEntityCIDRs(ctx, pol.TargetType, pol.TargetID, pol.TargetIP, ipAddress)
		if err != nil {
			return fmt.Errorf("resolve target for policy %s: %w", pol.Name, err)
		}
		// Defense-in-depth (unreachable in normal flow): the resolve.InternetSentinel
		// must only travel the internet path above — when isInternetTarget the
		// isInternetTarget case is taken (ipset negation when hasIPSet, the
		// four-negation fallback otherwise), so the CIDR path can never see
		// the sentinel.
		// If it ever does (e.g., a future caller bypasses those gates), refuse
		// to emit "-d <sentinel>" rather than producing invalid iptables.
		for _, cidr := range cidrs {
			if isInternetSentinelCIDR(cidr) {
				return failClosedSentinelLeakErr(pol.Name)
			}
		}
		if strings.EqualFold(serviceName, systemServiceMulticast) {
			isMulticastTarget := pol.TargetType == "special" && isMulticastSpecialID(pol.TargetID)
			if isMulticastTarget && pol.Action == "ACCEPT" {
				if writeToHost {
					buf.WriteString("-A OUTPUT -d 224.0.0.0/4 -m pkttype --pkt-type multicast -j ACCEPT\n")
				}
				if writeToDocker {
					buf.WriteString("-A DOCKER-USER -d 224.0.0.0/4 -m pkttype --pkt-type multicast -j ACCEPT\n")
				}
			}
		} else {
			isMulticastTarget := pol.TargetType == "special" && isMulticastSpecialID(pol.TargetID)
			rules, err := c.writeRules(pol, portClauses, false, "", cidrs, ipAddress, writeToHost, writeToDocker, noConntrack, ruleDirSource, isMulticastTarget)
			if err != nil {
				return err
			}
			for _, rule := range rules {
				buf.WriteString(rule + "\n")
			}
		}
	}
	return nil
}

// writeLoggingSection writes the final logging and default deny rules.
func (c *Compiler) writeLoggingSection(buf *strings.Builder, hasDocker bool) {
	buf.WriteString("# --- Logging and default deny ---\n")
	fmt.Fprintf(buf, "-A INPUT -j LOG --log-prefix %q --log-level 4\n", dropPrefixFor(ChainInput))
	buf.WriteString("-A INPUT -j DROP\n")
	fmt.Fprintf(buf, "-A OUTPUT -j LOG --log-prefix %q --log-level 4\n", dropPrefixFor(ChainOutput))
	buf.WriteString("-A OUTPUT -j DROP\n")

	if hasDocker {
		buf.WriteString("\n")
		buf.WriteString("# --- Docker: DOCKER-USER chain default ---\n")
		buf.WriteString("-A DOCKER-USER -j RETURN\n")
	}
}

// IGMP is connectionless multicast, so no conntrack or return rules are needed.
func (c *Compiler) writeIGMPRules(rw *ruleWriter, targetScope string, hasDocker bool) {
	writeToHost, writeToDocker := c.scopeFlags(targetScope, hasDocker)

	if writeToHost {
		// Accept IGMP queries (224.0.0.1 = All Hosts on this subnet)
		rw.accept(ChainInput, "-d 224.0.0.1/32 -p igmp")
		// Send IGMPv3 reports (224.0.0.22 = IGMPv3 routers)
		rw.accept(ChainOutput, "-d 224.0.0.22/32 -p igmp")
	}
	if writeToDocker {
		rw.accept(ChainDockerUser, "-d 224.0.0.1/32 -p igmp")
		rw.accept(ChainDockerUser, "-d 224.0.0.22/32 -p igmp")
	}
}

// VRRP is a protocol for virtual router redundancy, using multicast 224.0.0.18.
// No conntrack or return rules are needed.
func (c *Compiler) writeVRRPRules(rw *ruleWriter, targetScope string, hasDocker bool) {
	writeToHost, writeToDocker := c.scopeFlags(targetScope, hasDocker)

	if writeToHost {
		// Accept VRRP advertisements (224.0.0.18 = VRRP multicast)
		rw.accept(ChainOutput, "-d 224.0.0.18/32 -p vrrp")
	}
	if writeToDocker {
		rw.accept(ChainDockerUser, "-d 224.0.0.18/32 -p vrrp")
	}
}

func (c *Compiler) writeMulticastRule(rw *ruleWriter, action string, targetScope string, hasDocker bool) {
	writeToHost, writeToDocker := c.scopeFlags(targetScope, hasDocker)

	if writeToHost {
		rw.writeAction(action, ChainInput, "-m pkttype --pkt-type multicast")
	}
	if writeToDocker {
		rw.writeAction(action, ChainDockerUser, "-m pkttype --pkt-type multicast")
	}
	rw.newline()
}

// Broadcast traffic is connectionless, so no conntrack or return rules are needed.
// For broadcast, we match on destination (-d) since broadcast packets are sent TO the broadcast address.
// protocol is read from the service in scope; it falls back to "udp" when empty or "both"
// because broadcast traffic in the system services ("Subnet Broadcast", "Limited Broadcast")
// is conventionally carried over UDP and the columns may be unset.
func (c *Compiler) writeBroadcastRule(rw *ruleWriter, action string, targetScope string, hasDocker bool, broadcastAddr string, protocol string) {
	writeToHost, writeToDocker := c.scopeFlags(targetScope, hasDocker)

	protocol = normalizeBroadcastProto(protocol)

	if writeToHost {
		// Accept broadcast traffic destined for the broadcast address
		rw.accept(ChainInput, fmt.Sprintf("-d %s -p %s", broadcastAddr, protocol))
	}
	if writeToDocker {
		rw.accept(ChainDockerUser, fmt.Sprintf("-d %s -p %s", broadcastAddr, protocol))
	}
}

func (c *Compiler) scopeFlags(targetScope string, hasDocker bool) (writeToHost, writeToDocker bool) {
	writeToHost = targetScope == "host" || targetScope == ScopeBoth
	writeToDocker = hasDocker && (targetScope == "docker" || targetScope == ScopeBoth)
	return
}

// logDropRule generates a LOG + DROP rule pair for a given chain and match.
// Uses direction-specific log prefix: RUNIC-DROP-I for INPUT/DOCKER-USER, RUNIC-DROP-O otherwise.
func (c *Compiler) logDropRule(action, chain, match string) []string {
	if action != ActionLogDrop {
		return []string{fmt.Sprintf("-A %s %s -j %s", chain, match, action)}
	}
	prefix := dropPrefixFor(chain)
	return []string{
		fmt.Sprintf("-A %s %s -j LOG --log-prefix %q --log-level 4", chain, match, prefix),
		fmt.Sprintf("-A %s %s -j DROP", chain, match),
	}
}

// --- Unified rule-writing ---
//
// writeRules generates iptables rules for a single policy's port clauses.
// It consolidates writeTargetRules, writeSourceRules, and writeInternetRules into one function.
//
// ruleDir controls the direction:
//
//	"target" — rules are for ingress (INPUT matches source, OUTPUT is return traffic)
//	"source" — rules are for egress (OUTPUT matches destination, INPUT is return traffic)
//	"internet" — same as "source" but uses runic_private_ranges ipset negation.
//	Internet via writeRules is ipset-only; no-ipset fallback bypasses
//	writeRules via buildInternetFallbackRules.
//	The internet path is selected solely by ruleDir; callers pass false,""
//	for useIpset/ipsetName and the builders assert it while always emitting
//	the hardcoded negation matches.
//
// Internal wiring errors (unknown ruleDir, assertInternetIpset) wrap
// ErrPreviewValidation so errors.Is works; Compile bundle handlers still
// surface them as 500 (they map all Compile errors to 500), while
// PreviewCompile maps them to 400 via isPreviewValidationError. By
// construction they only fire on programmer error, never on user input.
//
// isMulticastTarget when true adjusts INPUT return rule behavior for multicast targets.
func (c *Compiler) writeRules(
	pol *policyInfo,
	portClauses []PortClause,
	useIpset bool,
	ipsetName string,
	cidrs []string,
	ipAddress string,
	writeToHost, writeToDocker bool,
	noConntrack bool,
	ruleDir ruleDir,
	isMulticastTarget bool,
) ([]string, error) {
	// Fail-closed marker guard: the resolve.InternetSentinel marker (bare or
	// normalized) must never reach a "-s"/"-d" literal. Internet targets use
	// the ruleDirInternet ipset/fallback paths with nil cidrs; any sentinel
	// on the CIDR path indicates a caller wiring mistake.
	for _, cidr := range cidrs {
		if isInternetSentinelCIDR(cidr) {
			policyName := "preview"
			if pol != nil && pol.Name != "" {
				policyName = pol.Name
			}
			return nil, failClosedSentinelLeakErr(policyName)
		}
	}
	if pol.Action == ActionAccept {
		return c.buildAcceptRules(pol, portClauses, useIpset, ipsetName, cidrs, ipAddress, writeToHost, writeToDocker, noConntrack, ruleDir, isMulticastTarget)
	}
	return c.buildLogDropRules(pol, portClauses, useIpset, ipsetName, cidrs, ipAddress, writeToHost, writeToDocker, ruleDir)
}

// buildAcceptRules emits the iptables ACCEPT rules for a single policy's port clauses.
// It handles both the ipset and CIDR paths and the host/docker scopes. It also
// emits the INPUT return-traffic rules for the "source" direction.
//
// Rule-direction contract: the "internet" path is selected solely by
// ruleDir == ruleDirInternet and always uses the hardcoded
// runic_private_ranges negation matches; callers pass false,"" for
// useIpset/ipsetName and the builders assert it. The "target"/"source"
// paths use useIpset/ipsetName for group ipsets and cidrs otherwise.
func (c *Compiler) buildAcceptRules(
	pol *policyInfo,
	portClauses []PortClause,
	useIpset bool,
	ipsetName string,
	cidrs []string,
	ipAddress string,
	writeToHost, writeToDocker bool,
	noConntrack bool,
	ruleDir ruleDir,
	isMulticastTarget bool,
) ([]string, error) {
	var rules []string
	privateIpsetMatch := privateIpsetDstMatch()
	if ruleDir != ruleDirTarget && ruleDir != ruleDirSource && ruleDir != ruleDirInternet {
		return nil, fmt.Errorf("unknown ruleDir %q: %w", ruleDir, ErrPreviewValidation)
	}

	for _, pc := range portClauses {
		primaryPortMatch, returnPortMatch := splitPortMatches(pc)

		conntrackFull := conntrackMatch(noConntrack)

		// Internet path: gated solely on ruleDir. Emits the hardened
		// runic_private_ranges negation (OUTPUT dst + INPUT src return +
		// DOCKER-USER mirror) when either scope is enabled; with neither
		// scope enabled no rules are emitted, matching the non-internet paths.
		// useIpset/ipsetName are not consulted here; reject any set value to
		// catch caller wiring mistakes (callers must pass false,"").
		// Fragments join via joinRuleParts like the no-ipset fallback so
		// empty port or conntrack segments never emit double spaces.
		if ruleDir == ruleDirInternet {
			if err := assertInternetIpset(useIpset, ipsetName); err != nil {
				return nil, err
			}
			if writeToHost {
				rules = append(rules,
					joinRuleParts("-A OUTPUT", "-p", pc.Protocol, privateIpsetMatch, primaryPortMatch, conntrackFull, "-j", pol.Action),
					joinRuleParts("-A INPUT", "-p", pc.Protocol, privateIpsetSrcMatch(), returnPortMatch, conntrackFull, "-j", "ACCEPT"),
				)
			}
			if writeToDocker {
				rules = append(rules, joinRuleParts("-A DOCKER-USER", "-p", pc.Protocol, privateIpsetMatch, primaryPortMatch, conntrackFull, "-j", pol.Action))
			}
			continue
		}

		// For "source" direction, determine return CIDRs with multicast adjustments.
		// Computed for source only; the internet path continues above and uses
		// the private-ranges src negation instead of returnCIDRs.
		var returnCIDRs []string
		if ruleDir == ruleDirSource {
			if isMulticastTarget {
				if noConntrack {
					returnCIDRs = nil
				} else {
					returnCIDRs = []string{"0.0.0.0/0"}
				}
			} else {
				returnCIDRs = cidrs
			}
		}

		if useIpset {
			ipsetMatchPrimary := fmt.Sprintf("-m set --match-set %s src", ipsetName)
			ipsetMatchReturn := fmt.Sprintf("-m set --match-set %s dst", ipsetName)
			// For source direction, swap the ipset match roles
			if ruleDir == ruleDirSource {
				ipsetMatchPrimary, ipsetMatchReturn = ipsetMatchReturn, ipsetMatchPrimary
			}

			if writeToHost {
				switch ruleDir {
				case ruleDirTarget:
					rules = append(rules,
						fmt.Sprintf("-A INPUT -p %s %s %s %s -j %s", pc.Protocol, ipsetMatchPrimary, primaryPortMatch, conntrackFull, pol.Action),
						fmt.Sprintf("-A OUTPUT -p %s %s %s %s -j ACCEPT", pc.Protocol, ipsetMatchReturn, returnPortMatch, conntrackFull),
					)
				case ruleDirSource:
					rules = append(rules,
						fmt.Sprintf("-A OUTPUT -p %s %s %s %s -j %s", pc.Protocol, ipsetMatchPrimary, primaryPortMatch, conntrackFull, pol.Action),
						fmt.Sprintf("-A INPUT -p %s %s %s %s -j %s", pc.Protocol, ipsetMatchReturn, returnPortMatch, conntrackFull, pol.Action),
					)
				default:
					return nil, fmt.Errorf("unknown ruleDir %q: %w", ruleDir, ErrPreviewValidation)
				}
			}
			if writeToDocker {
				switch ruleDir {
				case ruleDirTarget:
					rules = append(rules, fmt.Sprintf("-A DOCKER-USER -p %s %s %s %s -j %s", pc.Protocol, ipsetMatchPrimary, primaryPortMatch, conntrackFull, pol.Action))
				case ruleDirSource:
					rules = append(rules, fmt.Sprintf("-A DOCKER-USER -p %s %s %s %s -j %s", pc.Protocol, ipsetMatchPrimary, primaryPortMatch, conntrackFull, pol.Action))
				default:
					return nil, fmt.Errorf("unknown ruleDir %q: %w", ruleDir, ErrPreviewValidation)
				}
			}
		} else {
			// Filter out self-referencing CIDRs (peer connecting to itself).
			// A CIDR is self-referencing if it exactly matches the peer's own
			// IP address (normalized to CIDR notation). For example, peer with
			// IP "10.0.0.1" has CIDR "10.0.0.1/32", so a source CIDR of
			// "10.0.0.1/32" is self-referencing. A CIDR range like "10.0.0.0/24"
			// is NOT self-referencing even if it contains the peer's IP.
			// Fail closed: invalid peer IP aborts compilation (no rules).
			filteredCidrs, err := filterSelfReferencingCIDRs(cidrs, ipAddress)
			if err != nil {
				return nil, err
			}

			for _, cidr := range filteredCidrs {
				if writeToHost {
					switch ruleDir {
					case ruleDirTarget:
						rules = append(rules,
							fmt.Sprintf("-A INPUT -s %s -p %s %s %s -j %s", cidr, pc.Protocol, primaryPortMatch, conntrackFull, pol.Action),
							fmt.Sprintf("-A OUTPUT -d %s -p %s %s %s -j ACCEPT", cidr, pc.Protocol, returnPortMatch, conntrackFull),
						)
					case ruleDirSource:
						rules = append(rules, fmt.Sprintf("-A OUTPUT -d %s -p %s %s %s -j %s", cidr, pc.Protocol, primaryPortMatch, conntrackFull, pol.Action))
					default:
						return nil, fmt.Errorf("unknown ruleDir %q: %w", ruleDir, ErrPreviewValidation)
					}
				}
				if writeToDocker {
					switch ruleDir {
					case ruleDirTarget:
						rules = append(rules, fmt.Sprintf("-A DOCKER-USER -s %s -p %s %s %s -j %s", cidr, pc.Protocol, primaryPortMatch, conntrackFull, pol.Action))
					case ruleDirSource:
						rules = append(rules, fmt.Sprintf("-A DOCKER-USER -d %s -p %s %s %s -j %s", cidr, pc.Protocol, primaryPortMatch, conntrackFull, pol.Action))
					default:
						return nil, fmt.Errorf("unknown ruleDir %q: %w", ruleDir, ErrPreviewValidation)
					}
				}
			}

			// Generate INPUT return rules for source direction.
			// (Internet never reaches the CIDR path; it returns above.)
			// Fail closed: invalid peer IP aborts compilation (no rules).
			if ruleDir == ruleDirSource {
				filteredReturnCidrs, err := filterSelfReferencingCIDRs(returnCIDRs, ipAddress)
				if err != nil {
					return nil, err
				}
				for _, returnCidr := range filteredReturnCidrs {
					rules = append(rules, fmt.Sprintf("-A INPUT -s %s -p %s %s %s -j ACCEPT", returnCidr, pc.Protocol, returnPortMatch, conntrackFull))
				}
			}
		}
	}
	return rules, nil
}

// buildLogDropRules emits LOG + DROP (or plain DROP) rules for a single policy's
// port clauses. It mirrors the ipset/CIDR structure of buildAcceptRules but
// omits the return-traffic block (rejected traffic is not echoed back).
//
// Rule-direction contract: the "internet" path is selected solely by
// ruleDir == ruleDirInternet and always uses the hardcoded
// runic_private_ranges negation match; callers pass false,"" for
// useIpset/ipsetName and the builders assert it.
func (c *Compiler) buildLogDropRules(
	pol *policyInfo,
	portClauses []PortClause,
	useIpset bool,
	ipsetName string,
	cidrs []string,
	ipAddress string,
	writeToHost, writeToDocker bool,
	ruleDir ruleDir,
) ([]string, error) {
	var rules []string
	privateIpsetMatch := privateIpsetDstMatch()
	if ruleDir != ruleDirTarget && ruleDir != ruleDirSource && ruleDir != ruleDirInternet {
		return nil, fmt.Errorf("unknown ruleDir %q: %w", ruleDir, ErrPreviewValidation)
	}

	for _, pc := range portClauses {
		// Internet path: gated solely on ruleDir. Emits the hardened
		// OUTPUT + DOCKER-USER negation matches (LOG/DROP via logDropRule)
		// when either scope is enabled; with neither scope enabled no rules
		// are emitted, matching the non-internet paths. useIpset/ipsetName
		// are not consulted here; reject any set value to catch caller
		// wiring mistakes (callers must pass false,"").
		if ruleDir == ruleDirInternet {
			if err := assertInternetIpset(useIpset, ipsetName); err != nil {
				return nil, err
			}
			if writeToHost {
				match := joinRuleParts("-p", pc.Protocol, privateIpsetMatch, pc.PortMatch)
				rules = append(rules, c.logDropRule(pol.Action, ChainOutput, match)...)
			}
			if writeToDocker {
				match := joinRuleParts("-p", pc.Protocol, privateIpsetMatch, pc.PortMatch)
				rules = append(rules, c.logDropRule(pol.Action, ChainDockerUser, match)...)
			}
			continue
		}
		if useIpset {
			ipsetMatchPrimary := fmt.Sprintf("-m set --match-set %s src", ipsetName)
			if ruleDir == ruleDirSource {
				// For source direction, the primary match is on dst (return traffic).
				ipsetMatchPrimary = fmt.Sprintf("-m set --match-set %s dst", ipsetName)
			}

			if writeToHost {
				chain := ChainInput
				if ruleDir == ruleDirSource {
					chain = ChainOutput
				}
				match := fmt.Sprintf("-p %s %s %s", pc.Protocol, ipsetMatchPrimary, pc.PortMatch)
				rules = append(rules, c.logDropRule(pol.Action, chain, match)...)
			}
			if writeToDocker {
				match := fmt.Sprintf("-p %s %s %s", pc.Protocol, ipsetMatchPrimary, pc.PortMatch)
				rules = append(rules, c.logDropRule(pol.Action, ChainDockerUser, match)...)
			}
		} else {
			// Fail closed: invalid peer IP aborts compilation (no rules).
			filteredCidrs, err := filterSelfReferencingCIDRs(cidrs, ipAddress)
			if err != nil {
				return nil, err
			}
			for _, cidr := range filteredCidrs {
				if writeToHost {
					switch ruleDir {
					case ruleDirTarget:
						rules = append(rules, c.logDropRule(pol.Action, ChainInput, fmt.Sprintf("-s %s -p %s %s", cidr, pc.Protocol, pc.PortMatch))...)
					case ruleDirSource:
						rules = append(rules, c.logDropRule(pol.Action, ChainOutput, fmt.Sprintf("-d %s -p %s %s", cidr, pc.Protocol, pc.PortMatch))...)
					default:
						return nil, fmt.Errorf("unknown ruleDir %q: %w", ruleDir, ErrPreviewValidation)
					}
				}
				if writeToDocker {
					switch ruleDir {
					case ruleDirTarget:
						rules = append(rules, c.logDropRule(pol.Action, ChainDockerUser, fmt.Sprintf("-s %s -p %s %s", cidr, pc.Protocol, pc.PortMatch))...)
					case ruleDirSource:
						rules = append(rules, c.logDropRule(pol.Action, ChainDockerUser, fmt.Sprintf("-d %s -p %s %s", cidr, pc.Protocol, pc.PortMatch))...)
					default:
						return nil, fmt.Errorf("unknown ruleDir %q: %w", ruleDir, ErrPreviewValidation)
					}
				}
			}
		}
	}
	return rules, nil
}

// privateIpsetDstMatch returns the ipset negation match for internet-bound
// OUTPUT rules, and privateIpsetSrcMatch the INPUT return-path variant.
// Hoisted so buildAcceptRules and buildLogDropRules share one definition.
func privateIpsetDstMatch() string {
	return "-m set ! --match-set " + ipsetPrivateRanges + " dst"
}

func privateIpsetSrcMatch() string {
	return "-m set ! --match-set " + ipsetPrivateRanges + " src"
}

// internetFallbackMatch returns the no-ipset Internet fallback match for the
// given address flag ("-d" for OUTPUT/DOCKER-USER, "-s" for INPUT return):
// anchored at 0.0.0.0/0 with explicit RFC1918+loopback negations from
// privateFallbackCIDRs. Single helper so the dst/src forms cannot diverge.
func internetFallbackMatch(flag string) string {
	parts := []string{flag + " 0.0.0.0/0"}
	for _, cidr := range privateFallbackCIDRList() {
		parts = append(parts, "! "+flag+" "+cidr)
	}
	return strings.Join(parts, " ")
}

// internetFallbackDstMatch returns the no-ipset Internet fallback match for
// OUTPUT and DOCKER-USER rules: anchored at 0.0.0.0/0 with four explicit
// RFC1918+loopback negations. It mirrors the runic_private_ranges CIDRs via
// privateFallbackCIDRs without referencing the ipset, so peers without
// ipset support can still express egress-to-internet.
func internetFallbackDstMatch() string {
	return internetFallbackMatch("-d")
}

// internetFallbackSrcMatch returns the no-ipset Internet fallback match for
// INPUT return rules: the ! -s equivalents of internetFallbackDstMatch,
// anchored at 0.0.0.0/0.
func internetFallbackSrcMatch() string {
	return internetFallbackMatch("-s")
}

// joinRuleParts joins non-empty rule fragments with single spaces so empty
// port or conntrack segments never emit double spaces.
func joinRuleParts(parts ...string) string {
	nonEmpty := make([]string, 0, len(parts))
	for _, p := range parts {
		if p != "" {
			nonEmpty = append(nonEmpty, p)
		}
	}
	return strings.Join(nonEmpty, " ")
}

// splitPortMatches derives the primary (OUTPUT) and return (INPUT) port
// matches for one PortClause. Shared by buildAcceptRules and
// buildInternetFallbackRules so the two cannot diverge.
func splitPortMatches(pc PortClause) (primary, ret string) {
	primary = pc.PortMatch
	if pc.SrcPortMatch != "" {
		primary = pc.SrcPortMatch + " " + primary
	}
	ret = invertPortMatch(pc.PortMatch, pc.SrcPortMatch)
	return primary, ret
}

// conntrackMatch returns the conntrack match for ACCEPT rules, or "" when
// noConntrack disables it. Shared by buildAcceptRules and
// buildInternetFallbackRules so the two cannot diverge.
func conntrackMatch(noConntrack bool) string {
	if noConntrack {
		return ""
	}
	return "-m conntrack --ctstate NEW,ESTABLISHED"
}

// buildInternetFallbackRules renders egress-to-internet for peers without
// ipset support using the explicit four-negation fallback anchored at
// 0.0.0.0/0. It mirrors the ipset internet path shape exactly: ACCEPT uses
// primaryPortMatch (PortMatch plus SrcPortMatch) on OUTPUT with the
// invertPortMatch-derived returnPortMatch on the INPUT return, while
// DROP/LOG_DROP uses PortMatch only like the ipset path; noConntrack
// (ACCEPT includes the conntrack match unless disabled; DROP/LOG_DROP omits
// conntrack like the ipset path), writeToHost/writeToDocker scope selection
// (with neither scope enabled no rules are emitted), and pol.Action (ACCEPT
// gets OUTPUT plus the INPUT return; DROP/LOG_DROP are OUTPUT-only via
// logDropRule). Rule fragments are joined via joinRuleParts so empty port or
// conntrack segments never emit double spaces. It emits no
// runic_private_ranges reference.
func (c *Compiler) buildInternetFallbackRules(pol *policyInfo, portClauses []PortClause, writeToHost, writeToDocker bool, noConntrack bool) []string {
	var rules []string
	dstMatch := internetFallbackDstMatch()
	srcMatch := internetFallbackSrcMatch()
	for _, pc := range portClauses {
		primaryPortMatch, returnPortMatch := splitPortMatches(pc)

		conntrackFull := conntrackMatch(noConntrack)

		if pol.Action == ActionAccept {
			if writeToHost {
				rules = append(rules,
					joinRuleParts("-A OUTPUT", dstMatch, "-p", pc.Protocol, primaryPortMatch, conntrackFull, "-j", pol.Action),
					joinRuleParts("-A INPUT", srcMatch, "-p", pc.Protocol, returnPortMatch, conntrackFull, "-j ACCEPT"),
				)
			}
			if writeToDocker {
				rules = append(rules, joinRuleParts("-A DOCKER-USER", dstMatch, "-p", pc.Protocol, primaryPortMatch, conntrackFull, "-j", pol.Action))
			}
		} else {
			if writeToHost {
				match := joinRuleParts(dstMatch, "-p", pc.Protocol, pc.PortMatch)
				rules = append(rules, c.logDropRule(pol.Action, ChainOutput, match)...)
			}
			if writeToDocker {
				match := joinRuleParts(dstMatch, "-p", pc.Protocol, pc.PortMatch)
				rules = append(rules, c.logDropRule(pol.Action, ChainDockerUser, match)...)
			}
		}
	}
	return rules
}

// filterSelfReferencingCIDRs returns cidrs with any entries equal to the peer's
// own normalized CIDR (e.g., "10.0.0.1/32") removed. Peer-to-self traffic is
// not relevant for firewall rules and would otherwise generate matching rules
// that block loopback-shaped connections.
//
// NormalizeToCIDR performs no validation by contract (unparseable input gets
// "/32"), so the peer IP is validated with resolve.ValidatePeerCIDR first
// per its contract. A corrupt or /0 peer IP yields no reliable self CIDR;
// fail closed by returning an error (no rules) rather than returning cidrs
// unfiltered (which would emit extra INPUT -s ACCEPT rules, more permissive)
// or filtering against a garbage "<bad>/32" peerCIDR that would silently
// disable the filter. An empty peer IP means no host context (preview without
// a peer, or a peer row with no address): there is no self CIDR to exclude,
// so return cidrs unfiltered with no error. Internet targets with an empty
// peer IP still fail closed via the explicit empty-IP gates in
// writeSourceSection/previewAppendRules/previewForward. Callers propagate
// the error, aborting compilation. Wraps ErrPreviewValidation so errors.Is
// works; Compile bundle handlers still surface it as 500 (stored corrupt IP
// is DB corruption), while PreviewCompile maps it to 400.
func filterSelfReferencingCIDRs(cidrs []string, ipAddress string) ([]string, error) {
	if ipAddress == "" {
		return cidrs, nil
	}
	if err := resolve.ValidatePeerCIDR(ipAddress); err != nil {
		return nil, fmt.Errorf("invalid peer IP %q: %w: %w", common.TruncateString(ipAddress, resolve.MaxLoggedIPLen), err, ErrPreviewValidation)
	}
	peerCIDR := resolve.NormalizeToCIDR(ipAddress)
	filtered := make([]string, 0, len(cidrs))
	for _, cidr := range cidrs {
		if cidr != peerCIDR {
			filtered = append(filtered, cidr)
		}
	}
	return filtered, nil
}

// previewState aggregates the inputs and resolved CIDRs that PreviewCompile needs
// to render the four (host/docker × forward/backward) rule sections. Keeping these
// fields on a struct lets the per-section helpers take a single parameter rather
// than a long argument list, and avoids accidental divergence between the four
// sections that share most of their inputs.
type previewState struct {
	// Resolved inputs
	ipAddress        string
	hasIPSet         bool
	peerID           int
	serviceName      string
	protocol         string
	noConntrack      bool
	portClauses      []PortClause
	sourceCIDRs      []string
	targetCIDRs      []string
	isInternetTarget bool

	// Pol derived from the action string
	pol *policyInfo

	// Direction and scope (already defaulted to "both")
	direction   string
	targetScope string
}

// loadPreviewInputs loads the per-peer peer IP, the service definition, and the
// expanded port clauses for a single preview invocation. It centralizes the
// defaults (direction = "both", targetScope = "both") and the special-service
// (multicast, IGMP, VRRP) port-skip logic.
func (c *Compiler) loadPreviewInputs(ctx context.Context, peerID, serviceID int, direction, targetScope string) (previewState, error) {
	st := previewState{
		peerID:      peerID,
		direction:   direction,
		targetScope: targetScope,
	}
	if st.direction == "" {
		st.direction = DirBoth
	}
	if st.targetScope == "" {
		st.targetScope = ScopeBoth
	}

	if peerID != 0 {
		// Thread hasIPSet so the preview gates the internet path identically
		// to writeSourceSection (hasIPSet && isInternetTarget). Without this,
		// the preview would show ipset-negation rules for hosts that cannot
		// apply them. Single round-trip for both peer inputs.
		// Unknown peer IDs fail closed as validation errors (400 via
		// ErrPreviewValidation-wrapped sql.ErrNoRows); other DB failures
		// are internal (500) so a DB outage never yields a 200 with
		// wrong rules.
		// SQLite stores BOOLEAN as INTEGER 0/1 (has_ipset is nullable,
		// hence the COALESCE), but the driver may return bool (tests) or
		// int64 (prod). Scan into any and convert via scanBool.
		var hasIPSetRaw any
		if err := c.db.QueryRowContext(ctx,
			"SELECT ip_address, COALESCE(has_ipset, 0) FROM peers WHERE id = ?", peerID,
		).Scan(&st.ipAddress, &hasIPSetRaw); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return previewState{}, fmt.Errorf("unknown peer %d: %w: %w", peerID, sql.ErrNoRows, ErrPreviewValidation)
			}
			return previewState{}, fmt.Errorf("load peer: %w", err)
		}
		st.hasIPSet = scanBool(hasIPSetRaw)
	} else {
		// No peer context: keep the canonical ipset form (hasIPSet=true) so
		// internet previews render the hardened runic_private_ranges
		// negation. Empty-IP/IPv6 gates are bypassed for peerID 0 via
		// st.peerID in previewForward/previewAppendRules.
		st.hasIPSet = true
	}

	// Load service - MC-011: Include no_conntrack column
	// SQLite stores BOOLEAN as INTEGER 0/1, but the driver may return bool
	// (tests) or int64 (prod). Scan into any and convert via scanBool.
	var ports, sourcePorts string
	var noConntrackRaw any
	err := c.db.QueryRowContext(ctx,
		"SELECT name, ports, source_ports, protocol, COALESCE(no_conntrack, 0) FROM services WHERE id = ? AND is_pending_delete = 0", serviceID,
	).Scan(&st.serviceName, &ports, &sourcePorts, &st.protocol, &noConntrackRaw)
	if errors.Is(err, sql.ErrNoRows) {
		return previewState{}, fmt.Errorf("service %d is pending delete or does not exist: %w", serviceID, ErrPreviewValidation)
	}
	if err != nil {
		return previewState{}, fmt.Errorf("load service: %w", err)
	}
	st.noConntrack = scanBool(noConntrackRaw)

	// Skip port expansion for special services that don't use ports.
	isIGMPorVRRP := strings.EqualFold(st.serviceName, systemServiceIGMP) || strings.EqualFold(st.serviceName, systemServiceVRRP)
	if !strings.EqualFold(st.serviceName, systemServiceMulticast) && !isIGMPorVRRP {
		clauses, err := ExpandPorts(ports, sourcePorts, st.protocol)
		if err != nil {
			return previewState{}, fmt.Errorf("expand ports: %w: %w", err, ErrPreviewValidation)
		}
		st.portClauses = clauses
	}
	return st, nil
}

// resolvePreviewSourcesAndTargets resolves both endpoints of the policy into
// CIDR lists, applying the same special/peer-with-ip/entity fallbacks that
// writeTargetSection / writeSourceSection use in Compile.
func (c *Compiler) resolvePreviewSourcesAndTargets(ctx context.Context, st *previewState, sourceType string, sourceID int, sourceIP, targetType string, targetID int, targetIP string) error {
	var err error
	st.sourceCIDRs, err = c.resolveEntityCIDRs(ctx, sourceType, sourceID, sourceIP, st.ipAddress)
	if err != nil {
		return fmt.Errorf("resolve source entity %s/%d: %w", sourceType, sourceID, err)
	}
	st.targetCIDRs, err = c.resolveEntityCIDRs(ctx, targetType, targetID, targetIP, st.ipAddress)
	if err != nil {
		return fmt.Errorf("resolve target entity %s/%d: %w", targetType, targetID, err)
	}
	st.isInternetTarget = targetType == "special" && targetID == resolve.SpecialIDInternet
	return nil
}

// previewAppendRules is a small helper that calls writeRules and appends the
// result to rules. writeToHost/writeToDocker select the host or DOCKER-USER
// chains so host and docker preview sections share one call path. Internet
// targets use ipset semantics (runic_private_ranges negation, IPv4-only) so
// the preview matches the Compile path in writeSourceSection, including the
// fail-closed behavior for empty-IP/IPv6 peers via checkInternetPeer.
// No-ipset fallback is handled in previewForward via
// buildInternetFallbackRules; this helper is ipset-only defense. PeerID 0
// (no peer context) keeps the canonical ipset form and bypasses the gates
// via checkInternetPeer. The internet path is selected solely by
// ruleDir; callers pass false,"" for useIpset/ipsetName and the builders
// assert it, so this helper always passes false,"" and lets ruleDir drive
// the negation match.
func (c *Compiler) previewAppendRules(rules []string, st *previewState, pol *policyInfo, portClauses []PortClause, cidrs []string, isMulticastTarget bool, ruleDir ruleDir, writeToHost, writeToDocker bool) ([]string, error) {
	useIpset := false
	ipsetName := ""
	if ruleDir == ruleDirInternet {
		if err := checkInternetPeer(st.ipAddress, st.peerID, "preview"); err != nil {
			return nil, err
		}
		// Defense: user-facing no-ipset goes via buildInternetFallbackRules
		// in previewForward; reaching here with !hasIPSet indicates a caller
		// wiring mistake, not a user-facing fail-closed.
		if st.peerID != 0 && !st.hasIPSet {
			return nil, fmt.Errorf("preview internet without ipset must use fallback (peer %d): programmer error: %w", st.peerID, ErrPreviewValidation)
		}
		// ruleDir-only: keep useIpset/ipsetName unset so the builders take
		// the internet branch purely on ruleDir.
	} else {
		// Defense-in-depth: the sentinel (bare or normalized via
		// NormalizeToCIDR, e.g. "__internet__/32") must never reach a
		// "-s"/"-d" literal on the CIDR path. Unify with the writeRules
		// guard on failClosedSentinelLeakErr; ingress/internet errors stay
		// with the pre-resolution semantic gates.
		for _, cidr := range cidrs {
			if isInternetSentinelCIDR(cidr) {
				return nil, failClosedSentinelLeakErr("preview")
			}
		}
	}
	generated, err := c.writeRules(pol, portClauses, useIpset, ipsetName, cidrs, st.ipAddress, writeToHost, writeToDocker, st.noConntrack, ruleDir, isMulticastTarget)
	if err != nil {
		return nil, err
	}
	return append(rules, generated...), nil
}

// isPreviewSpecialService reports whether the service skips port handling
// and renders fixed IGMP/VRRP rules in previews.
func isPreviewSpecialService(serviceName string) bool {
	return strings.EqualFold(serviceName, systemServiceIGMP) || strings.EqualFold(serviceName, systemServiceVRRP)
}

// normalizeBroadcastProto normalizes the broadcast protocol, defaulting to udp
// when the service protocol is empty or "both" — broadcast system services
// in this codebase use UDP, and treating "both" as udp matches the historical
// hardcoded behavior.
func normalizeBroadcastProto(protocol string) string {
	if protocol == "" || strings.EqualFold(protocol, ProtoBoth) {
		return "udp"
	}
	return protocol
}

// previewHostForward renders the "Source → Target" rules that target the host
// chains (INPUT/OUTPUT) when targetScope is "host" or "both". It handles IGMP,
// VRRP, multicast, internet, and the regular peer/group case.
func (c *Compiler) previewHostForward(st *previewState, targetType string, targetID int) ([]string, error) {
	return c.previewForward(st, targetType, targetID, ChainInput, "# Forward (Source → Target)", true, false, "host")
}

// previewDockerForward is the DOCKER-USER equivalent of previewHostForward.
func (c *Compiler) previewDockerForward(st *previewState, targetType string, targetID int) ([]string, error) {
	return c.previewForward(st, targetType, targetID, ChainDockerUser, "# Docker: DOCKER-USER chain rules", false, true, "docker")
}

// previewForward renders forward (Source → Target) rules for either the host
// or docker chains. wantScope selects which targetScope values render.
func (c *Compiler) previewForward(st *previewState, targetType string, targetID int, chain, header string, writeToHost, writeToDocker bool, wantScope string) ([]string, error) {
	if st.targetScope != wantScope && st.targetScope != ScopeBoth {
		return nil, nil
	}

	// Short-circuit before any CIDR iteration.
	switch {
	case strings.EqualFold(st.serviceName, systemServiceIGMP):
		if chain == ChainDockerUser {
			return []string{
				"-A DOCKER-USER -d 224.0.0.1/32 -p igmp -j ACCEPT",
				"-A DOCKER-USER -d 224.0.0.22/32 -p igmp -j ACCEPT",
			}, nil
		}
		return []string{
			"-A INPUT -d 224.0.0.1/32 -p igmp -j ACCEPT",
			"-A OUTPUT -d 224.0.0.22/32 -p igmp -j ACCEPT",
		}, nil
	case strings.EqualFold(st.serviceName, systemServiceVRRP):
		if chain == ChainDockerUser {
			return []string{"-A DOCKER-USER -d 224.0.0.18/32 -p vrrp -j ACCEPT"}, nil
		}
		return []string{"-A OUTPUT -d 224.0.0.18/32 -p vrrp -j ACCEPT"}, nil
	}

	if st.direction != "both" && st.direction != "forward" {
		return nil, nil
	}

	rules := []string{header}

	// Multicast special targets as Destination receive via pkttype
	// matching rather than per-CIDR output rules. Emit the rule once, outside
	// the CIDR loop, since the same `224.0.0.0/4` block covers all members.
	if strings.EqualFold(st.serviceName, systemServiceMulticast) && targetType == "special" && isMulticastSpecialID(targetID) {
		if chain == ChainDockerUser {
			rules = append(rules, "-A DOCKER-USER -d 224.0.0.0/4 -m pkttype --pkt-type multicast -j ACCEPT")
		} else {
			rules = append(rules, "-A OUTPUT -d 224.0.0.0/4 -m pkttype --pkt-type multicast -j ACCEPT")
		}
		return rules, nil
	}

	// Use writeSourceRules for forward direction (egress). Gate the internet
	// path identically to writeSourceSection via checkInternetPeer: peers with
	// ipset support use the hardened runic_private_ranges negation, while
	// peers without ipset support render the explicit four-negation fallback
	// anchored at 0.0.0.0/0. PeerID 0 (no peer context) keeps the canonical
	// ipset form. IPv4-only: IPv6 peers fail closed like Compile because
	// runic_private_ranges cannot cover IPv6 internet destinations. Empty peer
	// IP fails closed like Compile; skipped for peerID 0 which has no host
	// to validate via checkInternetPeer.
	if st.isInternetTarget {
		if err := checkInternetPeer(st.ipAddress, st.peerID, "preview"); err != nil {
			return nil, err
		}
		if st.peerID == 0 || st.hasIPSet {
			return c.previewAppendRules(rules, st, st.pol, st.portClauses, nil, false, ruleDirInternet, writeToHost, writeToDocker)
		}
		// No-ipset fallback: explicit four-negation match anchored at
		// 0.0.0.0/0, mirroring writeSourceSection. Emits no
		// runic_private_ranges reference. Shared by host and docker via
		// this function through previewHostForward/previewDockerForward.
		return append(rules, c.buildInternetFallbackRules(st.pol, st.portClauses, writeToHost, writeToDocker, st.noConntrack)...), nil
	}
	isMulticastTarget := targetType == "special" && isMulticastSpecialID(targetID)
	return c.previewAppendRules(rules, st, st.pol, st.portClauses, st.targetCIDRs, isMulticastTarget, ruleDirSource, writeToHost, writeToDocker)
}

// previewHostBackward renders the "Target → Source" rules that target the host
// chains (INPUT/OUTPUT) when targetScope is "host" or "both" and direction is
// "both" or "backward". It handles multicast/broadcast sources, plus the
// regular peer/group case.
func (c *Compiler) previewHostBackward(st *previewState, sourceType string, sourceID int) ([]string, error) {
	return c.previewBackward(st, sourceType, sourceID, ChainInput, true, false, "host", true)
}

// previewDockerBackward is the DOCKER-USER equivalent of previewHostBackward.
func (c *Compiler) previewDockerBackward(st *previewState, sourceType string, sourceID int) ([]string, error) {
	return c.previewBackward(st, sourceType, sourceID, ChainDockerUser, false, true, "docker", false)
}

// previewBackward renders backward (Target → Source) rules for either chain.
// withHeader controls whether the "# Backward" header is emitted; the docker
// path historically omits it for generated sections.
func (c *Compiler) previewBackward(st *previewState, sourceType string, sourceID int, chain string, writeToHost, writeToDocker bool, wantScope string, withHeader bool) ([]string, error) {
	if st.targetScope != wantScope && st.targetScope != ScopeBoth {
		return nil, nil
	}
	// Skip backward — already rendered in the forward section.
	if isPreviewSpecialService(st.serviceName) {
		return nil, nil
	}
	if st.direction != "both" && st.direction != "backward" {
		return nil, nil
	}

	// Fail closed: ingress-from-internet has no preview semantics either,
	// matching the Compile gate in writeTargetSection. The resolver would
	// return the resolve.InternetSentinel marker, which must never reach a "-s"
	// literal via the default branch below.
	if sourceType == "special" && sourceID == resolve.SpecialIDInternet {
		return nil, failClosedIngressInternetErr("preview")
	}

	// Multicast / broadcast special sources indicate receiving
	// traffic via pkttype matching (-d 224.0.0.0/4 multicast) or destination-
	// address matching for broadcast.
	isMulticastSource := sourceType == "special" && isMulticastSpecialID(sourceID)
	isBroadcastSource := sourceType == "special" && isBroadcastSpecialID(sourceID)

	var rules []string
	if withHeader {
		rules = []string{"# Backward (Target → Source)"}
	}

	switch {
	case isMulticastSource:
		if strings.EqualFold(st.serviceName, systemServiceMulticast) {
			if chain == ChainDockerUser {
				return []string{"-A DOCKER-USER -m pkttype --pkt-type multicast -j ACCEPT"}, nil
			}
			return append(rules, "-A INPUT -m pkttype --pkt-type multicast -j ACCEPT"), nil
		}
		return c.previewAppendRules(rules, st, st.pol, st.portClauses, st.sourceCIDRs, false, ruleDirTarget, writeToHost, writeToDocker)
	case isBroadcastSource:
		// Broadcast traffic: -d match against the broadcast address. The
		// protocol is read from the service in scope and falls back to "udp"
		// when empty or "both" (matching the historical hardcoded behavior).
		// Defense-in-depth: refuse to emit a sentinel-derived "-d" literal
		// (bare or normalized) on this direct CIDR path.
		for _, cidr := range st.sourceCIDRs {
			if isInternetSentinelCIDR(cidr) {
				return nil, failClosedIngressInternetErr("preview")
			}
		}
		proto := normalizeBroadcastProto(st.protocol)
		for _, sourceCIDR := range st.sourceCIDRs {
			rules = append(rules, fmt.Sprintf("-A %s -d %s -p %s -j ACCEPT", chain, sourceCIDR, proto))
		}
		return rules, nil
	default:
		return c.previewAppendRules(rules, st, st.pol, st.portClauses, st.sourceCIDRs, false, ruleDirTarget, writeToHost, writeToDocker)
	}
}

// PreviewCompile generates iptables rules for a single policy. Unlike Compile(), this is policy-centric: it resolves both source and target entities
// and generates rules based on direction, showing the complete picture across all hosts.
func (c *Compiler) PreviewCompile(ctx context.Context, peerID, sourceID int, sourceType string, sourceIP string, targetID int, targetType string, targetIP string, serviceID int, action, direction string, targetScope string) ([]string, error) {
	if !resolve.IsValidAction(action) {
		return nil, fmt.Errorf("invalid action %q: must be one of ACCEPT, DROP, LOG_DROP: %w", action, ErrPreviewValidation)
	}
	if !resolve.IsValidEntityType(sourceType) {
		return nil, fmt.Errorf("invalid source_type %q: must be one of peer, group, special: %w", sourceType, ErrPreviewValidation)
	}
	if !resolve.IsValidEntityType(targetType) {
		return nil, fmt.Errorf("invalid target_type %q: must be one of peer, group, special: %w", targetType, ErrPreviewValidation)
	}
	if direction != "" && !resolve.IsValidDirection(direction) {
		return nil, fmt.Errorf("invalid direction %q: must be one of both, forward, backward: %w", direction, ErrPreviewValidation)
	}
	if targetScope != "" && !resolve.IsValidTargetScope(targetScope) {
		return nil, fmt.Errorf("invalid target_scope %q: must be one of both, host, docker: %w", targetScope, ErrPreviewValidation)
	}
	st, err := c.loadPreviewInputs(ctx, peerID, serviceID, direction, targetScope)
	if err != nil {
		return nil, err
	}
	if err := c.resolvePreviewSourcesAndTargets(ctx, &st, sourceType, sourceID, sourceIP, targetType, targetID, targetIP); err != nil {
		return nil, err
	}
	st.pol = &policyInfo{Action: action}

	var rules []string
	for _, section := range []func() ([]string, error){
		func() ([]string, error) { return c.previewHostForward(&st, targetType, targetID) },
		func() ([]string, error) { return c.previewHostBackward(&st, sourceType, sourceID) },
		func() ([]string, error) { return c.previewDockerForward(&st, targetType, targetID) },
		func() ([]string, error) { return c.previewDockerBackward(&st, sourceType, sourceID) },
	} {
		more, err := section()
		if err != nil {
			return nil, err
		}
		rules = append(rules, more...)
	}
	return rules, nil
}

func (c *Compiler) CompileAndStore(ctx context.Context, peerID int) (models.RuleBundleRow, error) {
	content, err := c.Compile(ctx, peerID)
	if err != nil {
		return models.RuleBundleRow{}, fmt.Errorf("compile: %w", err)
	}

	var hmacKey string
	err = c.db.QueryRowContext(ctx, "SELECT hmac_key FROM peers WHERE id = ?", peerID).Scan(&hmacKey)
	if err != nil {
		return models.RuleBundleRow{}, fmt.Errorf("fetch peer HMAC key: %w", err)
	}

	// Compute next version number for this peer
	var versionNumber int
	err = c.db.QueryRowContext(ctx,
		"SELECT COALESCE(MAX(version_number), 0) + 1 FROM rule_bundles WHERE peer_id = ?", peerID).Scan(&versionNumber)
	if err != nil {
		return models.RuleBundleRow{}, fmt.Errorf("get next version number: %w", err)
	}

	version := Version(content)
	signature := SignWithVersion(content, hmacKey, versionNumber)

	// Use db.SaveBundle to avoid duplicate transaction logic
	params := models.CreateBundleParams{
		PeerID:        peerID,
		Version:       version,
		VersionNumber: versionNumber,
		RulesContent:  content,
		HMAC:          signature,
	}

	bundle, err := db.SaveBundle(ctx, c.beginner, params)
	if err != nil {
		return models.RuleBundleRow{}, fmt.Errorf("save bundle: %w", err)
	}

	return bundle, nil
}

func (c *Compiler) RecompileAffectedPeers(ctx context.Context, groupID int) error {
	if c == nil || c.db == nil {
		return fmt.Errorf("recompile affected peers for group %d: compiler or db is nil", groupID)
	}
	// Collect all transitively related groups. When a peer is added to a group,
	// it also affects any other group that shares peers with this group (transitive
	// membership via overlapping group membership). We find all groups that share
	// at least one peer with the given group, then recompile all affected peers
	// for the entire set of related groups.
	// Detach from the caller's context so cancellation does not expire the
	// fan-out mid-loop. Each stage below gets its own timeout (mirroring
	// processGroupChange) so a large fan-out cannot expire mid-loop and
	// leave half-recompiled peers.
	base := ctx
	if base == nil {
		base = context.Background()
	} else {
		base = context.WithoutCancel(base)
	}
	transCtx, transCancel := context.WithTimeout(base, 5*time.Second)
	allGroupIDs, transErr := c.collectTransitiveGroupIDs(transCtx, groupID)
	transCancel()

	// Collect all affected peer IDs from policies referencing any related group.
	// Deduplicate policy IDs across groups and resolve them with the batched
	// helper so the fan-out is a single engine call instead of an N+1 loop.
	// Peer dedup uses the shared common.MergePeerIDs helper (leaf
	// internal/common, no cycle) so the engine and the change worker share
	// one map-dedup+sort implementation.
	policySeen := make(map[int]struct{})
	var allPolicyIDs []int
	// Per-group continue: one bad group must not drop the policies of the
	// other groups, mirroring the per-policy continue+errors.Join semantics
	// of GetAffectedPeersByPolicies. A transitive traversal failure joins
	// here so callers never see silent success with missing groups.
	var groupErr error
	if transErr != nil {
		groupErr = errors.Join(groupErr, transErr)
	}
	for _, gid := range allGroupIDs {
		groupCtx, groupCancel := context.WithTimeout(base, 5*time.Second)
		policyIDs, err := c.findPoliciesByGroup(groupCtx, gid)
		groupCancel()
		if err != nil {
			groupErr = errors.Join(groupErr, fmt.Errorf("group %d: %w", gid, err))
			continue
		}
		for _, pid := range policyIDs {
			if _, ok := policySeen[pid]; !ok {
				policySeen[pid] = struct{}{}
				allPolicyIDs = append(allPolicyIDs, pid)
			}
		}
	}
	var resolveErr error
	var peerSlices [][]int
	if len(allPolicyIDs) > 0 {
		resolveCtx, resolveCancel := context.WithTimeout(base, 10*time.Second)
		affectedByPolicy, err := c.GetAffectedPeersByPolicies(resolveCtx, allPolicyIDs)
		resolveCancel()
		// Merge partial results even when err != nil: per-policy continue
		// semantics mean one bad policy must not drop the peers of the
		// good policies.
		for _, affected := range affectedByPolicy {
			peerSlices = append(peerSlices, affected)
		}
		sortedPeerIDs := common.MergePeerIDs(peerSlices...)
		if err != nil {
			// Do not silently succeed with whatever resolved. If no peers
			// resolved, fail fast; otherwise recompile the resolved peers
			// below in deterministic order and then report the partial
			// failure so callers never see silent success with zero fan-out.
			// A legitimate empty-group resolution (nil error, zero peers)
			// skips this branch and succeeds with zero fan-out below.
			if len(sortedPeerIDs) == 0 {
				return fmt.Errorf("get affected peers for recompile: %w", errors.Join(groupErr, err))
			}
			log.ErrorContext(base, "partial failure getting affected peers for recompile", "error", err)
			// Remember the resolution error to return after compiling the
			// resolved peers.
			resolveErr = err
		}
		// Compile in sorted order for deterministic behavior;
		// MergePeerIDs already sorts, matching the fan-out elsewhere.
		for _, peerID := range sortedPeerIDs {
			// Each compile gets its own timeout so a large fan-out cannot
			// expire mid-loop and leave half-recompiled peers.
			compileCtx, compileCancel := context.WithTimeout(base, 10*time.Second)
			_, err := c.CompileAndStore(compileCtx, peerID)
			compileCancel()
			if err != nil {
				compileErr := fmt.Errorf("recompile peer %d: %w", peerID, err)
				if joined := errors.Join(groupErr, resolveErr); joined != nil {
					return errors.Join(joined, compileErr)
				}
				return compileErr
			}
		}
	} else if groupErr != nil {
		// No policies resolved because every group lookup failed: fail
		// instead of reporting success with zero fan-out. A legitimate
		// empty result (no policies reference the groups, nil error)
		// succeeds with zero fan-out below instead of erroring.
		return fmt.Errorf("find policies for recompile: %w", groupErr)
	}
	// Report partial group/policy failures after compiling the resolved peers
	// so callers never see silent success with missing fan-out.
	if joined := errors.Join(groupErr, resolveErr); joined != nil {
		if resolveErr != nil {
			return fmt.Errorf("get affected peers for recompile: %w", joined)
		}
		return fmt.Errorf("find policies for recompile: %w", joined)
	}
	return nil
}

// FindPoliciesByGroup returns IDs of non-deleted policies that reference
// the given group as either source or target. It is the exported single-sourced
// helper for group fan-out; the change worker calls it instead of duplicating
// the predicate so the source/target predicate lives in exactly one place.
func (c *Compiler) FindPoliciesByGroup(ctx context.Context, groupID int) ([]int, error) {
	return c.findPoliciesByGroup(ctx, groupID)
}

// findPoliciesByGroup returns IDs of non-deleted policies that reference
// the given group as either source or target.
//
// Conservative superset: intentionally includes disabled policies, mirroring
// GetAffectedPeersByPolicy (which ignores the enabled flag) and
// store.FindPoliciesUsingService, so disable fan-out still resolves the
// previously-affected peers. Over-marking (an extra pending signal) is safe;
// under-marking would lose the DB pending signal.
//
// Row-scan contract (unified with store.queryRows and queryPeerIDs):
// fail-fast. A single corrupt row aborts the lookup instead of being
// skipped, so one bad row can never silently drop policies from fan-out
// resolution and lose the DB pending signal.
func (c *Compiler) findPoliciesByGroup(ctx context.Context, groupID int) ([]int, error) {
	if c == nil || c.db == nil {
		return nil, fmt.Errorf("find policies by group %d: compiler or db is nil", groupID)
	}
	rows, err := c.db.QueryContext(ctx,
		`SELECT DISTINCT id FROM policies WHERE is_pending_delete = 0 AND ((source_type = 'group' AND source_id = ?) OR (target_type = 'group' AND target_id = ?)) ORDER BY id ASC`, groupID, groupID)
	if err != nil {
		return nil, fmt.Errorf("find affected policies for group %d: %w", groupID, err)
	}
	defer func() {
		if err := rows.Close(); err != nil {
			log.WarnContext(ctx, "failed to close rows", "error", err)
		}
	}()

	var policyIDs []int
	for rows.Next() {
		var id int
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("scan policy id by group %d: %w", groupID, err)
		}
		policyIDs = append(policyIDs, id)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate policies by group: %w", err)
	}
	return policyIDs, nil
}

// collectTransitiveGroupIDs finds all groups that are transitively related to
// the given group through shared peer membership. For example, if groupA and
// groupB both contain peer 42, then changes to groupA also affect groupB.
// This returns the original groupID along with all transitively related groups.
// A non-nil error signals partial traversal failure; the returned IDs are
// still usable but callers must not report silent success with missing fan-out.
func (c *Compiler) collectTransitiveGroupIDs(ctx context.Context, groupID int) ([]int, error) {
	if c == nil || c.db == nil {
		return nil, fmt.Errorf("collect transitive group IDs for group %d: compiler or db is nil", groupID)
	}
	visited := make(map[int]struct{})
	var result []int
	var walkErr error

	var walk func(gid int)
	walk = func(gid int) {
		if _, ok := visited[gid]; ok {
			return
		}
		visited[gid] = struct{}{}
		result = append(result, gid)

		// Find all groups that share at least one peer with this group.
		// ORDER BY keeps the walk deterministic so downstream policy/error
		// order does not depend on SQLite row order.
		rows, err := c.db.QueryContext(ctx, `
			SELECT DISTINCT gm2.group_id
			FROM group_members gm1
			JOIN group_members gm2 ON gm1.peer_id = gm2.peer_id AND gm2.group_id != gm1.group_id
			JOIN groups g ON gm2.group_id = g.id
			WHERE gm1.group_id = ? AND g.is_pending_delete = 0
			ORDER BY gm2.group_id ASC`, gid)
		if err != nil {
			log.ErrorContext(ctx, "failed to find transitive groups", "group_id", gid, "error", err)
			walkErr = errors.Join(walkErr, fmt.Errorf("transitive groups for group %d: %w", gid, err))
			return
		}
		// Collect related IDs first, then close the cursor before recursing.
		// The cursor must not stay open across walk(relatedGID): each
		// recursion level would otherwise hold its SQLite cursor/lock until
		// the full unwind, stacking N open cursors on a transitive chain.
		var related []int
		for rows.Next() {
			var relatedGID int
			if err := rows.Scan(&relatedGID); err != nil {
				log.WarnContext(ctx, "failed to scan related group", "error", err)
				walkErr = errors.Join(walkErr, fmt.Errorf("transitive groups scan for group %d: %w", gid, err))
				continue
			}
			related = append(related, relatedGID)
		}
		if err := rows.Err(); err != nil {
			log.ErrorContext(ctx, "rows iteration error", "group_id", gid, "error", err)
			walkErr = errors.Join(walkErr, fmt.Errorf("transitive groups iteration for group %d: %w", gid, err))
		}
		if cerr := rows.Close(); cerr != nil {
			log.WarnContext(ctx, "failed to close rows", "error", cerr)
		}
		for _, relatedGID := range related {
			walk(relatedGID)
		}
	}

	walk(groupID)
	return result, walkErr
}

// peerExists reports whether a peer row exists. sql.ErrNoRows from the scan
// maps to (false, nil); other DB errors are returned.
func (c *Compiler) peerExists(ctx context.Context, peerID int) (bool, error) {
	if c == nil || c.db == nil {
		return false, fmt.Errorf("verify peer %d: compiler or db is nil", peerID)
	}
	var id int
	if err := c.db.QueryRowContext(ctx, "SELECT id FROM peers WHERE id = ?", peerID).Scan(&id); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil
		}
		return false, fmt.Errorf("verify peer %d: %w", peerID, err)
	}
	return true, nil
}

// groupExists reports whether a non-deleted group row exists. sql.ErrNoRows
// from the scan maps to (false, nil); other DB errors are returned. Mirrors
// peerExists so a missing or soft-deleted group surfaces as sql.ErrNoRows
// instead of silent success with zero fan-out.
func (c *Compiler) groupExists(ctx context.Context, groupID int) (bool, error) {
	if c == nil || c.db == nil {
		return false, fmt.Errorf("verify group %d: compiler or db is nil", groupID)
	}
	var id int
	if err := c.db.QueryRowContext(ctx, "SELECT id FROM groups WHERE id = ? AND is_pending_delete = 0", groupID).Scan(&id); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil
		}
		return false, fmt.Errorf("verify group %d: %w", groupID, err)
	}
	return true, nil
}

// queryPeerIDs runs a peer-ID SELECT and returns the scanned IDs. It
// centralizes the Query/scan/rows.Err/Close handling (defer Close) so the
// group-member and all-peers lookups share one implementation instead of
// hand-rolling cursors.
//
// Row-scan contract (unified with store.queryRows): fail-fast. A single
// corrupt row aborts the whole lookup with an error instead of being
// skipped, so one bad row can never silently drop peers from fan-out
// resolution and lose the DB pending signal.
func (c *Compiler) queryPeerIDs(ctx context.Context, errLabel string, query string, args ...any) ([]int, error) {
	if c == nil || c.db == nil {
		return nil, fmt.Errorf("%s: compiler or db is nil", errLabel)
	}
	rows, err := c.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", errLabel, err)
	}
	defer func() {
		if err := rows.Close(); err != nil {
			log.WarnContext(ctx, "failed to close rows", "error", err)
		}
	}()
	var ids []int
	for rows.Next() {
		var id int
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("%s: scan peer id: %w", errLabel, err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("%s: %w", errLabel, err)
	}
	return ids, nil
}

// groupMemberPeers returns the IDs of peers that are members of the given
// non-deleted group. It is the single shared helper for the source-group and
// target-group member lookups in GetAffectedPeersByPolicy so the SELECT,
// scan, and rows.Err/Close handling live in exactly one place.
func (c *Compiler) groupMemberPeers(ctx context.Context, groupID int) ([]int, error) {
	if c == nil || c.db == nil {
		return nil, fmt.Errorf("query group %d members: compiler or db is nil", groupID)
	}
	// JOIN peers so orphan group_members rows for deleted peers never yield
	// dead IDs that would fail the downstream INSERT pending_changes FK
	// after the handler already reported success. Direct peer refs are
	// verified via peerExists; expanded members are verified here.
	peers, err := c.queryPeerIDs(ctx, fmt.Sprintf("query group %d members", groupID), `
		SELECT DISTINCT gm.peer_id
		FROM group_members gm
		JOIN groups g ON gm.group_id = g.id
		JOIN peers p ON p.id = gm.peer_id
		WHERE gm.group_id = ? AND g.is_pending_delete = 0
	`, groupID)
	if err != nil {
		return nil, err
	}
	return peers, nil
}

// GetAffectedPeersByPolicy returns peer IDs affected by a policy. It finds any peer present in either the source or target of the policy.
//
// Documented architecture decision: this function is intentionally a
// conservative superset of loadApplicablePolicies, not an exact mirror.
// Over-marking (an extra pending signal) is safe; under-marking would lose
// the DB pending signal. The compiler remains the source of truth for rule
// applicability; this function only determines which peers need a pending
// signal. The two intentional divergences are:
//   - enabled flag: ignored here even though loadApplicablePolicies filters
//     on enabled=1. Disabling a policy is itself a change that must fan out
//     to the previously-affected peers, and the post-update resolution for a
//     disable would find zero peers if it mirrored the enabled filter.
//   - specials: conservative over-mark relative to loadApplicablePolicies
//     (see below).
func (c *Compiler) GetAffectedPeersByPolicy(ctx context.Context, policyID int) ([]int, error) {
	if c == nil || c.db == nil {
		return nil, fmt.Errorf("get affected peers for policy %d: compiler or db is nil", policyID)
	}
	var srcType, tgtType string
	var srcID, tgtID int
	if err := c.db.QueryRowContext(ctx, "SELECT source_type, source_id, target_type, target_id FROM policies WHERE id = ? AND is_pending_delete = 0", policyID).Scan(&srcType, &srcID, &tgtType, &tgtID); err != nil {
		return nil, fmt.Errorf("get policy abstract: %w", err)
	}

	// Peer dedup uses the shared common.MergePeerIDs helper (leaf
	// internal/common, no cycle) so the engine and the change worker share
	// one map-dedup+sort implementation.
	var idSlices [][]int

	// Process source - handle peer, group, and special types
	// Note: Even if source is special, we still check target for peer/group
	switch srcType {
	case "peer":
		// Verify the peer exists synchronously. Blindly marking a
		// deleted/invalid peer would return success here and fail later on
		// the async INSERT FK, after the handler already responded.
		exists, err := c.peerExists(ctx, srcID)
		if err != nil {
			return nil, fmt.Errorf("verify source peer for policy %d: %w", policyID, err)
		}
		if !exists {
			return nil, fmt.Errorf("source peer %d for policy %d: %w", srcID, policyID, sql.ErrNoRows)
		}
		idSlices = append(idSlices, []int{srcID})
	case "group":
		// Verify the group exists synchronously, mirroring the peer path.
		// A missing or soft-deleted group must surface sql.ErrNoRows
		// instead of succeeding with zero fan-out.
		exists, err := c.groupExists(ctx, srcID)
		if err != nil {
			return nil, fmt.Errorf("verify source group for policy %d: %w", policyID, err)
		}
		if !exists {
			return nil, fmt.Errorf("source group %d for policy %d: %w", srcID, policyID, sql.ErrNoRows)
		}
		members, err := c.groupMemberPeers(ctx, srcID)
		if err != nil {
			return nil, fmt.Errorf("source group members for policy %d: %w", policyID, err)
		}
		idSlices = append(idSlices, members)
	}

	// Process target - handle peer, group, and special types
	// Note: Even if target is special, we still check source for peer/group
	switch tgtType {
	case "peer":
		// Verify the peer exists synchronously (see the source case above:
		// an unverified ID fails the async INSERT FK after success).
		exists, err := c.peerExists(ctx, tgtID)
		if err != nil {
			return nil, fmt.Errorf("verify target peer for policy %d: %w", policyID, err)
		}
		if !exists {
			return nil, fmt.Errorf("target peer %d for policy %d: %w", tgtID, policyID, sql.ErrNoRows)
		}
		idSlices = append(idSlices, []int{tgtID})
	case "group":
		// Verify the group exists synchronously (see the source case above:
		// an unverified ID would succeed here with zero fan-out).
		exists, err := c.groupExists(ctx, tgtID)
		if err != nil {
			return nil, fmt.Errorf("verify target group for policy %d: %w", policyID, err)
		}
		if !exists {
			return nil, fmt.Errorf("target group %d for policy %d: %w", tgtID, policyID, sql.ErrNoRows)
		}
		members, err := c.groupMemberPeers(ctx, tgtID)
		if err != nil {
			return nil, fmt.Errorf("target group members for policy %d: %w", policyID, err)
		}
		idSlices = append(idSlices, members)
	}

	// Special-target handling is intentionally conservative (over-marks) relative
	// to loadApplicablePolicies, per the architecture decision documented on
	// GetAffectedPeersByPolicy (conservative superset, not exact mirror).
	// That loader excludes source specials
	// SubnetBroadcast, LimitedBroadcast, AllHosts, mDNS, IGMPv3 from
	// source-side applicability only (IsSource=0 via NOT IN), while the same
	// peer still matches as a target (IsTarget=1) and still gets ingress rules
	// via the broadcast/multicast paths in writeTargetSection. Fanning out to
	// the opposite-side group/peer members is therefore required even for
	// those excluded source specials (e.g. source __subnet_broadcast__ with a
	// group target must still signal the group members). Over-marking is safe
	// (an extra pending signal); under-marking would lose the DB pending
	// signal. This documents the conservative choice instead of claiming an
	// exact mirror.
	// - SpecialIDAllPeers on either side fans out to all non-deleted peers.
	//   Peers have no soft-delete flag, so every row in peers is non-deleted;
	//   this mirrors Resolver.ResolveSpecialTarget for __all_peers__ which
	//   selects all peer IPs without filtering.
	// - SpecialIDAnyIP / SpecialIDInternet as source affect only the opposite
	//   side peer(s) (no fan-out here; the opposite side was already added).
	// - Other specials as target with group/peer source affect the source
	//   side (already covered above).
	if (srcType == "special" && srcID == resolve.SpecialIDAllPeers) ||
		(tgtType == "special" && tgtID == resolve.SpecialIDAllPeers) {
		// ORDER BY id keeps the fan-out deterministic before the final
		// sort; every row in peers (including manual peers, which have no
		// soft-delete flag) is intentionally included, mirroring
		// Resolver.ResolveSpecialTarget for __all_peers__.
		allPeers, err := c.queryPeerIDs(ctx, fmt.Sprintf("query all peers for policy %d", policyID), `SELECT id FROM peers ORDER BY id`)
		if err != nil {
			return nil, fmt.Errorf("query all peers for policy %d: %w", policyID, err)
		}
		idSlices = append(idSlices, allPeers)
	}

	return common.MergePeerIDs(idSlices...), nil
}

// GetAffectedPeersByPolicies returns a map of policyID -> affected peer IDs for
// each input policy. It is a thin batched wrapper over GetAffectedPeersByPolicy.
//
// TODO(engine-batched-fanout): this still issues one SQL query set per policy
// (N+1: one GetAffectedPeersByPolicy per policy ID), so a group touching P
// policies costs P sequential policy resolutions plus the merge step.
// The wrapper centralizes error handling and the return shape so call sites
// stay stable, but the real fix is a single batched query with
// "WHERE policies.id IN (...)" that loads all policy rows at once and then
// resolves group members / peer targets in bulk. Benchmark before/after with
// a group fanning out to 50+ policies (measure wall time and query count via
// test DB query logging); the batched form should issue O(1) policy-row
// queries instead of O(P).
//
// Error semantics are per-policy continue: one bad policy does not drop the
// peers of the other policies. Successfully resolved policies are returned
// in the map alongside an aggregated error (via errors.Join) covering the
// failed policies. Callers must merge the partial map even when err != nil.
func (c *Compiler) GetAffectedPeersByPolicies(ctx context.Context, policyIDs []int) (map[int][]int, error) {
	// Dedup inputs so duplicate policy IDs do not cause duplicate SQL
	// queries (mirrors RecompilePeersForGroup's policySeen dedup).
	seen := make(map[int]struct{}, len(policyIDs))
	uniqueIDs := make([]int, 0, len(policyIDs))
	for _, pid := range policyIDs {
		if _, ok := seen[pid]; !ok {
			seen[pid] = struct{}{}
			uniqueIDs = append(uniqueIDs, pid)
		}
	}
	result := make(map[int][]int, len(uniqueIDs))
	var errs []error
	for _, pid := range uniqueIDs {
		peers, err := c.GetAffectedPeersByPolicy(ctx, pid)
		if err != nil {
			errs = append(errs, fmt.Errorf("policy %d: %w", pid, err))
			continue
		}
		result[pid] = peers
	}
	return result, errors.Join(errs...)
}

// invertPortMatch swaps destination port flags with source port flags.
// Example: dstMatch="--dport 80", srcMatch="--sport 5353" -> "--sport 80 --dport 5353"
// The plural forms (--dports/--sports) are replaced BEFORE singular forms (--dport/--sport)
// to avoid substring collisions (e.g. "--dport" is a substring of "--dports").
func invertPortMatch(dstMatch, srcMatch string) string {
	var result string

	if dstMatch != "" {
		result = strings.ReplaceAll(dstMatch, "--dports", "--sports")
		result = strings.ReplaceAll(result, "--dport", "--sport")
	}

	if srcMatch != "" {
		srcToDst := strings.ReplaceAll(srcMatch, "--sports", "--dports")
		srcToDst = strings.ReplaceAll(srcToDst, "--sport", "--dport")
		if result != "" {
			result = result + " " + srcToDst
		} else {
			result = srcToDst
		}
	}

	return result
}
