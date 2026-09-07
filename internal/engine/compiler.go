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

// ruleDir discriminates the four rule-generation paths inside writeRules.
const (
	ruleDirTarget   = "target"
	ruleDirSource   = "source"
	ruleDirInternet = "internet"
)

// Ipset name conventions.
const (
	ipsetPrivateRanges = "runic_private_ranges"
	ipsetGroupPrefix   = "runic_group_"
)

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

// --- Compiler Sub-routines ---

func (c *Compiler) loadPeerData(ctx context.Context, peerID int) (hostname string, ipAddress string, hasDocker bool, hasIPSet bool, err error) {
	err = c.db.QueryRowContext(ctx,
		"SELECT hostname, ip_address, has_docker, COALESCE(has_ipset, 0) FROM peers WHERE id = ?", peerID,
	).Scan(&hostname, &ipAddress, &hasDocker, &hasIPSet)
	if err != nil {
		err = fmt.Errorf("load peer %d: %w", peerID, err)
	}
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
			log.Warn("close err", "err", err)
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
	serviceIDs := make(map[int]bool)
	for i := range policies {
		p := &policies[i]
		serviceIDs[p.ServiceID] = true
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
				log.Warn("close err", "err", err)
			}
		}()

		for rows.Next() {
			var sid int
			var s ServiceInfo
			if err := rows.Scan(&sid, &s.Name, &s.Ports, &s.SourcePorts, &s.Protocol, &s.NoConntrack); err != nil {
				return nil, fmt.Errorf("scan service: %w", err)
			}
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
	SetType string // hash:ip or hash:net
	Members []string
}

func (c *Compiler) resolveIPSetDefinitions(ctx context.Context, hasIPSet bool, groupOrder []int, groupIDToName map[int]string) ([]ipsetData, map[int]string, error) {
	var ipsets []ipsetData
	groupIDToIpsetName := make(map[int]string)
	if hasIPSet && len(groupOrder) > 0 {
		for _, gid := range groupOrder {
			members, hasCIDR, err := c.resolver.resolveGroupForIpset(ctx, gid)
			if err != nil {
				return nil, nil, fmt.Errorf("resolve group %d for ipset: %w", gid, err)
			}
			setType := "hash:ip"
			if hasCIDR {
				setType = "hash:net"
			}
			sanitizedName := ipsetGroupPrefix + sanitizeForIpset(groupIDToName[gid])
			if err := ValidateIPSetName(sanitizedName); err != nil {
				return nil, nil, fmt.Errorf("group %d (%q): %w", gid, groupIDToName[gid], err)
			}
			var addrs []string
			for _, m := range members {
				addrs = append(addrs, m.Address)
			}
			ipsets = append(ipsets, ipsetData{
				Name:    sanitizedName,
				SetType: setType,
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
		log.WarnContext(ctx, "Failed to load control_plane_port, using default "+DefaultControlPlanePort, "error", err)
		controlPlanePort = DefaultControlPlanePort
	}
	if controlPlanePort == "" {
		controlPlanePort = DefaultControlPlanePort
	}

	return c.generateIptablesPayload(ctx, hostname, ipAddress, hasDocker, hasIPSet, policies, services, ipsets, groupIDToIpsetName, controlPlanePort)
}

func (c *Compiler) generateIptablesPayload(
	ctx context.Context,
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
	c.writeIpsetDefinitions(&buf, hasIPSet, ipsets)
	c.writeFilterTableHeader(&buf, hasDocker)
	rw.writeStandardRules(hasDocker, controlPlanePort)

	if err := c.writePolicySection(ctx, &buf, rw, policies, services, groupIDToIpsetName, hasDocker, hasIPSet, ipAddress); err != nil {
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

// writeIpsetDefinitions writes ipset create/add definitions (before *filter).
func (c *Compiler) writeIpsetDefinitions(buf *strings.Builder, hasIPSet bool, ipsets []ipsetData) {
	if hasIPSet && len(ipsets) > 0 {
		buf.WriteString("\n# --- Ipset Definitions ---\n")
		for _, is := range ipsets {
			fmt.Fprintf(buf, "create %s %s family inet\n", is.Name, is.SetType)
			for _, member := range is.Members {
				fmt.Fprintf(buf, "add %s %s\n", is.Name, member)
			}
			buf.WriteString("\n")
		}
	}

	privateCIDRs := []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8"}
	if hasIPSet {
		buf.WriteString("# --- Ipset: Private Ranges for __internet__ exclusion ---\n")
		buf.WriteString("create runic_private_ranges hash:net family inet\n")
		for _, cidr := range privateCIDRs {
			fmt.Fprintf(buf, "add runic_private_ranges %s\n", cidr)
		}
		buf.WriteString("\n")
	}
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
	policies []policyInfo,
	services map[int]ServiceInfo,
	groupIDToIpsetName map[int]string,
	hasDocker bool,
	hasIPSet bool,
	ipAddress string,
) error {
	for i := range policies {
		if err := c.writeSinglePolicy(ctx, buf, rw, &policies[i], services, groupIDToIpsetName, hasDocker, hasIPSet, ipAddress); err != nil {
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
	pol *policyInfo,
	services map[int]ServiceInfo,
	groupIDToIpsetName map[int]string,
	hasDocker bool,
	hasIPSet bool,
	ipAddress string,
) error {
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
	if err := c.writeSourceSection(ctx, buf, rw, pol, portClauses, serviceName, groupIDToIpsetName, hasDocker, hasIPSet, ipAddress, writeToHost, writeToDocker, noConntrack); err != nil {
		return err
	}

	buf.WriteString("\n")
	return nil
}

// resolveEntityCIDRs looks up the CIDRs that represent the given entity (peer, group, or
// special target). It centralizes the special-case fallbacks for peer-with-IP and bare
// special targets. entityType and entityID identify the entity; the optional overrideIP is
// used for policies that pin a specific source or target IP (e.g., manual peer IPs).
func (c *Compiler) resolveEntityCIDRs(ctx context.Context, entityType string, entityID int, overrideIP string, ipAddress string) ([]string, error) {
	switch {
	case entityType == "special":
		return c.resolver.ResolveSpecialTarget(ctx, entityID, ipAddress)
	case entityType == "peer" && overrideIP != "":
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
			rules, err := c.writeRules(pol, portClauses, true, ipsetName, nil, ipAddress, writeToHost, writeToDocker, noConntrack, "target", false)
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
			rules, err := c.writeRules(pol, portClauses, false, "", cidrs, ipAddress, writeToHost, writeToDocker, noConntrack, "target", false)
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

	targetName := c.formatEntityName(ctx, pol.TargetType, pol.TargetID)
	fmt.Fprintf(buf, "# As Source (Egress to %s)\n", targetName)

	isInternetTarget := pol.TargetType == "special" && pol.TargetID == resolve.SpecialIDInternet
	useInternetIpset := hasIPSet && isInternetTarget

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
			rules, err := c.writeRules(pol, portClauses, true, ipsetName, nil, ipAddress, writeToHost, writeToDocker, noConntrack, "source", isMulticastTarget)
			if err != nil {
				return err
			}
			for _, rule := range rules {
				buf.WriteString(rule + "\n")
			}
		}
	case useInternetIpset:
		isMulticastTarget := false
		rules, err := c.writeRules(pol, portClauses, false, "", nil, ipAddress, writeToHost, writeToDocker, noConntrack, "internet", isMulticastTarget)
		if err != nil {
			return err
		}
		for _, rule := range rules {
			buf.WriteString(rule + "\n")
		}
	default:
		cidrs, err := c.resolveEntityCIDRs(ctx, pol.TargetType, pol.TargetID, pol.TargetIP, ipAddress)
		if err != nil {
			return fmt.Errorf("resolve target for policy %s: %w", pol.Name, err)
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
			rules, err := c.writeRules(pol, portClauses, false, "", cidrs, ipAddress, writeToHost, writeToDocker, noConntrack, "source", isMulticastTarget)
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
//	"internet" — same as "source" but uses runic_private_ranges ipset negation
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
	ruleDir string,
	isMulticastTarget bool,
) ([]string, error) {
	if pol.Action == ActionAccept {
		return c.buildAcceptRules(pol, portClauses, useIpset, ipsetName, cidrs, ipAddress, writeToHost, writeToDocker, noConntrack, ruleDir, isMulticastTarget)
	}
	return c.buildLogDropRules(pol, portClauses, useIpset, ipsetName, cidrs, ipAddress, writeToHost, writeToDocker, ruleDir)
}

// buildAcceptRules emits the iptables ACCEPT rules for a single policy's port clauses.
// It handles both the ipset and CIDR paths and the host/docker scopes. It also
// emits the INPUT return-traffic rules for the "source" and "internet" directions.
func (c *Compiler) buildAcceptRules(
	pol *policyInfo,
	portClauses []PortClause,
	useIpset bool,
	ipsetName string,
	cidrs []string,
	ipAddress string,
	writeToHost, writeToDocker bool,
	noConntrack bool,
	ruleDir string,
	isMulticastTarget bool,
) ([]string, error) {
	var rules []string
	privateIpsetMatch := privateIpsetDstMatch()

	for _, pc := range portClauses {
		// Build port matches depending on direction
		var primaryPortMatch, returnPortMatch string
		primaryPortMatch = pc.PortMatch
		if pc.SrcPortMatch != "" {
			primaryPortMatch = pc.SrcPortMatch + " " + primaryPortMatch
		}
		returnPortMatch = invertPortMatch(pc.PortMatch, pc.SrcPortMatch)

		// Build conntrack part based on noConntrack flag
		conntrackFull := "-m conntrack --ctstate NEW,ESTABLISHED"
		if noConntrack {
			conntrackFull = ""
		}

		// For "source" direction, determine return CIDRs with multicast adjustments
		var returnCIDRs []string
		if ruleDir == ruleDirSource || ruleDir == ruleDirInternet {
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
				case ruleDirInternet:
					rules = append(rules,
						fmt.Sprintf("-A OUTPUT -p %s %s %s %s -j %s", pc.Protocol, privateIpsetMatch, primaryPortMatch, conntrackFull, pol.Action),
						fmt.Sprintf("-A INPUT -p %s %s %s %s -j ACCEPT", pc.Protocol, privateIpsetSrcMatch(), returnPortMatch, conntrackFull),
					)
				}
			}
			if writeToDocker {
				switch ruleDir {
				case ruleDirTarget:
					rules = append(rules, fmt.Sprintf("-A DOCKER-USER -p %s %s %s %s -j %s", pc.Protocol, ipsetMatchPrimary, primaryPortMatch, conntrackFull, pol.Action))
				case ruleDirSource:
					rules = append(rules, fmt.Sprintf("-A DOCKER-USER -p %s %s %s %s -j %s", pc.Protocol, ipsetMatchPrimary, primaryPortMatch, conntrackFull, pol.Action))
				case ruleDirInternet:
					rules = append(rules, fmt.Sprintf("-A DOCKER-USER -p %s %s %s %s -j %s", pc.Protocol, privateIpsetMatch, primaryPortMatch, conntrackFull, pol.Action))
				}
			}
		} else {
			// Filter out self-referencing CIDRs (peer connecting to itself).
			// A CIDR is self-referencing if it exactly matches the peer's own
			// IP address (normalized to CIDR notation). For example, peer with
			// IP "10.0.0.1" has CIDR "10.0.0.1/32", so a source CIDR of
			// "10.0.0.1/32" is self-referencing. A CIDR range like "10.0.0.0/24"
			// is NOT self-referencing even if it contains the peer's IP.
			filteredCidrs := filterSelfReferencingCIDRs(cidrs, ipAddress)

			for _, cidr := range filteredCidrs {
				if writeToHost {
					switch ruleDir {
					case ruleDirTarget:
						rules = append(rules,
							fmt.Sprintf("-A INPUT -s %s -p %s %s %s -j %s", cidr, pc.Protocol, primaryPortMatch, conntrackFull, pol.Action),
							fmt.Sprintf("-A OUTPUT -d %s -p %s %s %s -j ACCEPT", cidr, pc.Protocol, returnPortMatch, conntrackFull),
						)
					case ruleDirSource, ruleDirInternet:
						rules = append(rules, fmt.Sprintf("-A OUTPUT -d %s -p %s %s %s -j %s", cidr, pc.Protocol, primaryPortMatch, conntrackFull, pol.Action))
					}
				}
				if writeToDocker {
					switch ruleDir {
					case ruleDirTarget:
						rules = append(rules, fmt.Sprintf("-A DOCKER-USER -s %s -p %s %s %s -j %s", cidr, pc.Protocol, primaryPortMatch, conntrackFull, pol.Action))
					case ruleDirSource, ruleDirInternet:
						rules = append(rules, fmt.Sprintf("-A DOCKER-USER -d %s -p %s %s %s -j %s", cidr, pc.Protocol, primaryPortMatch, conntrackFull, pol.Action))
					}
				}
			}

			// Generate INPUT return rules for source/internet direction
			if ruleDir == ruleDirSource || ruleDir == ruleDirInternet {
				filteredReturnCidrs := filterSelfReferencingCIDRs(returnCIDRs, ipAddress)
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
func (c *Compiler) buildLogDropRules(
	pol *policyInfo,
	portClauses []PortClause,
	useIpset bool,
	ipsetName string,
	cidrs []string,
	ipAddress string,
	writeToHost, writeToDocker bool,
	ruleDir string,
) ([]string, error) {
	var rules []string
	privateIpsetMatch := privateIpsetDstMatch()

	for _, pc := range portClauses {
		if useIpset {
			ipsetMatchPrimary := fmt.Sprintf("-m set --match-set %s src", ipsetName)
			if ruleDir == ruleDirSource {
				// For source direction, the primary match is on dst (return traffic).
				ipsetMatchPrimary = fmt.Sprintf("-m set --match-set %s dst", ipsetName)
			}

			if writeToHost {
				chain := ChainInput
				if ruleDir == ruleDirSource || ruleDir == ruleDirInternet {
					chain = ChainOutput
				}
				match := fmt.Sprintf("-p %s %s %s", pc.Protocol, ipsetMatchPrimary, pc.PortMatch)
				if ruleDir == ruleDirInternet {
					match = fmt.Sprintf("-p %s %s %s", pc.Protocol, privateIpsetMatch, pc.PortMatch)
				}
				rules = append(rules, c.logDropRule(pol.Action, chain, match)...)
			}
			if writeToDocker {
				match := fmt.Sprintf("-p %s %s %s", pc.Protocol, ipsetMatchPrimary, pc.PortMatch)
				if ruleDir == ruleDirInternet {
					match = fmt.Sprintf("-p %s %s %s", pc.Protocol, privateIpsetMatch, pc.PortMatch)
				}
				rules = append(rules, c.logDropRule(pol.Action, ChainDockerUser, match)...)
			}
		} else {
			filteredCidrs := filterSelfReferencingCIDRs(cidrs, ipAddress)
			for _, cidr := range filteredCidrs {
				if writeToHost {
					switch ruleDir {
					case ruleDirTarget:
						rules = append(rules, c.logDropRule(pol.Action, ChainInput, fmt.Sprintf("-s %s -p %s %s", cidr, pc.Protocol, pc.PortMatch))...)
					case ruleDirSource, ruleDirInternet:
						rules = append(rules, c.logDropRule(pol.Action, ChainOutput, fmt.Sprintf("-d %s -p %s %s", cidr, pc.Protocol, pc.PortMatch))...)
					}
				}
				if writeToDocker {
					switch ruleDir {
					case ruleDirTarget:
						rules = append(rules, c.logDropRule(pol.Action, ChainDockerUser, fmt.Sprintf("-s %s -p %s %s", cidr, pc.Protocol, pc.PortMatch))...)
					case ruleDirSource, ruleDirInternet:
						rules = append(rules, c.logDropRule(pol.Action, ChainDockerUser, fmt.Sprintf("-d %s -p %s %s", cidr, pc.Protocol, pc.PortMatch))...)
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

// filterSelfReferencingCIDRs returns cidrs with any entries equal to the peer's
// own normalized CIDR (e.g., "10.0.0.1/32") removed. Peer-to-self traffic is
// not relevant for firewall rules and would otherwise generate matching rules
// that block loopback-shaped connections.
func filterSelfReferencingCIDRs(cidrs []string, ipAddress string) []string {
	peerCIDR := resolve.NormalizeToCIDR(ipAddress)
	filtered := make([]string, 0, len(cidrs))
	for _, cidr := range cidrs {
		if cidr != peerCIDR {
			filtered = append(filtered, cidr)
		}
	}
	return filtered
}

// previewState aggregates the inputs and resolved CIDRs that PreviewCompile needs
// to render the four (host/docker × forward/backward) rule sections. Keeping these
// fields on a struct lets the per-section helpers take a single parameter rather
// than a long argument list, and avoids accidental divergence between the four
// sections that share most of their inputs.
type previewState struct {
	// Resolved inputs
	ipAddress        string
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
		if err := c.db.QueryRowContext(ctx,
			"SELECT ip_address FROM peers WHERE id = ?", peerID,
		).Scan(&st.ipAddress); err != nil && !errors.Is(err, sql.ErrNoRows) {
			// Log but don't fail - IP is optional for preview
			log.WarnContext(ctx, "Failed to load peer IP for preview", "error", err)
		}
	}

	// Load service - MC-011: Include no_conntrack column
	var ports, sourcePorts string
	err := c.db.QueryRowContext(ctx,
		"SELECT name, ports, source_ports, protocol, COALESCE(no_conntrack, 0) FROM services WHERE id = ? AND is_pending_delete = 0", serviceID,
	).Scan(&st.serviceName, &ports, &sourcePorts, &st.protocol, &st.noConntrack)
	if errors.Is(err, sql.ErrNoRows) {
		return previewState{}, fmt.Errorf("service %d is pending delete or does not exist", serviceID)
	}
	if err != nil {
		return previewState{}, fmt.Errorf("load service: %w", err)
	}

	// Skip port expansion for special services that don't use ports.
	isIGMPorVRRP := strings.EqualFold(st.serviceName, systemServiceIGMP) || strings.EqualFold(st.serviceName, systemServiceVRRP)
	if !strings.EqualFold(st.serviceName, systemServiceMulticast) && !isIGMPorVRRP {
		clauses, err := ExpandPorts(ports, sourcePorts, st.protocol)
		if err != nil {
			return previewState{}, fmt.Errorf("expand ports: %w", err)
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
// chains so host and docker preview sections share one call path.
func (c *Compiler) previewAppendRules(rules []string, st *previewState, pol *policyInfo, portClauses []PortClause, cidrs []string, isMulticastTarget bool, ruleDir string, writeToHost, writeToDocker bool) ([]string, error) {
	generated, err := c.writeRules(pol, portClauses, false, "", cidrs, st.ipAddress, writeToHost, writeToDocker, st.noConntrack, ruleDir, isMulticastTarget)
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
func (c *Compiler) previewHostForward(st *previewState, sourceType string, targetType string, targetID int) ([]string, error) {
	return c.previewForward(st, targetType, targetID, ChainInput, "# Forward (Source → Target)", true, false, "host")
}

// previewDockerForward is the DOCKER-USER equivalent of previewHostForward.
func (c *Compiler) previewDockerForward(st *previewState, sourceType string, targetType string, targetID int) ([]string, error) {
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

	// Use writeSourceRules for forward direction (egress)
	if st.isInternetTarget {
		return c.previewAppendRules(rules, st, st.pol, st.portClauses, nil, false, ruleDirInternet, writeToHost, writeToDocker)
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
		func() ([]string, error) { return c.previewHostForward(&st, sourceType, targetType, targetID) },
		func() ([]string, error) { return c.previewHostBackward(&st, sourceType, sourceID) },
		func() ([]string, error) { return c.previewDockerForward(&st, sourceType, targetType, targetID) },
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
	// Collect all transitively related groups. When a peer is added to a group,
	// it also affects any other group that shares peers with this group (transitive
	// membership via overlapping group membership). We find all groups that share
	// at least one peer with the given group, then recompile all affected peers
	// for the entire set of related groups.
	allGroupIDs := c.collectTransitiveGroupIDs(ctx, groupID)

	// Collect all affected peer IDs from policies referencing any related group.
	peerSet := make(map[int]bool)
	for _, gid := range allGroupIDs {
		policyIDs, err := c.findPoliciesByGroup(ctx, gid)
		if err != nil {
			return err
		}

		for _, pid := range policyIDs {
			affected, err := c.GetAffectedPeersByPolicy(ctx, pid)
			if err != nil {
				log.ErrorContext(ctx, "Failed to get affected peers for recompile", "policy_id", pid, "error", err)
				continue
			}
			for _, peerID := range affected {
				peerSet[peerID] = true
			}
		}
	}

	for peerID := range peerSet {
		if _, err := c.CompileAndStore(ctx, peerID); err != nil {
			return fmt.Errorf("recompile peer %d: %w", peerID, err)
		}
	}
	return nil
}

// findPoliciesByGroup returns IDs of enabled, non-deleted policies that reference
// the given group as either source or target.
func (c *Compiler) findPoliciesByGroup(ctx context.Context, groupID int) ([]int, error) {
	rows, err := c.db.QueryContext(ctx,
		`SELECT DISTINCT id FROM policies WHERE is_pending_delete = 0 AND ((source_type = 'group' AND source_id = ?) OR (target_type = 'group' AND target_id = ?)) AND enabled = 1`, groupID, groupID)
	if err != nil {
		return nil, fmt.Errorf("find affected policies for group %d: %w", groupID, err)
	}
	defer func() {
		if err := rows.Close(); err != nil {
			log.Warn("close err", "err", err)
		}
	}()

	var policyIDs []int
	for rows.Next() {
		var id int
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("scan policy id: %w", err)
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
func (c *Compiler) collectTransitiveGroupIDs(ctx context.Context, groupID int) []int {
	visited := make(map[int]bool)
	var result []int

	var walk func(gid int)
	walk = func(gid int) {
		if visited[gid] {
			return
		}
		visited[gid] = true
		result = append(result, gid)

		// Find all groups that share at least one peer with this group.
		rows, err := c.db.QueryContext(ctx, `
			SELECT DISTINCT gm2.group_id
			FROM group_members gm1
			JOIN group_members gm2 ON gm1.peer_id = gm2.peer_id AND gm2.group_id != gm1.group_id
			JOIN groups g ON gm2.group_id = g.id
			WHERE gm1.group_id = ? AND g.is_pending_delete = 0`, gid)
		if err != nil {
			log.WarnContext(ctx, "Failed to find transitive groups", "group_id", gid, "error", err)
			return
		}
		defer func() {
			if cErr := rows.Close(); cErr != nil {
				log.Warn("close err", "err", cErr)
			}
		}()

		for rows.Next() {
			var relatedGID int
			if err := rows.Scan(&relatedGID); err != nil {
				log.WarnContext(ctx, "Failed to scan related group", "error", err)
				continue
			}
			walk(relatedGID)
		}
		if err := rows.Err(); err != nil {
			log.WarnContext(ctx, "Rows iteration error", "error", err)
		}
	}

	walk(groupID)
	return result
}

// GetAffectedPeersByPolicy returns peer IDs affected by a policy. It finds any peer present in either the source or target of the policy.
func (c *Compiler) GetAffectedPeersByPolicy(ctx context.Context, policyID int) ([]int, error) {
	var srcType, tgtType string
	var srcID, tgtID int
	if err := c.db.QueryRowContext(ctx, "SELECT source_type, source_id, target_type, target_id FROM policies WHERE id = ? AND is_pending_delete = 0", policyID).Scan(&srcType, &srcID, &tgtType, &tgtID); err != nil {
		return nil, fmt.Errorf("get policy abstract: %w", err)
	}

	peers := make(map[int]bool)

	// Process source - handle peer, group, and special types
	// Note: Even if source is special, we still check target for peer/group
	switch srcType {
	case "peer":
		peers[srcID] = true
	case "group":
		rows, err := c.db.QueryContext(ctx, `
			SELECT DISTINCT gm.peer_id
			FROM group_members gm
			JOIN groups g ON gm.group_id = g.id
			WHERE gm.group_id = ? AND g.is_pending_delete = 0
		`, srcID)
		if err != nil {
			return nil, fmt.Errorf("query source group members for policy %d: %w", policyID, err)
		}
		defer func() {
			if err := rows.Close(); err != nil {
				log.Warn("close err", "err", err)
			}
		}()
		for rows.Next() {
			var p int
			if err := rows.Scan(&p); err != nil {
				log.WarnContext(ctx, "Failed to scan peer from group", "error", err)
				continue
			}
			peers[p] = true
		}
		if err := rows.Err(); err != nil {
			log.ErrorContext(ctx, "rows iteration error in GetAffectedPeersByPolicy (source group)", "policy_id", policyID, "error", err)
		}
	}

	// Process target - handle peer, group, and special types
	// Note: Even if target is special, we still check source for peer/group
	switch tgtType {
	case "peer":
		peers[tgtID] = true
	case "group":
		rows, err := c.db.QueryContext(ctx, `
			SELECT DISTINCT gm.peer_id
			FROM group_members gm
			JOIN groups g ON gm.group_id = g.id
			WHERE gm.group_id = ? AND g.is_pending_delete = 0
		`, tgtID)
		if err != nil {
			return nil, fmt.Errorf("query target group members for policy %d: %w", policyID, err)
		}
		defer func() {
			if err := rows.Close(); err != nil {
				log.Warn("close err", "err", err)
			}
		}()
		for rows.Next() {
			var p int
			if err := rows.Scan(&p); err != nil {
				log.WarnContext(ctx, "Failed to scan peer from target group", "error", err)
				continue
			}
			peers[p] = true
		}
		if err := rows.Err(); err != nil {
			log.ErrorContext(ctx, "rows iteration error in GetAffectedPeersByPolicy (target group)", "policy_id", policyID, "error", err)
		}
	}

	var peerList []int
	for id := range peers {
		peerList = append(peerList, id)
	}
	return peerList, nil
}

// GetAffectedPeersByPolicies returns a map of policyID -> affected peer IDs for
// each input policy. It is a thin batched wrapper over GetAffectedPeersByPolicy.
//
// NOTE: this is a stopgap. It still issues one SQL query per policy, so the
// caller does N queries (one per policy) followed by a merge step. The
// duplication vs. the per-policy call is zero in number of queries, but the
// benefit is centralized error handling and a single returned shape, which
// makes it easier to swap in a single batched SQL query later without
// touching every call site. Once the engine grows a real
// "find affected peers for these policies" query (one query with
// "policies.id IN (...)"), update the body to use it.
func (c *Compiler) GetAffectedPeersByPolicies(ctx context.Context, policyIDs []int) (map[int][]int, error) {
	result := make(map[int][]int, len(policyIDs))
	for _, pid := range policyIDs {
		peers, err := c.GetAffectedPeersByPolicy(ctx, pid)
		if err != nil {
			return nil, err
		}
		result[pid] = peers
	}
	return result, nil
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
