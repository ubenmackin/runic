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
type ruleWriter struct{ buf *strings.Builder }

func (rw *ruleWriter) accept(chain, match string) {
	fmt.Fprintf(rw.buf, "-A %s %s -j ACCEPT\n", chain, match)
}

func (rw *ruleWriter) drop(chain, match string) {
	fmt.Fprintf(rw.buf, "-A %s %s -j DROP\n", chain, match)
}

func (rw *ruleWriter) logDrop(chain, match string) {
	// Use direction-specific log prefix: RUNIC-DROP-I for INPUT, RUNIC-DROP-O for OUTPUT
	prefix := "[RUNIC-DROP-O] " // default for OUTPUT
	if chain == "INPUT" || chain == "DOCKER-USER" {
		prefix = "[RUNIC-DROP-I] "
	}
	fmt.Fprintf(rw.buf, "-A %s %s -j LOG --log-prefix \"%s\" --log-level 4\n", chain, match, prefix)
	rw.drop(chain, match)
}

func (rw *ruleWriter) writeAction(action, chain, match string) {
	switch action {
	case "ACCEPT":
		rw.accept(chain, match)
	case "DROP":
		rw.drop(chain, match)
	case "LOG_DROP":
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
			return fmt.Sprintf("group %d", entityID)
		}
		return name
	default:
		return fmt.Sprintf("%s %d", entityType, entityID)
	}
}

func (c *Compiler) getSpecialDisplayName(specialID int) string {
	names := map[int]string{
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
	if name, ok := names[specialID]; ok {
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
	rw.buf.WriteString("\n")

	// ICMP RELATED
	rw.buf.WriteString("# --- Standard: ICMP RELATED ---\n")
	rw.buf.WriteString("-A INPUT -p icmp -m conntrack --ctstate RELATED -j ACCEPT\n")
	rw.buf.WriteString("-A OUTPUT -p icmp -m conntrack --ctstate RELATED -j ACCEPT\n")
	rw.buf.WriteString("\n")

	// INVALID
	rw.buf.WriteString("# --- Standard: INVALID packet drop ---\n")
	rw.buf.WriteString("-A INPUT -m conntrack --ctstate INVALID -j DROP\n")
	rw.buf.WriteString("-A OUTPUT -m conntrack --ctstate INVALID -j DROP\n")
	rw.buf.WriteString("\n")

	// Control Plane Communication
	if controlPlanePort != "" {
		rw.buf.WriteString("# --- Standard: Control Plane Communication ---\n")
		fmt.Fprintf(rw.buf, "# Allows agent to communicate with control plane on port %s\n", controlPlanePort)
		fmt.Fprintf(rw.buf, "-A INPUT -p tcp --dport %s -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT\n", controlPlanePort)
		fmt.Fprintf(rw.buf, "-A OUTPUT -p tcp --sport %s -m conntrack --ctstate ESTABLISHED -j ACCEPT\n", controlPlanePort)
		fmt.Fprintf(rw.buf, "-A OUTPUT -p tcp --dport %s -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT\n", controlPlanePort)
		fmt.Fprintf(rw.buf, "-A INPUT -p tcp --sport %s -m conntrack --ctstate ESTABLISHED -j ACCEPT\n", controlPlanePort)
		rw.buf.WriteString("\n")
	}

	// Docker standard rules
	if hasDocker {
		rw.buf.WriteString("# --- Docker: Standard rules for DOCKER-USER ---\n")
		rw.buf.WriteString("-A DOCKER-USER -p icmp -m conntrack --ctstate RELATED -j ACCEPT\n")
		rw.buf.WriteString("-A DOCKER-USER -m conntrack --ctstate INVALID -j DROP\n")
		rw.buf.WriteString("\n")
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
		return nil, nil, nil, err
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
			return nil, err
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
			sanitizedName := "runic_group_" + sanitizeForIpset(groupIDToName[gid])
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
		log.WarnContext(ctx, "Failed to load control_plane_port, using default 8080", "error", err)
		controlPlanePort = "8080"
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

	if err := c.writePolicySection(ctx, &buf, rw, policies, services, ipsets, groupIDToIpsetName, hasDocker, hasIPSet, ipAddress); err != nil {
		return "", err
	}

	c.writeLoggingSection(&buf, hasDocker)
	buf.WriteString("\nCOMMIT\n")

	return buf.String(), nil
}

// writePayloadHeader writes the comment header at the top of the bundle.
func (c *Compiler) writePayloadHeader(buf *strings.Builder, hostname string, policies []policyInfo, hasIPSet bool, ipsets []ipsetData) {
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
	ipsets []ipsetData,
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

	// Expand ports for non-multicast, non-broadcast, and non-IGMP/VRRP services
	var portClauses []PortClause
	isBroadcastService := serviceName == systemServiceSubnetBroadcast || serviceName == systemServiceLimitedBroadcast
	isIGMPorVRRP := strings.EqualFold(serviceName, systemServiceIGMP) || strings.EqualFold(serviceName, systemServiceVRRP)
	if serviceName != systemServiceMulticast && !isBroadcastService && !isIGMPorVRRP {
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
		if serviceName == systemServiceMulticast {
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
		var cidrs []string
		var err error
		switch {
		case pol.SourceType == "special":
			cidrs, err = c.resolver.ResolveSpecialTarget(ctx, pol.SourceID, ipAddress)
		case pol.SourceType == "peer" && pol.SourceIP != "":
			cidrs = []string{resolve.NormalizeToCIDR(pol.SourceIP)}
		default:
			cidrs, err = c.resolver.ResolveEntity(ctx, pol.SourceType, pol.SourceID)
		}
		if err != nil {
			return fmt.Errorf("resolve source for policy %s: %w", pol.Name, err)
		}
		if serviceName == systemServiceMulticast {
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
		if serviceName == systemServiceMulticast {
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
		var cidrs []string
		var err error
		switch {
		case pol.TargetType == "special":
			cidrs, err = c.resolver.ResolveSpecialTarget(ctx, pol.TargetID, ipAddress)
		case pol.TargetType == "peer" && pol.TargetIP != "":
			cidrs = []string{resolve.NormalizeToCIDR(pol.TargetIP)}
		default:
			cidrs, err = c.resolver.ResolveEntity(ctx, pol.TargetType, pol.TargetID)
		}
		if err != nil {
			return fmt.Errorf("resolve target for policy %s: %w", pol.Name, err)
		}
		if serviceName == systemServiceMulticast {
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
	buf.WriteString("-A INPUT -j LOG --log-prefix \"[RUNIC-DROP-I] \" --log-level 4\n")
	buf.WriteString("-A INPUT -j DROP\n")
	buf.WriteString("-A OUTPUT -j LOG --log-prefix \"[RUNIC-DROP-O] \" --log-level 4\n")
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
		rw.accept("INPUT", "-d 224.0.0.1/32 -p igmp")
		// Send IGMPv3 reports (224.0.0.22 = IGMPv3 routers)
		rw.accept("OUTPUT", "-d 224.0.0.22/32 -p igmp")
	}
	if writeToDocker {
		rw.accept("DOCKER-USER", "-d 224.0.0.1/32 -p igmp")
		rw.accept("DOCKER-USER", "-d 224.0.0.22/32 -p igmp")
	}
}

// VRRP is a protocol for virtual router redundancy, using multicast 224.0.0.18.
// No conntrack or return rules are needed.
func (c *Compiler) writeVRRPRules(rw *ruleWriter, targetScope string, hasDocker bool) {
	writeToHost, writeToDocker := c.scopeFlags(targetScope, hasDocker)

	if writeToHost {
		// Accept VRRP advertisements (224.0.0.18 = VRRP multicast)
		rw.accept("OUTPUT", "-d 224.0.0.18/32 -p vrrp")
	}
	if writeToDocker {
		rw.accept("DOCKER-USER", "-d 224.0.0.18/32 -p vrrp")
	}
}

func (c *Compiler) writeMulticastRule(rw *ruleWriter, action string, targetScope string, hasDocker bool) {
	writeToHost, writeToDocker := c.scopeFlags(targetScope, hasDocker)

	if writeToHost {
		rw.writeAction(action, "INPUT", "-m pkttype --pkt-type multicast")
	}
	if writeToDocker {
		rw.writeAction(action, "DOCKER-USER", "-m pkttype --pkt-type multicast")
	}
	rw.newline()
}

// Broadcast traffic is connectionless, so no conntrack or return rules are needed.
// For broadcast, we match on destination (-d) since broadcast packets are sent TO the broadcast address.
func (c *Compiler) writeBroadcastRule(rw *ruleWriter, action string, targetScope string, hasDocker bool, broadcastAddr string, protocol string) {
	writeToHost, writeToDocker := c.scopeFlags(targetScope, hasDocker)

	if writeToHost {
		// Accept broadcast traffic destined for the broadcast address
		rw.accept("INPUT", fmt.Sprintf("-d %s -p %s", broadcastAddr, protocol))
	}
	if writeToDocker {
		rw.accept("DOCKER-USER", fmt.Sprintf("-d %s -p %s", broadcastAddr, protocol))
	}
}

func (c *Compiler) scopeFlags(targetScope string, hasDocker bool) (writeToHost, writeToDocker bool) {
	writeToHost = targetScope == "host" || targetScope == "both"
	writeToDocker = hasDocker && (targetScope == "docker" || targetScope == "both")
	return
}

// logDropRule generates a LOG + DROP rule pair for a given chain and match.
// Uses direction-specific log prefix: RUNIC-DROP-I for INPUT/DOCKER-USER, RUNIC-DROP-O otherwise.
func (c *Compiler) logDropRule(action, chain, match string) []string {
	if action != "LOG_DROP" {
		return []string{fmt.Sprintf("-A %s %s -j %s", chain, match, action)}
	}
	prefix := "[RUNIC-DROP-O] " // default for OUTPUT
	if chain == "INPUT" || chain == "DOCKER-USER" {
		prefix = "[RUNIC-DROP-I] "
	}
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
	var rules []string
	privateIpsetMatch := "-m set ! --match-set runic_private_ranges dst"

	for _, pc := range portClauses {
		// Build port matches depending on direction
		var primaryPortMatch, returnPortMatch string
		primaryPortMatch = pc.PortMatch
		if pc.SrcPortMatch != "" {
			primaryPortMatch = pc.SrcPortMatch + " " + primaryPortMatch
		}
		returnPortMatch = invertPortMatch(pc.PortMatch, pc.SrcPortMatch)

		// Build conntrack part based on noConntrack flag
		var conntrackFull string
		if noConntrack {
			conntrackFull = ""
		} else {
			conntrackFull = "-m conntrack --ctstate NEW,ESTABLISHED"
		}

		// For "source" direction, determine return CIDRs with multicast adjustments
		var returnCIDRs []string
		if ruleDir == "source" || ruleDir == "internet" {
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
			if ruleDir == "source" {
				ipsetMatchPrimary, ipsetMatchReturn = ipsetMatchReturn, ipsetMatchPrimary
			}

			if writeToHost {
				if pol.Action == "ACCEPT" {
					switch ruleDir {
					case "target":
						rules = append(rules,
							fmt.Sprintf("-A INPUT -p %s %s %s %s -j %s", pc.Protocol, ipsetMatchPrimary, primaryPortMatch, conntrackFull, pol.Action),
							fmt.Sprintf("-A OUTPUT -p %s %s %s %s -j ACCEPT", pc.Protocol, ipsetMatchReturn, returnPortMatch, conntrackFull),
						)
					case "source":
						rules = append(rules,
							fmt.Sprintf("-A OUTPUT -p %s %s %s %s -j %s", pc.Protocol, ipsetMatchPrimary, primaryPortMatch, conntrackFull, pol.Action),
							fmt.Sprintf("-A INPUT -p %s %s %s %s -j %s", pc.Protocol, ipsetMatchReturn, returnPortMatch, conntrackFull, pol.Action),
						)
					case "internet":
						rules = append(rules,
							fmt.Sprintf("-A OUTPUT -p %s %s %s %s -j %s", pc.Protocol, privateIpsetMatch, primaryPortMatch, conntrackFull, pol.Action),
							fmt.Sprintf("-A INPUT -p %s %s %s %s -j ACCEPT", pc.Protocol, "-m set ! --match-set runic_private_ranges src", returnPortMatch, conntrackFull),
						)
					}
				} else {
					chain := "INPUT"
					if ruleDir == "source" || ruleDir == "internet" {
						chain = "OUTPUT"
					}
					match := fmt.Sprintf("-p %s %s %s", pc.Protocol, ipsetMatchPrimary, primaryPortMatch)
					if ruleDir == "internet" {
						match = fmt.Sprintf("-p %s %s %s", pc.Protocol, privateIpsetMatch, primaryPortMatch)
					}
					rules = append(rules, c.logDropRule(pol.Action, chain, match)...)
				}
			}
			if writeToDocker {
				if pol.Action == "ACCEPT" {
					switch ruleDir {
					case "target":
						rules = append(rules, fmt.Sprintf("-A DOCKER-USER -p %s %s %s %s -j %s", pc.Protocol, ipsetMatchPrimary, primaryPortMatch, conntrackFull, pol.Action))
					case "source":
						rules = append(rules, fmt.Sprintf("-A DOCKER-USER -p %s %s %s %s -j %s", pc.Protocol, ipsetMatchPrimary, primaryPortMatch, conntrackFull, pol.Action))
					case "internet":
						rules = append(rules, fmt.Sprintf("-A DOCKER-USER -p %s %s %s %s -j %s", pc.Protocol, privateIpsetMatch, primaryPortMatch, conntrackFull, pol.Action))
					}
				} else {
					match := fmt.Sprintf("-p %s %s %s", pc.Protocol, ipsetMatchPrimary, primaryPortMatch)
					if ruleDir == "internet" {
						match = fmt.Sprintf("-p %s %s %s", pc.Protocol, privateIpsetMatch, primaryPortMatch)
					}
					rules = append(rules, c.logDropRule(pol.Action, "DOCKER-USER", match)...)
				}
			}
		} else {
			// Filter out self-referencing CIDRs (peer connecting to itself).
			// A CIDR is self-referencing if it exactly matches the peer's own
			// IP address (normalized to CIDR notation). For example, peer with
			// IP "10.0.0.1" has CIDR "10.0.0.1/32", so a source CIDR of
			// "10.0.0.1/32" is self-referencing. A CIDR range like "10.0.0.0/24"
			// is NOT self-referencing even if it contains the peer's IP.
			var filteredCidrs []string
			peerCIDR := resolve.NormalizeToCIDR(ipAddress)
			for _, cidr := range cidrs {
				if cidr != peerCIDR {
					filteredCidrs = append(filteredCidrs, cidr)
				}
			}

			for _, cidr := range filteredCidrs {
				if writeToHost {
					switch ruleDir {
					case "target":
						if pol.Action == "ACCEPT" {
							rules = append(rules,
								fmt.Sprintf("-A INPUT -s %s -p %s %s %s -j %s", cidr, pc.Protocol, primaryPortMatch, conntrackFull, pol.Action),
								fmt.Sprintf("-A OUTPUT -d %s -p %s %s %s -j ACCEPT", cidr, pc.Protocol, returnPortMatch, conntrackFull),
							)
						} else {
							rules = append(rules, c.logDropRule(pol.Action, "INPUT", fmt.Sprintf("-s %s -p %s %s", cidr, pc.Protocol, primaryPortMatch))...)
						}
					case "source":
						if pol.Action == "ACCEPT" {
							rules = append(rules, fmt.Sprintf("-A OUTPUT -d %s -p %s %s %s -j %s", cidr, pc.Protocol, primaryPortMatch, conntrackFull, pol.Action))
						} else {
							rules = append(rules, c.logDropRule(pol.Action, "OUTPUT", fmt.Sprintf("-d %s -p %s %s", cidr, pc.Protocol, primaryPortMatch))...)
						}
					case "internet":
						if pol.Action == "ACCEPT" {
							rules = append(rules, fmt.Sprintf("-A OUTPUT -d %s -p %s %s %s -j %s", cidr, pc.Protocol, primaryPortMatch, conntrackFull, pol.Action))
						} else {
							rules = append(rules, c.logDropRule(pol.Action, "OUTPUT", fmt.Sprintf("-d %s -p %s %s", cidr, pc.Protocol, primaryPortMatch))...)
						}
					}
				}
				if writeToDocker {
					switch ruleDir {
					case "target":
						if pol.Action == "ACCEPT" {
							rules = append(rules, fmt.Sprintf("-A DOCKER-USER -s %s -p %s %s %s -j %s", cidr, pc.Protocol, primaryPortMatch, conntrackFull, pol.Action))
						} else {
							rules = append(rules, c.logDropRule(pol.Action, "DOCKER-USER", fmt.Sprintf("-s %s -p %s %s", cidr, pc.Protocol, primaryPortMatch))...)
						}
					case "source":
						if pol.Action == "ACCEPT" {
							rules = append(rules, fmt.Sprintf("-A DOCKER-USER -d %s -p %s %s %s -j %s", cidr, pc.Protocol, primaryPortMatch, conntrackFull, pol.Action))
						} else {
							rules = append(rules, c.logDropRule(pol.Action, "DOCKER-USER", fmt.Sprintf("-d %s -p %s %s", cidr, pc.Protocol, primaryPortMatch))...)
						}
					case "internet":
						if pol.Action == "ACCEPT" {
							rules = append(rules, fmt.Sprintf("-A DOCKER-USER -d %s -p %s %s %s -j %s", cidr, pc.Protocol, primaryPortMatch, conntrackFull, pol.Action))
						} else {
							rules = append(rules, c.logDropRule(pol.Action, "DOCKER-USER", fmt.Sprintf("-d %s -p %s %s", cidr, pc.Protocol, primaryPortMatch))...)
						}
					}
				}
			}

			// Generate INPUT return rules for source/internet direction
			if (ruleDir == "source" || ruleDir == "internet") && pol.Action == "ACCEPT" {
				var filteredReturnCidrs []string
				for _, rc := range returnCIDRs {
					if rc != peerCIDR {
						filteredReturnCidrs = append(filteredReturnCidrs, rc)
					}
				}
				for _, returnCidr := range filteredReturnCidrs {
					rules = append(rules, fmt.Sprintf("-A INPUT -s %s -p %s %s %s -j ACCEPT", returnCidr, pc.Protocol, returnPortMatch, conntrackFull))
				}
			}
		}
	}
	return rules, nil
}

// PreviewCompile generates iptables rules for a single policy. Unlike Compile(), this is policy-centric: it resolves both source and target entities
// and generates rules based on direction, showing the complete picture across all hosts.
func (c *Compiler) PreviewCompile(ctx context.Context, peerID, sourceID int, sourceType string, sourceIP string, targetID int, targetType string, targetIP string, serviceID int, action, direction string, targetScope string) ([]string, error) {
	// Load a peer IP for special target resolution (uses peerID as reference)
	var ipAddress string
	if peerID != 0 {
		if err := c.db.QueryRowContext(ctx,
			"SELECT ip_address FROM peers WHERE id = ?", peerID,
		).Scan(&ipAddress); err != nil && !errors.Is(err, sql.ErrNoRows) {
			// Log but don't fail - IP is optional for preview
			log.WarnContext(ctx, "Failed to load peer IP for preview", "error", err)
		}
	}

	// Default direction
	if direction == "" {
		direction = "both"
	}

	// Default target_scope
	if targetScope == "" {
		targetScope = "both"
	}

	var rules []string

	// Load service - MC-011: Include no_conntrack column
	var serviceName, ports, sourcePorts, protocol string
	var noConntrack bool
	err := c.db.QueryRowContext(ctx, "SELECT name, ports, source_ports, protocol, COALESCE(no_conntrack, 0) FROM services WHERE id = ? AND is_pending_delete = 0", serviceID).Scan(&serviceName, &ports, &sourcePorts, &protocol, &noConntrack)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("service %d is pending delete or does not exist", serviceID)
	}
	if err != nil {
		return nil, fmt.Errorf("load service: %w", err)
	}

	var portClauses []PortClause
	// Skip port expansion for special services that don't use ports
	isIGMPorVRRP := strings.EqualFold(serviceName, systemServiceIGMP) || strings.EqualFold(serviceName, systemServiceVRRP)
	if serviceName != systemServiceMulticast && !isIGMPorVRRP {
		portClauses, err = ExpandPorts(ports, sourcePorts, protocol)
		if err != nil {
			return nil, fmt.Errorf("expand ports: %w", err)
		}
	}

	// Resolve source CIDRs
	var sourceCIDRs []string
	switch {
	case sourceType == "special":
		sourceCIDRs, err = c.resolver.ResolveSpecialTarget(ctx, sourceID, ipAddress)
		if err != nil {
			return nil, fmt.Errorf("resolve source special target %d: %w", sourceID, err)
		}
	case sourceType == "peer" && sourceIP != "":
		// Use the specific source_ip from the policy instead of peer's primary IP
		sourceCIDRs = []string{resolve.NormalizeToCIDR(sourceIP)}
	default:
		sourceCIDRs, err = c.resolver.ResolveEntity(ctx, sourceType, sourceID)
		if err != nil {
			return nil, fmt.Errorf("resolve source entity %s/%d: %w", sourceType, sourceID, err)
		}
	}

	// Resolve target CIDRs
	var targetCIDRs []string
	switch {
	case targetType == "special":
		targetCIDRs, err = c.resolver.ResolveSpecialTarget(ctx, targetID, ipAddress)
		if err != nil {
			return nil, fmt.Errorf("resolve target special target %d: %w", targetID, err)
		}
	case targetType == "peer" && targetIP != "":
		// Use the specific target_ip from the policy instead of peer's primary IP
		targetCIDRs = []string{resolve.NormalizeToCIDR(targetIP)}
	default:
		targetCIDRs, err = c.resolver.ResolveEntity(ctx, targetType, targetID)
		if err != nil {
			return nil, fmt.Errorf("resolve target entity %s/%d: %w", targetType, targetID, err)
		}
	}

	isInternetTarget := targetType == "special" && targetID == resolve.SpecialIDInternet

	// Build policy info for helper functions
	pol := &policyInfo{
		Action: action,
	}

	// Forward: Source initiates connections TO Target
	// Source hosts get: OUTPUT to target + INPUT established from target
	// Target hosts get: INPUT from source + OUTPUT established to source
	if targetScope == "host" || targetScope == "both" {
		// IG-002: Special IGMP handling - skip normal source/target resolution
		// VRRP-002: Special VRRP handling - skip normal source/target resolution
		switch {
		case strings.EqualFold(serviceName, systemServiceIGMP):
			// IG-002: Special IGMP handling
			rules = append(rules,
				"-A INPUT -d 224.0.0.1/32 -p igmp -j ACCEPT",
				"-A OUTPUT -d 224.0.0.22/32 -p igmp -j ACCEPT",
			)
		case strings.EqualFold(serviceName, systemServiceVRRP):
			// VRRP-002: Special VRRP handling (advertisements are sent to 224.0.0.18)
			rules = append(rules, "-A OUTPUT -d 224.0.0.18/32 -p vrrp -j ACCEPT")
		case direction == "both" || direction == "forward":
			rules = append(rules, "# Forward (Source → Target)")
			for _, targetCIDR := range targetCIDRs {
				if serviceName == systemServiceMulticast {
					// MC-012: Only generate OUTPUT multicast rule when Target is a multicast special target
					isMulticastTarget := targetType == "special" && isMulticastSpecialID(targetID)
					if isMulticastTarget {
						rules = append(rules, "-A OUTPUT -d 224.0.0.0/4 -m pkttype --pkt-type multicast -j ACCEPT")
					}
					continue
				}
				_ = targetCIDR // suppress unused variable warning
			}
			// Use writeSourceRules for forward direction (egress)
			if isInternetTarget {
				writeRules, err := c.writeRules(pol, portClauses, false, "", nil, ipAddress, true, false, noConntrack, "internet", false)
				if err != nil {
					return nil, err
				}
				rules = append(rules, writeRules...)
			} else {
				// Use writeSourceRules for regular targets
				isMulticastTarget := targetType == "special" && isMulticastSpecialID(targetID)
				writeRules, err := c.writeRules(pol, portClauses, false, "", targetCIDRs, ipAddress, true, false, noConntrack, "source", isMulticastTarget)
				if err != nil {
					return nil, err
				}
				rules = append(rules, writeRules...)
			}
		}

		// Backward: Target initiates connections TO Source
		// Target hosts get: OUTPUT to source + INPUT established from source
		// Source hosts get: INPUT from target + OUTPUT established to target
		// IG-002: Skip backward for IGMP (already handled above)
		// VRRP-002: Skip backward for VRRP (already handled above)
		if !strings.EqualFold(serviceName, systemServiceIGMP) && !strings.EqualFold(serviceName, systemServiceVRRP) && (direction == "both" || direction == "backward") {
			rules = append(rules, "# Backward (Target → Source)")
			// MC-009: Multicast special targets as Source indicate receiving multicast traffic
			isMulticastSource := sourceType == "special" && isMulticastSpecialID(sourceID)
			// BC-003: Broadcast special targets as Source indicate receiving broadcast traffic
			isBroadcastSource := sourceType == "special" && isBroadcastSpecialID(sourceID)
			switch {
			case isMulticastSource:
				// Multicast source: use packet type matching for receiving multicast traffic
				if serviceName == systemServiceMulticast {
					rules = append(rules, "-A INPUT -m pkttype --pkt-type multicast -j ACCEPT")
				} else {
					writeRules, err := c.writeRules(pol, portClauses, false, "", sourceCIDRs, ipAddress, true, false, noConntrack, "target", false)
					if err != nil {
						return nil, err
					}
					rules = append(rules, writeRules...)
				}
			case isBroadcastSource:
				// Broadcast source: use -d (destination) matching since broadcast packets are sent TO the broadcast address
				for _, sourceCIDR := range sourceCIDRs {
					rules = append(rules, fmt.Sprintf("-A INPUT -d %s -p udp -j ACCEPT", sourceCIDR))
				}
			default:
				// Use writeTargetRules for backward direction (ingress from source perspective)
				writeRules, err := c.writeRules(pol, portClauses, false, "", sourceCIDRs, ipAddress, true, false, noConntrack, "target", false)
				if err != nil {
					return nil, err
				}
				rules = append(rules, writeRules...)
			}
		}
	}

	// Docker: DOCKER-USER chain rules (for Docker containers)
	// Generated when targetScope is "docker" or "both"
	if targetScope == "docker" || targetScope == "both" {
		// IG-002: Special IGMP handling for Docker
		// VRRP-002: Special VRRP handling for Docker
		switch {
		case strings.EqualFold(serviceName, systemServiceIGMP):
			// IG-002: Special IGMP handling for Docker
			rules = append(rules,
				"-A DOCKER-USER -d 224.0.0.1/32 -p igmp -j ACCEPT",
				"-A DOCKER-USER -d 224.0.0.22/32 -p igmp -j ACCEPT",
			)
		case strings.EqualFold(serviceName, systemServiceVRRP):
			// VRRP-002: Special VRRP handling (advertisements are sent to 224.0.0.18)
			rules = append(rules, "-A DOCKER-USER -d 224.0.0.18/32 -p vrrp -j ACCEPT")
		default:
			rules = append(rules, "# Docker: DOCKER-USER chain rules")
			// Forward direction: Source → Target (Docker)
			if direction == "both" || direction == "forward" {
				for _, targetCIDR := range targetCIDRs {
					if serviceName == systemServiceMulticast {
						rules = append(rules, "-A DOCKER-USER -d 224.0.0.0/4 -m pkttype --pkt-type multicast -j ACCEPT")
						continue
					}
					_ = targetCIDR // suppress unused variable warning
				}
				// Use writeSourceRules for Docker forward direction (egress to Docker)
				if isInternetTarget {
					writeRules, err := c.writeRules(pol, portClauses, false, "", nil, ipAddress, false, true, noConntrack, "internet", false)
					if err != nil {
						return nil, err
					}
					rules = append(rules, writeRules...)
				} else {
					isMulticastTarget := targetType == "special" && isMulticastSpecialID(targetID)
					writeRules, err := c.writeRules(pol, portClauses, false, "", targetCIDRs, ipAddress, false, true, noConntrack, "source", isMulticastTarget)
					if err != nil {
						return nil, err
					}
					rules = append(rules, writeRules...)
				}
			}
			// Backward direction: Target (Docker) ← Source
			// IG-002: Skip backward for IGMP (already handled above)
			// VRRP-002: Skip backward for VRRP (already handled above)
			if direction == "both" || direction == "backward" {
				// MC-009: Multicast special targets as Source indicate receiving multicast traffic
				isMulticastSource := sourceType == "special" && isMulticastSpecialID(sourceID)
				// BC-003: Broadcast special targets as Source indicate receiving broadcast traffic
				isBroadcastSource := sourceType == "special" && isBroadcastSpecialID(sourceID)
				switch {
				case isMulticastSource:
					// Multicast source: use packet type matching for receiving multicast traffic
					if serviceName == systemServiceMulticast {
						rules = append(rules, "-A DOCKER-USER -m pkttype --pkt-type multicast -j ACCEPT")
					} else {
						writeRules, err := c.writeRules(pol, portClauses, false, "", sourceCIDRs, ipAddress, false, true, noConntrack, "target", false)
						if err != nil {
							return nil, err
						}
						rules = append(rules, writeRules...)
					}
				case isBroadcastSource:
					// Broadcast source: use -d (destination) matching for broadcast traffic
					for _, sourceCIDR := range sourceCIDRs {
						rules = append(rules, fmt.Sprintf("-A DOCKER-USER -d %s -p udp -j ACCEPT", sourceCIDR))
					}
				default:
					// Use writeTargetRules for Docker backward direction
					writeRules, err := c.writeRules(pol, portClauses, false, "", sourceCIDRs, ipAddress, false, true, noConntrack, "target", false)
					if err != nil {
						return nil, err
					}
					rules = append(rules, writeRules...)
				}
			}
		}
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
			return nil, err
		}
		policyIDs = append(policyIDs, id)
	}
	if err := rows.Err(); err != nil {
		return nil, err
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
