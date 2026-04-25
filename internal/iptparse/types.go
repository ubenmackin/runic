// Package iptparse provides parsing of iptables-save output into structured data.
package iptparse

// ParsedChain represents a single iptables chain with its rules.
type ParsedChain struct {
	Name  string       // e.g., "INPUT", "OUTPUT", "DOCKER-USER"
	Rules []ParsedRule // rules in order
}

// ParsedRule represents a single iptables rule parsed into structured fields.
type ParsedRule struct {
	Chain           string      // INPUT, OUTPUT, DOCKER-USER
	Order           int         // position in chain
	Raw             string      // original rule text
	Protocol        string      // tcp, udp, icmp, all
	SourceIP        string      // source IP/CIDR or "" for any
	DestIP          string      // destination IP/CIDR or "" for any
	SourcePort      string      // source port or port range
	DestPort        string      // destination port or port range
	InInterface     string      // -i match
	OutInterface    string      // -o match
	IpsetMatch      *IpsetMatch // -m set --match-set info
	ConntrackStates []string    // --ctstate values
	Target          string      // ACCEPT, DROP, REJECT, LOG, or custom chain name
	IsRunicStandard bool        // detected as Runic-managed standard rule
	IsClean         bool        // can be fully mapped to Runic policy
	SkipReason      string      // why it can't be mapped (if !IsClean)
	Comment         string      // -m comment --comment value
	PktType         string      // -m pkttype --pkt-type value
}

// IpsetMatch represents an ipset match in a rule.
type IpsetMatch struct {
	Name      string // ipset name
	Direction string // "src" or "dst" (from --match-set name src/dst)
}
