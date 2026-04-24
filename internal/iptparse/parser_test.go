package iptparse

import (
	"strings"
	"testing"
)

// TestParseBasicInputRule tests a simple INPUT rule accepting TCP on port 80.
func TestParseBasicInputRule(t *testing.T) {
	input := `*filter
:INPUT ACCEPT [0:0]
-A INPUT -p tcp -m tcp --dport 80 -j ACCEPT
COMMIT
`
	chains, err := Parse(input, []string{"INPUT"})
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}
	if len(chains) != 1 {
		t.Fatalf("expected 1 chain, got %d", len(chains))
	}
	if chains[0].Name != "INPUT" {
		t.Errorf("expected chain name INPUT, got %s", chains[0].Name)
	}
	if len(chains[0].Rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(chains[0].Rules))
	}

	rule := chains[0].Rules[0]
	if rule.Chain != "INPUT" {
		t.Errorf("expected Chain=INPUT, got %s", rule.Chain)
	}
	if rule.Order != 1 {
		t.Errorf("expected Order=1, got %d", rule.Order)
	}
	if rule.Protocol != "tcp" {
		t.Errorf("expected Protocol=tcp, got %s", rule.Protocol)
	}
	if rule.DestPort != "80" {
		t.Errorf("expected DestPort=80, got %s", rule.DestPort)
	}
	if rule.Target != "ACCEPT" {
		t.Errorf("expected Target=ACCEPT, got %s", rule.Target)
	}
	if !rule.IsClean {
		t.Errorf("expected IsClean=true, got false")
	}
	if rule.IsRunicStandard {
		t.Errorf("expected IsRunicStandard=false, got true")
	}
	if rule.SkipReason != "" {
		t.Errorf("expected SkipReason='', got %q", rule.SkipReason)
	}
}

// TestParseBasicOutputRule tests a simple OUTPUT rule.
func TestParseBasicOutputRule(t *testing.T) {
	input := `*filter
:OUTPUT ACCEPT [0:0]
-A OUTPUT -p udp --dport 53 -j ACCEPT
COMMIT
`
	chains, err := Parse(input, []string{"OUTPUT"})
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}
	if len(chains) != 1 {
		t.Fatalf("expected 1 chain, got %d", len(chains))
	}

	rule := chains[0].Rules[0]
	if rule.Chain != "OUTPUT" {
		t.Errorf("expected Chain=OUTPUT, got %s", rule.Chain)
	}
	if rule.Protocol != "udp" {
		t.Errorf("expected Protocol=udp, got %s", rule.Protocol)
	}
	if rule.DestPort != "53" {
		t.Errorf("expected DestPort=53, got %s", rule.DestPort)
	}
	if rule.Target != "ACCEPT" {
		t.Errorf("expected Target=ACCEPT, got %s", rule.Target)
	}
	if !rule.IsClean {
		t.Errorf("expected IsClean=true, got false")
	}
}

// TestParseDockerUserRule tests DOCKER-USER chain rule with -o docker0.
func TestParseDockerUserRule(t *testing.T) {
	input := `*filter
:DOCKER-USER - [0:0]
-A DOCKER-USER -o docker0 -p tcp --dport 443 -j ACCEPT
COMMIT
`
	chains, err := Parse(input, []string{"DOCKER-USER"})
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}
	if len(chains) != 1 {
		t.Fatalf("expected 1 chain, got %d", len(chains))
	}

	rule := chains[0].Rules[0]
	if rule.Chain != "DOCKER-USER" {
		t.Errorf("expected Chain=DOCKER-USER, got %s", rule.Chain)
	}
	if rule.OutInterface != "docker0" {
		t.Errorf("expected OutInterface=docker0, got %s", rule.OutInterface)
	}
	if rule.Protocol != "tcp" {
		t.Errorf("expected Protocol=tcp, got %s", rule.Protocol)
	}
	if rule.DestPort != "443" {
		t.Errorf("expected DestPort=443, got %s", rule.DestPort)
	}
	if rule.Target != "ACCEPT" {
		t.Errorf("expected Target=ACCEPT, got %s", rule.Target)
	}
	// -o docker0 in DOCKER-USER chain should be acceptable
	if !rule.IsClean {
		t.Errorf("expected IsClean=true for DOCKER-USER with -o docker0, got false; SkipReason=%q", rule.SkipReason)
	}
}

// TestParseIpsetMatch tests rule with -m set --match-set runic_group_web src.
func TestParseIpsetMatch(t *testing.T) {
	input := `*filter
:INPUT DROP [0:0]
-A INPUT -m set --match-set runic_group_web src -p tcp --dport 443 -j ACCEPT
COMMIT
`
	chains, err := Parse(input, []string{"INPUT"})
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	rule := chains[0].Rules[0]
	if rule.IpsetMatch == nil {
		t.Fatal("expected IpsetMatch to be set, got nil")
	}
	if rule.IpsetMatch.Name != "runic_group_web" {
		t.Errorf("expected IpsetMatch.Name=runic_group_web, got %s", rule.IpsetMatch.Name)
	}
	if rule.IpsetMatch.Direction != "src" {
		t.Errorf("expected IpsetMatch.Direction=src, got %s", rule.IpsetMatch.Direction)
	}
	if rule.Protocol != "tcp" {
		t.Errorf("expected Protocol=tcp, got %s", rule.Protocol)
	}
	if rule.DestPort != "443" {
		t.Errorf("expected DestPort=443, got %s", rule.DestPort)
	}
	if rule.Target != "ACCEPT" {
		t.Errorf("expected Target=ACCEPT, got %s", rule.Target)
	}
	// runic_ prefixed ipset = Runic standard
	if !rule.IsRunicStandard {
		t.Errorf("expected IsRunicStandard=true for runic_ ipset, got false")
	}
	if rule.IsClean {
		t.Errorf("expected IsClean=false for Runic standard rule, got true")
	}
	if rule.SkipReason != "runic standard rule" {
		t.Errorf("expected SkipReason='runic standard rule', got %q", rule.SkipReason)
	}
}

// TestParseCustomIpset tests rule with non-Runic ipset.
func TestParseCustomIpset(t *testing.T) {
	input := `*filter
:INPUT DROP [0:0]
-A INPUT -m set --match-set custom_allow src -p tcp --dport 22 -j ACCEPT
COMMIT
`
	chains, err := Parse(input, []string{"INPUT"})
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	rule := chains[0].Rules[0]
	if rule.IpsetMatch == nil {
		t.Fatal("expected IpsetMatch to be set, got nil")
	}
	if rule.IpsetMatch.Name != "custom_allow" {
		t.Errorf("expected IpsetMatch.Name=custom_allow, got %s", rule.IpsetMatch.Name)
	}
	if rule.IpsetMatch.Direction != "src" {
		t.Errorf("expected IpsetMatch.Direction=src, got %s", rule.IpsetMatch.Direction)
	}
	// Non-runic ipset should not be marked as Runic standard
	if rule.IsRunicStandard {
		t.Errorf("expected IsRunicStandard=false for non-runic ipset, got true")
	}
	// Should be clean since it's ACCEPT with supported modules only
	if !rule.IsClean {
		t.Errorf("expected IsClean=true for non-runic ipset with ACCEPT, got false; SkipReason=%q", rule.SkipReason)
	}
}

// TestParseConntrackStates tests rule with conntrack states.
func TestParseConntrackStates(t *testing.T) {
	input := `*filter
:INPUT DROP [0:0]
-A INPUT -p tcp -m conntrack --ctstate NEW -m tcp --dport 80 -j ACCEPT
COMMIT
`
	chains, err := Parse(input, []string{"INPUT"})
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	rule := chains[0].Rules[0]
	if len(rule.ConntrackStates) != 1 || rule.ConntrackStates[0] != "NEW" {
		t.Errorf("expected ConntrackStates=[NEW], got %v", rule.ConntrackStates)
	}
	if rule.Protocol != "tcp" {
		t.Errorf("expected Protocol=tcp, got %s", rule.Protocol)
	}
	if rule.DestPort != "80" {
		t.Errorf("expected DestPort=80, got %s", rule.DestPort)
	}
	if rule.Target != "ACCEPT" {
		t.Errorf("expected Target=ACCEPT, got %s", rule.Target)
	}
	// NEW state only should be clean
	if !rule.IsClean {
		t.Errorf("expected IsClean=true for NEW-only conntrack, got false; SkipReason=%q", rule.SkipReason)
	}
}

// TestDetectRunicStandardLoopback tests loopback ACCEPT rule detection.
func TestDetectRunicStandardLoopback(t *testing.T) {
	tests := []struct {
		name  string
		input string
		iface string
		in    bool // true = -i, false = -o
	}{
		{
			name:  "input loopback",
			input: "-A INPUT -i lo -j ACCEPT",
			iface: "lo",
			in:    true,
		},
		{
			name:  "output loopback",
			input: "-A OUTPUT -o lo -j ACCEPT",
			iface: "lo",
			in:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			iptSave := "*filter\n:INPUT DROP [0:0]\n:OUTPUT DROP [0:0]\n" + tt.input + "\nCOMMIT\n"
			chains, err := Parse(iptSave, []string{"INPUT", "OUTPUT"})
			if err != nil {
				t.Fatalf("Parse returned error: %v", err)
			}

			found := false
			for _, chain := range chains {
				for _, rule := range chain.Rules {
					if rule.IsRunicStandard && rule.Target == "ACCEPT" {
						if tt.in && rule.InInterface == "lo" {
							found = true
						}
						if !tt.in && rule.OutInterface == "lo" {
							found = true
						}
					}
				}
			}
			if !found {
				t.Errorf("expected Runic standard loopback rule to be detected")
			}
		})
	}
}

// TestDetectRunicStandardICMPRelated tests ICMP RELATED ACCEPT detection.
func TestDetectRunicStandardICMPRelated(t *testing.T) {
	input := `*filter
:INPUT DROP [0:0]
-A INPUT -p icmp -m conntrack --ctstate RELATED -j ACCEPT
COMMIT
`
	chains, err := Parse(input, []string{"INPUT"})
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	rule := chains[0].Rules[0]
	if !rule.IsRunicStandard {
		t.Errorf("expected IsRunicStandard=true for ICMP RELATED, got false")
	}
	if rule.SkipReason != "runic standard rule" {
		t.Errorf("expected SkipReason='runic standard rule', got %q", rule.SkipReason)
	}
}

// TestDetectRunicStandardInvalidDrop tests INVALID DROP detection.
func TestDetectRunicStandardInvalidDrop(t *testing.T) {
	input := `*filter
:INPUT DROP [0:0]
-A INPUT -m conntrack --ctstate INVALID -j DROP
COMMIT
`
	chains, err := Parse(input, []string{"INPUT"})
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	rule := chains[0].Rules[0]
	if !rule.IsRunicStandard {
		t.Errorf("expected IsRunicStandard=true for INVALID DROP, got false")
	}
	if rule.SkipReason != "runic standard rule" {
		t.Errorf("expected SkipReason='runic standard rule', got %q", rule.SkipReason)
	}
}

// TestDetectRunicStandardIpsetRule tests rule with runic_ prefixed ipset detection.
func TestDetectRunicStandardIpsetRule(t *testing.T) {
	input := `*filter
:INPUT DROP [0:0]
-A INPUT -m set --match-set runic_group_office src -p tcp --dport 443 -j ACCEPT
COMMIT
`
	chains, err := Parse(input, []string{"INPUT"})
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	rule := chains[0].Rules[0]
	if !rule.IsRunicStandard {
		t.Errorf("expected IsRunicStandard=true for runic_ ipset, got false")
	}
	if rule.SkipReason != "runic standard rule" {
		t.Errorf("expected SkipReason='runic standard rule', got %q", rule.SkipReason)
	}
}

// TestSkipInterfaceMatch tests that rule with -i eth0 is marked as not clean.
func TestSkipInterfaceMatch(t *testing.T) {
	input := `*filter
:INPUT DROP [0:0]
-A INPUT -i eth0 -p tcp --dport 80 -j ACCEPT
COMMIT
`
	chains, err := Parse(input, []string{"INPUT"})
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	rule := chains[0].Rules[0]
	if rule.IsClean {
		t.Errorf("expected IsClean=false for -i eth0, got true")
	}
	if !strings.Contains(rule.SkipReason, "interface match not supported") {
		t.Errorf("expected SkipReason containing 'interface match not supported', got %q", rule.SkipReason)
	}
}

// TestSkipRejectTarget tests that rule with -j REJECT is marked as not clean.
func TestSkipRejectTarget(t *testing.T) {
	input := `*filter
:INPUT DROP [0:0]
-A INPUT -p tcp --dport 80 -j REJECT
COMMIT
`
	chains, err := Parse(input, []string{"INPUT"})
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	rule := chains[0].Rules[0]
	if rule.IsClean {
		t.Errorf("expected IsClean=false for REJECT target, got true")
	}
	if !strings.Contains(rule.SkipReason, "unsupported target: REJECT") {
		t.Errorf("expected SkipReason containing 'unsupported target: REJECT', got %q", rule.SkipReason)
	}
}

// TestSkipConntrackEstablished tests that rule with ESTABLISHED state is marked as not clean.
func TestSkipConntrackEstablished(t *testing.T) {
	input := `*filter
:INPUT DROP [0:0]
-A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
COMMIT
`
	chains, err := Parse(input, []string{"INPUT"})
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	rule := chains[0].Rules[0]
	// ESTABLISHED,RELATED should be Runic standard
	if !rule.IsRunicStandard {
		t.Errorf("expected IsRunicStandard=true for ESTABLISHED,RELATED rule, got false")
	}
}

// TestSkipConntrackEstablishedNonRunic tests that ESTABLISHED state without RELATED is not clean.
func TestSkipConntrackEstablishedNonRunic(t *testing.T) {
	input := `*filter
:INPUT DROP [0:0]
-A INPUT -p tcp -m conntrack --ctstate ESTABLISHED -m tcp --dport 80 -j ACCEPT
COMMIT
`
	chains, err := Parse(input, []string{"INPUT"})
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	rule := chains[0].Rules[0]
	// ESTABLISHED alone (with specific port) is not a standard Runic rule
	if rule.IsRunicStandard {
		t.Errorf("expected IsRunicStandard=false, got true")
	}
	if rule.IsClean {
		t.Errorf("expected IsClean=false for ESTABLISHED conntrack, got true")
	}
	if !strings.Contains(rule.SkipReason, "conntrack states not supported") {
		t.Errorf("expected SkipReason containing 'conntrack states not supported', got %q", rule.SkipReason)
	}
}

// TestSkipCustomChain tests that rule with -j CUSTOM_CHAIN is marked as not clean.
func TestSkipCustomChain(t *testing.T) {
	input := `*filter
:INPUT DROP [0:0]
-A INPUT -p tcp --dport 80 -j CUSTOM_CHAIN
COMMIT
`
	chains, err := Parse(input, []string{"INPUT"})
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	rule := chains[0].Rules[0]
	if rule.IsClean {
		t.Errorf("expected IsClean=false for custom chain target, got true")
	}
	if !strings.Contains(rule.SkipReason, "unsupported target: CUSTOM_CHAIN") {
		t.Errorf("expected SkipReason containing 'unsupported target: CUSTOM_CHAIN', got %q", rule.SkipReason)
	}
}

// TestParseEmptyInput tests that empty string returns no chains.
func TestParseEmptyInput(t *testing.T) {
	chains, err := Parse("", []string{"INPUT"})
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}
	if len(chains) != 0 {
		t.Errorf("expected 0 chains for empty input, got %d", len(chains))
	}
}

// TestParseCommentLines tests that lines starting with # or : are ignored.
func TestParseCommentLines(t *testing.T) {
	input := `# This is a comment
*filter
:INPUT ACCEPT [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
# Another comment
-A INPUT -p tcp -m tcp --dport 80 -j ACCEPT
COMMIT
`
	chains, err := Parse(input, []string{"INPUT"})
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}
	if len(chains) != 1 {
		t.Fatalf("expected 1 chain, got %d", len(chains))
	}
	if len(chains[0].Rules) != 1 {
		t.Errorf("expected 1 rule (comments and chain defs ignored), got %d", len(chains[0].Rules))
	}
}

// TestParseMultipleChains tests input with rules across multiple chains.
func TestParseMultipleChains(t *testing.T) {
	input := `*filter
:INPUT ACCEPT [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
:DOCKER-USER - [0:0]
-A INPUT -p tcp -m tcp --dport 80 -j ACCEPT
-A INPUT -s 10.0.0.1/32 -j DROP
-A OUTPUT -p udp --dport 53 -j ACCEPT
-A DOCKER-USER -o docker0 -p tcp --dport 443 -j ACCEPT
COMMIT
`
	chains, err := Parse(input, []string{"INPUT", "OUTPUT", "DOCKER-USER"})
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}
	if len(chains) != 3 {
		t.Fatalf("expected 3 chains, got %d", len(chains))
	}

	// Verify INPUT chain
	inputChain := chains[0]
	if inputChain.Name != "INPUT" {
		t.Errorf("expected first chain INPUT, got %s", inputChain.Name)
	}
	if len(inputChain.Rules) != 2 {
		t.Errorf("expected 2 INPUT rules, got %d", len(inputChain.Rules))
	}

	// Verify first INPUT rule
	rule1 := inputChain.Rules[0]
	if rule1.Protocol != "tcp" {
		t.Errorf("expected Protocol=tcp, got %s", rule1.Protocol)
	}
	if rule1.DestPort != "80" {
		t.Errorf("expected DestPort=80, got %s", rule1.DestPort)
	}
	if rule1.Target != "ACCEPT" {
		t.Errorf("expected Target=ACCEPT, got %s", rule1.Target)
	}

	// Verify second INPUT rule
	rule2 := inputChain.Rules[1]
	if rule2.SourceIP != "10.0.0.1/32" {
		t.Errorf("expected SourceIP=10.0.0.1/32, got %s", rule2.SourceIP)
	}
	if rule2.Target != "DROP" {
		t.Errorf("expected Target=DROP, got %s", rule2.Target)
	}

	// Verify OUTPUT chain
	outputChain := chains[1]
	if outputChain.Name != "OUTPUT" {
		t.Errorf("expected second chain OUTPUT, got %s", outputChain.Name)
	}
	if len(outputChain.Rules) != 1 {
		t.Errorf("expected 1 OUTPUT rule, got %d", len(outputChain.Rules))
	}

	// Verify DOCKER-USER chain
	dockerChain := chains[2]
	if dockerChain.Name != "DOCKER-USER" {
		t.Errorf("expected third chain DOCKER-USER, got %s", dockerChain.Name)
	}
	if len(dockerChain.Rules) != 1 {
		t.Errorf("expected 1 DOCKER-USER rule, got %d", len(dockerChain.Rules))
	}
	dockerRule := dockerChain.Rules[0]
	if dockerRule.OutInterface != "docker0" {
		t.Errorf("expected OutInterface=docker0, got %s", dockerRule.OutInterface)
	}
}

// TestChainFilter tests that only requested chains are parsed.
func TestChainFilter(t *testing.T) {
	input := `*filter
:INPUT ACCEPT [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
-A INPUT -p tcp -m tcp --dport 80 -j ACCEPT
-A OUTPUT -p udp --dport 53 -j ACCEPT
-A FORWARD -j DROP
COMMIT
`
	// Only request INPUT chain
	chains, err := Parse(input, []string{"INPUT"})
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}
	if len(chains) != 1 {
		t.Fatalf("expected 1 chain (only INPUT), got %d", len(chains))
	}
	if chains[0].Name != "INPUT" {
		t.Errorf("expected chain INPUT, got %s", chains[0].Name)
	}
	if len(chains[0].Rules) != 1 {
		t.Errorf("expected 1 rule, got %d", len(chains[0].Rules))
	}
}

// TestUnsupportedModule tests that rules with unsupported modules are marked not clean.
func TestUnsupportedModule(t *testing.T) {
	tests := []struct {
		name   string
		rule   string
		module string
	}{
		{
			name:   "hashlimit module",
			rule:   "-A INPUT -m hashlimit --hashlimit-upto 10/min -j ACCEPT",
			module: "hashlimit",
		},
		{
			name:   "comment module",
			rule:   "-A INPUT -m comment --comment \"my rule\" -j ACCEPT",
			module: "comment",
		},
		{
			name:   "limit module",
			rule:   "-A INPUT -m limit --limit 10/min -j ACCEPT",
			module: "limit",
		},
		{
			name:   "recent module",
			rule:   "-A INPUT -m recent --set -j DROP",
			module: "recent",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			iptSave := "*filter\n:INPUT DROP [0:0]\n" + tt.rule + "\nCOMMIT\n"
			chains, err := Parse(iptSave, []string{"INPUT"})
			if err != nil {
				t.Fatalf("Parse returned error: %v", err)
			}

			rule := chains[0].Rules[0]
			if rule.IsClean {
				t.Errorf("expected IsClean=false for %s module, got true", tt.module)
			}
			if !strings.Contains(rule.SkipReason, "unsupported module: "+tt.module) {
				t.Errorf("expected SkipReason containing 'unsupported module: %s', got %q", tt.module, rule.SkipReason)
			}
		})
	}
}

// TestParseSourceAndDestIP tests source and destination IP extraction.
func TestParseSourceAndDestIP(t *testing.T) {
	input := `*filter
:INPUT DROP [0:0]
-A INPUT -s 192.168.1.0/24 -d 10.0.0.1/32 -p tcp --dport 22 -j ACCEPT
COMMIT
`
	chains, err := Parse(input, []string{"INPUT"})
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	rule := chains[0].Rules[0]
	if rule.SourceIP != "192.168.1.0/24" {
		t.Errorf("expected SourceIP=192.168.1.0/24, got %s", rule.SourceIP)
	}
	if rule.DestIP != "10.0.0.1/32" {
		t.Errorf("expected DestIP=10.0.0.1/32, got %s", rule.DestIP)
	}
	if rule.Protocol != "tcp" {
		t.Errorf("expected Protocol=tcp, got %s", rule.Protocol)
	}
	if rule.DestPort != "22" {
		t.Errorf("expected DestPort=22, got %s", rule.DestPort)
	}
}

// TestParseSourcePort tests source port extraction.
func TestParseSourcePort(t *testing.T) {
	input := `*filter
:OUTPUT DROP [0:0]
-A OUTPUT -p tcp --sport 8080 -j ACCEPT
COMMIT
`
	chains, err := Parse(input, []string{"OUTPUT"})
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	rule := chains[0].Rules[0]
	if rule.SourcePort != "8080" {
		t.Errorf("expected SourcePort=8080, got %s", rule.SourcePort)
	}
}

// TestParseInInterface tests input interface extraction.
func TestParseInInterface(t *testing.T) {
	input := `*filter
:INPUT DROP [0:0]
-A INPUT -i eth1 -p tcp --dport 22 -j ACCEPT
COMMIT
`
	chains, err := Parse(input, []string{"INPUT"})
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	rule := chains[0].Rules[0]
	if rule.InInterface != "eth1" {
		t.Errorf("expected InInterface=eth1, got %s", rule.InInterface)
	}
	if rule.IsClean {
		t.Errorf("expected IsClean=false for -i eth1, got true")
	}
}

// TestParseOutInterfaceNonDocker tests output interface in non-DOCKER-USER chain.
func TestParseOutInterfaceNonDocker(t *testing.T) {
	input := `*filter
:OUTPUT DROP [0:0]
-A OUTPUT -o eth0 -p tcp --dport 80 -j ACCEPT
COMMIT
`
	chains, err := Parse(input, []string{"OUTPUT"})
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	rule := chains[0].Rules[0]
	if rule.OutInterface != "eth0" {
		t.Errorf("expected OutInterface=eth0, got %s", rule.OutInterface)
	}
	if rule.IsClean {
		t.Errorf("expected IsClean=false for -o eth0 in OUTPUT, got true")
	}
	if !strings.Contains(rule.SkipReason, "interface match not supported") {
		t.Errorf("expected SkipReason containing 'interface match not supported', got %q", rule.SkipReason)
	}
}

// TestParseRawField tests that the Raw field preserves the original rule text.
func TestParseRawField(t *testing.T) {
	ruleText := "-A INPUT -p tcp -m tcp --dport 80 -j ACCEPT"
	input := "*filter\n:INPUT DROP [0:0]\n" + ruleText + "\nCOMMIT\n"
	chains, err := Parse(input, []string{"INPUT"})
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	rule := chains[0].Rules[0]
	if rule.Raw != ruleText {
		t.Errorf("expected Raw=%q, got %q", ruleText, rule.Raw)
	}
}

// TestParseRuleOrder tests that rule order is correctly assigned.
func TestParseRuleOrder(t *testing.T) {
	input := `*filter
:INPUT DROP [0:0]
-A INPUT -p tcp -m tcp --dport 80 -j ACCEPT
-A INPUT -p tcp -m tcp --dport 443 -j ACCEPT
-A INPUT -p udp --dport 53 -j ACCEPT
COMMIT
`
	chains, err := Parse(input, []string{"INPUT"})
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	if len(chains[0].Rules) != 3 {
		t.Fatalf("expected 3 rules, got %d", len(chains[0].Rules))
	}

	for i, rule := range chains[0].Rules {
		if rule.Order != i+1 {
			t.Errorf("rule %d: expected Order=%d, got %d", i, i+1, rule.Order)
		}
	}
}

// TestParseLOGTarget tests that LOG target is marked as unsupported.
func TestParseLOGTarget(t *testing.T) {
	input := `*filter
:INPUT DROP [0:0]
-A INPUT -j LOG --log-prefix "[RUNIC-DROP-I] " --log-level 4
COMMIT
`
	chains, err := Parse(input, []string{"INPUT"})
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	rule := chains[0].Rules[0]
	if rule.Target != "LOG" {
		t.Errorf("expected Target=LOG, got %s", rule.Target)
	}
	if rule.IsClean {
		t.Errorf("expected IsClean=false for LOG target, got true")
	}
	if !strings.Contains(rule.SkipReason, "unsupported target: LOG") {
		t.Errorf("expected SkipReason containing 'unsupported target: LOG', got %q", rule.SkipReason)
	}
}

// TestParseMultiplePortRanges tests rule with both sport and dport.
func TestParseMultiplePortRanges(t *testing.T) {
	input := `*filter
:INPUT DROP [0:0]
-A INPUT -p tcp --sport 1024:65535 --dport 80 -j ACCEPT
COMMIT
`
	chains, err := Parse(input, []string{"INPUT"})
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	rule := chains[0].Rules[0]
	if rule.SourcePort != "1024:65535" {
		t.Errorf("expected SourcePort=1024:65535, got %s", rule.SourcePort)
	}
	if rule.DestPort != "80" {
		t.Errorf("expected DestPort=80, got %s", rule.DestPort)
	}
}

// TestParseProtocolAll tests that protocol "all" is parsed correctly.
func TestParseProtocolAll(t *testing.T) {
	input := `*filter
:INPUT DROP [0:0]
-A INPUT -s 10.0.0.0/8 -j DROP
COMMIT
`
	chains, err := Parse(input, []string{"INPUT"})
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	rule := chains[0].Rules[0]
	if rule.Protocol != "" {
		// No -p flag means protocol is empty (matches all)
		t.Errorf("expected empty Protocol for no -p flag, got %q", rule.Protocol)
	}
	if rule.SourceIP != "10.0.0.0/8" {
		t.Errorf("expected SourceIP=10.0.0.0/8, got %s", rule.SourceIP)
	}
}

// TestParseConntrackMultipleStates tests conntrack with multiple states.
func TestParseConntrackMultipleStates(t *testing.T) {
	input := `*filter
:INPUT DROP [0:0]
-A INPUT -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
COMMIT
`
	chains, err := Parse(input, []string{"INPUT"})
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	rule := chains[0].Rules[0]
	if len(rule.ConntrackStates) != 2 {
		t.Fatalf("expected 2 conntrack states, got %d", len(rule.ConntrackStates))
	}
	if rule.ConntrackStates[0] != "NEW" {
		t.Errorf("expected first state=NEW, got %s", rule.ConntrackStates[0])
	}
	if rule.ConntrackStates[1] != "ESTABLISHED" {
		t.Errorf("expected second state=ESTABLISHED, got %s", rule.ConntrackStates[1])
	}
	// ESTABLISHED is not NEW only — should be not clean
	if rule.IsClean {
		t.Errorf("expected IsClean=false for ESTABLISHED state, got true")
	}
}

// TestDockerUserNonDocker0Interface tests that non-docker0 interface in DOCKER-USER is not clean.
func TestDockerUserNonDocker0Interface(t *testing.T) {
	input := `*filter
:DOCKER-USER - [0:0]
-A DOCKER-USER -o eth0 -p tcp --dport 80 -j ACCEPT
COMMIT
`
	chains, err := Parse(input, []string{"DOCKER-USER"})
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	rule := chains[0].Rules[0]
	if rule.IsClean {
		t.Errorf("expected IsClean=false for -o eth0 in DOCKER-USER, got true")
	}
	if !strings.Contains(rule.SkipReason, "interface match not supported") {
		t.Errorf("expected SkipReason containing 'interface match not supported', got %q", rule.SkipReason)
	}
}

// TestDockerUserInInterface tests that -i in DOCKER-USER chain is not clean.
func TestDockerUserInInterface(t *testing.T) {
	input := `*filter
:DOCKER-USER - [0:0]
-A DOCKER-USER -i eth0 -p tcp --dport 80 -j ACCEPT
COMMIT
`
	chains, err := Parse(input, []string{"DOCKER-USER"})
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	rule := chains[0].Rules[0]
	if rule.IsClean {
		t.Errorf("expected IsClean=false for -i eth0 in DOCKER-USER, got true")
	}
	if !strings.Contains(rule.SkipReason, "interface match not supported") {
		t.Errorf("expected SkipReason containing 'interface match not supported', got %q", rule.SkipReason)
	}
}

// TestStateModule tests parsing of -m state (older conntrack syntax).
func TestStateModule(t *testing.T) {
	input := `*filter
:INPUT DROP [0:0]
-A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
COMMIT
`
	chains, err := Parse(input, []string{"INPUT"})
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	rule := chains[0].Rules[0]
	// "state" module is not in supportedModules, so it should be unclean
	if rule.IsClean {
		t.Errorf("expected IsClean=false for 'state' module, got true")
	}
	if !strings.Contains(rule.SkipReason, "unsupported module: state") {
		t.Errorf("expected SkipReason containing 'unsupported module: state', got %q", rule.SkipReason)
	}
}
