package iptparse

import (
	"fmt"
	"strings"
)

// supportedModules lists the iptables modules we consider "clean" for Runic mapping.
var supportedModules = map[string]bool{
	"set":       true,
	"conntrack": true,
	"tcp":       true,
	"udp":       true,
	"icmp":      true,
}

// Parse parses iptables-save output into structured chain data.
// Only chains listed in the chains parameter are processed.
func Parse(iptablesSaveOutput string, chains []string) ([]ParsedChain, error) {
	chainSet := make(map[string]bool, len(chains))
	for _, c := range chains {
		chainSet[c] = true
	}

	// Collect rules per chain, preserving order
	chainRules := make(map[string][]string)
	var chainOrder []string

	lines := strings.Split(iptablesSaveOutput, "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		// Skip empty lines, comments, chain definitions, table markers, and COMMIT
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, ":") ||
			strings.HasPrefix(trimmed, "*") || trimmed == "COMMIT" {
			continue
		}

		// Only process -A (append) rules
		if !strings.HasPrefix(trimmed, "-A ") {
			continue
		}

		// Extract chain name: "-A CHAIN ..."
		parts := strings.Fields(trimmed)
		if len(parts) < 2 {
			continue
		}
		chainName := parts[1]

		if !chainSet[chainName] {
			continue
		}

		if _, exists := chainRules[chainName]; !exists {
			chainOrder = append(chainOrder, chainName)
		}
		chainRules[chainName] = append(chainRules[chainName], trimmed)
	}

	// Build result preserving chain order from input
	result := make([]ParsedChain, 0, len(chainOrder))
	for _, name := range chainOrder {
		rules := chainRules[name]
		parsedRules := make([]ParsedRule, 0, len(rules))
		for i, raw := range rules {
			rule := parseRule(raw, name, i+1)
			parsedRules = append(parsedRules, rule)
		}
		result = append(result, ParsedChain{
			Name:  name,
			Rules: parsedRules,
		})
	}

	return result, nil
}

// parseRule tokenizes and parses a single iptables rule line.
func parseRule(line, chain string, order int) ParsedRule {
	rule := ParsedRule{
		Chain:           chain,
		Order:           order,
		Raw:             line,
		ConntrackStates: []string{},
	}

	// Strip the "-A CHAIN " prefix
	rest := strings.TrimPrefix(line, fmt.Sprintf("-A %s ", chain))
	tokens := strings.Fields(rest)

	// Tokenize flags and values
	var modules []string
	i := 0
	for i < len(tokens) {
		tok := tokens[i]

		switch tok {
		case "-p":
			i++
			if i < len(tokens) {
				rule.Protocol = tokens[i]
			}

		case "-s":
			i++
			if i < len(tokens) {
				rule.SourceIP = tokens[i]
			}

		case "-d":
			i++
			if i < len(tokens) {
				rule.DestIP = tokens[i]
			}

		case "--sport":
			i++
			if i < len(tokens) {
				rule.SourcePort = tokens[i]
			}

		case "--dport":
			i++
			if i < len(tokens) {
				rule.DestPort = tokens[i]
			}

		case "-i":
			i++
			if i < len(tokens) {
				rule.InInterface = tokens[i]
			}

		case "-o":
			i++
			if i < len(tokens) {
				rule.OutInterface = tokens[i]
			}

		case "-j":
			i++
			if i < len(tokens) {
				rule.Target = tokens[i]
			}

		case "-m":
			i++
			if i < len(tokens) {
				mod := tokens[i]
				modules = append(modules, mod)

				switch mod {
				case "set":
					// Look for --match-set NAME DIR
					for i+1 < len(tokens) && tokens[i+1] != "-m" && tokens[i+1] != "-j" && tokens[i+1] != "-p" && tokens[i+1] != "-s" && tokens[i+1] != "-d" && tokens[i+1] != "-i" && tokens[i+1] != "-o" {
						if tokens[i+1] == "--match-set" {
							i += 2 // skip --match-set
							if i+1 < len(tokens) {
								ipsetName := tokens[i]
								ipsetDir := tokens[i+1]
								rule.IpsetMatch = &IpsetMatch{
									Name:      ipsetName,
									Direction: ipsetDir,
								}
								i++ // skip direction (consumed in next i++)
							}
						} else {
							i++
						}
					}

				case "conntrack":
					// Look for --ctstate
					for i+1 < len(tokens) && tokens[i+1] != "-m" && tokens[i+1] != "-j" && tokens[i+1] != "-p" && tokens[i+1] != "-s" && tokens[i+1] != "-d" && tokens[i+1] != "-i" && tokens[i+1] != "-o" {
						if tokens[i+1] == "--ctstate" {
							i += 2 // skip --ctstate
							if i < len(tokens) {
								states := strings.Split(tokens[i], ",")
								for _, s := range states {
									trimmed := strings.TrimSpace(s)
									if trimmed != "" {
										rule.ConntrackStates = append(rule.ConntrackStates, trimmed)
									}
								}
							}
						} else {
							i++
						}
					}

				case "tcp":
					// Look for --dport or --sport
					for i+1 < len(tokens) && tokens[i+1] != "-m" && tokens[i+1] != "-j" && tokens[i+1] != "-p" && tokens[i+1] != "-s" && tokens[i+1] != "-d" && tokens[i+1] != "-i" && tokens[i+1] != "-o" {
						switch tokens[i+1] {
						case "--dport":
							i += 2 // skip --dport
							if i < len(tokens) {
								rule.DestPort = tokens[i]
							}
						case "--sport":
							i += 2 // skip --sport
							if i < len(tokens) {
								rule.SourcePort = tokens[i]
							}
						default:
							i++
						}
					}

				case "udp":
					// Look for --dport or --sport
					for i+1 < len(tokens) && tokens[i+1] != "-m" && tokens[i+1] != "-j" && tokens[i+1] != "-p" && tokens[i+1] != "-s" && tokens[i+1] != "-d" && tokens[i+1] != "-i" && tokens[i+1] != "-o" {
						switch tokens[i+1] {
						case "--dport":
							i += 2 // skip --dport
							if i < len(tokens) {
								rule.DestPort = tokens[i]
							}
						case "--sport":
							i += 2 // skip --sport
							if i < len(tokens) {
								rule.SourcePort = tokens[i]
							}
						default:
							i++
						}
					}
				}
			}

		default:
			// Skip unrecognized tokens
		}

		i++
	}

	// Determine IsRunicStandard, IsClean, and SkipReason
	classifyRule(&rule, modules)

	return rule
}

// classifyRule sets IsRunicStandard, IsClean, and SkipReason on a parsed rule.
func classifyRule(rule *ParsedRule, modules []string) {
	// --- Detect Runic standard rules ---
	if isRunicStandard(rule) {
		rule.IsRunicStandard = true
		rule.IsClean = false
		rule.SkipReason = "runic standard rule"
		return
	}

	// --- Check for unclean conditions ---

	// Check interface matches
	if rule.InInterface != "" {
		// Loopback is Runic standard (caught above), any other -i is unsupported
		rule.IsClean = false
		rule.SkipReason = "interface match not supported"
		return
	}
	if rule.OutInterface != "" {
		// In DOCKER-USER chain, -o docker0 is expected
		if rule.Chain == "DOCKER-USER" && rule.OutInterface == "docker0" {
			// This is acceptable — continue checking
		} else {
			rule.IsClean = false
			rule.SkipReason = "interface match not supported"
			return
		}
	}

	// Check target
	if rule.Target != "ACCEPT" && rule.Target != "DROP" {
		if rule.Target == "" {
			// No target — not clean
			rule.IsClean = false
			rule.SkipReason = "unsupported target: "
			return
		}
		rule.IsClean = false
		rule.SkipReason = fmt.Sprintf("unsupported target: %s", rule.Target)
		return
	}

	// Check conntrack states
	for _, state := range rule.ConntrackStates {
		if state != "NEW" {
			rule.IsClean = false
			rule.SkipReason = fmt.Sprintf("conntrack states not supported: %s", strings.Join(rule.ConntrackStates, ","))
			return
		}
	}

	// Check for unsupported modules
	for _, mod := range modules {
		if !supportedModules[mod] {
			rule.IsClean = false
			rule.SkipReason = fmt.Sprintf("unsupported module: %s", mod)
			return
		}
	}

	// All checks passed — rule is clean
	rule.IsClean = true
	rule.SkipReason = ""
}

// isRunicStandard detects rules that are Runic-managed standard rules.
func isRunicStandard(rule *ParsedRule) bool {
	// Loopback: -i lo or -o lo with ACCEPT target
	if rule.Target == "ACCEPT" && (rule.InInterface == "lo" || rule.OutInterface == "lo") {
		return true
	}

	// ICMP RELATED: -p icmp -m conntrack --ctstate RELATED with ACCEPT
	if rule.Protocol == "icmp" && rule.Target == "ACCEPT" && hasConntrackState(rule, "RELATED") {
		return true
	}

	// ESTABLISHED,RELATED ACCEPT: standard conntrack state tracking rule
	if rule.Target == "ACCEPT" && hasConntrackState(rule, "ESTABLISHED") && hasConntrackState(rule, "RELATED") {
		return true
	}

	// INVALID drop: -m conntrack --ctstate INVALID -j DROP
	if rule.Target == "DROP" && hasConntrackState(rule, "INVALID") {
		return true
	}

	// Any rule referencing runic_ prefixed ipsets (compiler-generated)
	if rule.IpsetMatch != nil && strings.HasPrefix(rule.IpsetMatch.Name, "runic_") {
		return true
	}

	return false
}

// hasConntrackState checks if a rule has a specific conntrack state.
func hasConntrackState(rule *ParsedRule, state string) bool {
	for _, s := range rule.ConntrackStates {
		if s == state {
			return true
		}
	}
	return false
}
