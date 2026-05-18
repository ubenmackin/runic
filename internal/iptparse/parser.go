package iptparse

import (
	"fmt"
	"log"
	"strings"
)

var supportedModules = map[string]bool{
	"set":       true,
	"conntrack": true,
	"tcp":       true,
	"udp":       true,
	"icmp":      true,
	"comment":   true,
	"multiport": true,
	"pkttype":   true,
}

// parseModuleParams advances through tokens for a given module, calling the handler
// for each recognized flag within the module's parameter block. The block ends when
// a new flag starting with "-" (other than module-specific flags) or a known module
// flag is encountered. Returns the updated token index.
func parseModuleParams(tokens []string, i int, module string, handlers map[string]func([]string, *int)) int {
	for i+1 < len(tokens) {
		next := tokens[i+1]
		// Stop if next token starts a new module, jump target, or basic match flag
		if next == "-m" || next == "-j" || next == "-p" || next == "-s" || next == "-d" || next == "-i" || next == "-o" {
			break
		}
		if fn, ok := handlers[next]; ok {
			fn(tokens, &i)
		} else {
			i++
		}
	}
	return i
}

// Parse only processes chains listed in the chains parameter.
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

// moduleHandlers returns the parameter handlers for a given iptables module name.
func moduleHandlers(rule *ParsedRule, mod string) map[string]func([]string, *int) {
	switch mod {
	case "set":
		return map[string]func([]string, *int){
			"--match-set": func(ts []string, ip *int) {
				*ip += 2 // skip --match-set
				if *ip+1 < len(ts) {
					rule.IpsetMatch = &IpsetMatch{
						Name:      ts[*ip],
						Direction: ts[*ip+1],
					}
					*ip++ // skip direction (consumed in next i++)
				}
			},
		}
	case "conntrack":
		return map[string]func([]string, *int){
			"--ctstate": func(ts []string, ip *int) {
				*ip += 2 // skip --ctstate
				if *ip < len(ts) {
					states := strings.Split(ts[*ip], ",")
					for _, s := range states {
						trimmed := strings.TrimSpace(s)
						if trimmed != "" {
							rule.ConntrackStates = append(rule.ConntrackStates, trimmed)
						}
					}
				}
			},
		}
	case "tcp", "udp":
		return map[string]func([]string, *int){
			"--dport": func(ts []string, ip *int) {
				*ip += 2
				if *ip < len(ts) {
					rule.DestPort = ts[*ip]
				}
			},
			"--sport": func(ts []string, ip *int) {
				*ip += 2
				if *ip < len(ts) {
					rule.SourcePort = ts[*ip]
				}
			},
		}
	case "comment":
		return map[string]func([]string, *int){
			"--comment": func(ts []string, ip *int) {
				*ip += 2
				if *ip < len(ts) {
					rule.Comment = strings.Trim(ts[*ip], "\"")
				}
			},
		}
	case "multiport":
		return map[string]func([]string, *int){
			"--dports": func(ts []string, ip *int) {
				*ip += 2
				if *ip < len(ts) {
					rule.DestPort = ts[*ip]
				}
			},
			"--sports": func(ts []string, ip *int) {
				*ip += 2
				if *ip < len(ts) {
					rule.SourcePort = ts[*ip]
				}
			},
		}
	case "pkttype":
		return map[string]func([]string, *int){
			"--pkt-type": func(ts []string, ip *int) {
				*ip += 2
				if *ip < len(ts) {
					rule.PktType = ts[*ip]
				}
			},
		}
	default:
		return nil
	}
}

// completenessError returns a non-empty error string if the parsed rule is
// truncated or malformed — missing a target or containing no meaningful matches.
func completenessError(rule *ParsedRule) string {
	if rule.Target == "" {
		return "rule missing target (-j)"
	}
	if rule.Protocol == "" && rule.SourceIP == "" && rule.DestIP == "" &&
		rule.SourcePort == "" && rule.DestPort == "" &&
		rule.InInterface == "" && rule.OutInterface == "" &&
		rule.IpsetMatch == nil && len(rule.ConntrackStates) == 0 &&
		rule.Comment == "" && rule.PktType == "" {
		return "rule has no match criteria — possibly truncated"
	}
	return ""
}

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

				if handlers := moduleHandlers(&rule, mod); handlers != nil {
					i = parseModuleParams(tokens, i, mod, handlers)
				}
			}

		default:
			log.Printf("unrecognized token in rule %d (chain %s): %s", order, chain, tok)
		}

		i++
	}

	// Validate completeness for truncated/malformed input
	if reason := completenessError(&rule); reason != "" {
		log.Printf("incomplete rule %d (chain %s): %s — raw: %s", order, chain, reason, line)
	}

	// Determine IsRunicStandard, IsClean, and SkipReason
	classifyRule(&rule, modules)

	return rule
}

// Validate ensures the input has complete structure (non-empty, contains at least one rule line).
func Validate(iptablesSaveOutput string) error {
	if strings.TrimSpace(iptablesSaveOutput) == "" {
		return fmt.Errorf("empty iptables-save output")
	}
	lines := strings.Split(iptablesSaveOutput, "\n")
	hasChain := false
	hasRule := false
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, ":") {
			hasChain = true
		}
		if strings.HasPrefix(trimmed, "-A ") {
			hasRule = true
		}
	}
	if !hasChain {
		return fmt.Errorf("missing chain definitions in iptables-save output")
	}
	if !hasRule {
		return fmt.Errorf("no rules found in iptables-save output")
	}
	return nil
}

func classifyRule(rule *ParsedRule, modules []string) {
	// --- Detect Runic standard rules ---
	if isRunicStandard(rule) {
		rule.IsRunicStandard = true
		rule.IsClean = false
		rule.SkipReason = "runic standard rule"
		return
	}

	// --- Check for unclean conditions ---

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

	for _, state := range rule.ConntrackStates {
		if state != "NEW" {
			rule.IsClean = false
			rule.SkipReason = fmt.Sprintf("conntrack states not supported: %s", strings.Join(rule.ConntrackStates, ","))
			return
		}
	}

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

func hasConntrackState(rule *ParsedRule, state string) bool {
	for _, s := range rule.ConntrackStates {
		if s == state {
			return true
		}
	}
	return false
}
