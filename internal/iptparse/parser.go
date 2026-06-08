package iptparse

import (
	"fmt"
	"strings"

	"runic/internal/common/log"
)

// supportedModules is the set of iptables module names that the parser is
// willing to consume. Modules outside this set cause the rule to be marked
// unclean (see classifyRule). Stored as map[string]struct{} to make the
// "presence-only" intent explicit and save a byte per entry.
var supportedModules = map[string]struct{}{
	"set":       {},
	"conntrack": {},
	"tcp":       {},
	"udp":       {},
	"icmp":      {},
	"comment":   {},
	"multiport": {},
	"pkttype":   {},
}

// parseModuleParams advances through tokens for a given module, calling the handler
// for each recognized flag within the module's parameter block. The block ends when
// a new flag starting with "-" (other than module-specific flags) or a known module
// flag is encountered. Returns the updated token index.
//
// Each handler has signature func(ts []string, i int) int: it consumes the tokens
// it needs and returns the new index. This makes the side-effect-free nature of
// parsing explicit (the caller owns `i`) and avoids the previous pattern of
// taking a *int and reassigning through it.
func parseModuleParams(tokens []string, i int, module string, handlers map[string]func([]string, int) int) int {
	for i+1 < len(tokens) {
		next := tokens[i+1]
		// Stop if next token starts a new module, jump target, or basic match flag
		if next == "-m" || next == "-j" || next == "-p" || next == "-s" || next == "-d" || next == "-i" || next == "-o" {
			break
		}
		if fn, ok := handlers[next]; ok {
			i = fn(tokens, i)
		} else {
			i++
		}
	}
	return i
}

// Parse only processes chains listed in the chains parameter.
//
// The parser is lossless: parse errors and warnings are collected into
// rule.Warnings and chain.Warnings rather than returned as the function
// error. This preserves the historical contract that Parse returns
// ([]ParsedChain, nil) for any input that is structurally valid (i.e.,
// contains a *filter or similar table marker plus at least one -A rule).
func Parse(iptablesSaveOutput string, chains []string) ([]ParsedChain, error) {
	chainSet := make(map[string]struct{}, len(chains))
	for _, c := range chains {
		chainSet[c] = struct{}{}
	}

	// Collect rules per chain, preserving order
	chainRules := make(map[string][]string)
	chainWarnings := make(map[string][]string)
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

		if _, ok := chainSet[chainName]; !ok {
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
			Name:     name,
			Rules:    parsedRules,
			Warnings: chainWarnings[name],
		})
	}

	return result, nil
}

// moduleHandlers returns the parameter handlers for a given iptables module name.
// Each handler signature is func(ts []string, i int) int — it consumes the tokens
// it needs (the flag, plus any value) and returns the new index. The caller
// (parseModuleParams) stores the result and continues.
func moduleHandlers(rule *ParsedRule, mod string) map[string]func([]string, int) int {
	switch mod {
	case "set":
		return map[string]func([]string, int) int{
			"--match-set": func(ts []string, i int) int {
				i += 2 // skip --match-set
				if i+1 < len(ts) {
					rule.IpsetMatch = &IpsetMatch{
						Name:      ts[i],
						Direction: ts[i+1],
					}
					i++ // skip direction; the +1 in the outer loop will skip the value
				}
				return i
			},
		}
	case "conntrack":
		return map[string]func([]string, int) int{
			"--ctstate": func(ts []string, i int) int {
				i += 2 // skip --ctstate
				if i < len(ts) {
					states := strings.Split(ts[i], ",")
					for _, s := range states {
						trimmed := strings.TrimSpace(s)
						if trimmed != "" {
							rule.ConntrackStates = append(rule.ConntrackStates, trimmed)
						}
					}
				}
				return i
			},
		}
	case "tcp", "udp":
		return map[string]func([]string, int) int{
			"--dport": func(ts []string, i int) int {
				i += 2
				if i < len(ts) {
					rule.DestPort = ts[i]
				}
				return i
			},
			"--sport": func(ts []string, i int) int {
				i += 2
				if i < len(ts) {
					rule.SourcePort = ts[i]
				}
				return i
			},
		}
	case "comment":
		// Note: --comment does not handle embedded spaces. The value is a single
		// token in iptables-save output even if the original rule used quoted
		// spaces, so spaces will be silently lost. A quoting-aware parser would
		// need to re-tokenize the raw line rather than rely on strings.Fields.
		return map[string]func([]string, int) int{
			"--comment": func(ts []string, i int) int {
				i += 2
				if i < len(ts) {
					rule.Comment = strings.Trim(ts[i], "\"")
				}
				return i
			},
		}
	case "multiport":
		return map[string]func([]string, int) int{
			"--dports": func(ts []string, i int) int {
				i += 2
				if i < len(ts) {
					rule.DestPort = ts[i]
				}
				return i
			},
			"--sports": func(ts []string, i int) int {
				i += 2
				if i < len(ts) {
					rule.SourcePort = ts[i]
				}
				return i
			},
		}
	case "pkttype":
		return map[string]func([]string, int) int{
			"--pkt-type": func(ts []string, i int) int {
				i += 2
				if i < len(ts) {
					rule.PktType = ts[i]
				}
				return i
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
		Warnings:        []string{},
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
			// Unknown tokens are recorded as warnings instead of being silently
			// dropped. They are also still emitted to the structured log so
			// operators monitoring the agent can spot unexpected iptables
			// extensions in the wild.
			warning := fmt.Sprintf("unrecognized token: %s", tok)
			rule.Warnings = append(rule.Warnings, warning)
			log.Warn("iptparse: unrecognized token", "rule_order", order, "chain", chain, "token", tok)
		}

		i++
	}

	// Validate completeness for truncated/malformed input. We record the
	// reason as a warning AND emit a structured log entry — the warning so
	// the importer UI can surface it, the log for offline debugging.
	if reason := completenessError(&rule); reason != "" {
		rule.Warnings = append(rule.Warnings, reason)
		log.Warn("iptparse: incomplete rule", "rule_order", order, "chain", chain, "reason", reason, "raw", line)
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
		if _, ok := supportedModules[mod]; !ok {
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
