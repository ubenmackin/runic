// Package apply provides the application applier.
package apply

import (
	"strings"
	"testing"
)

// Duplicate create lines used to replace the earlier definition and duplicate
// the order entry, producing incorrect membership instead of a hard error.
func TestParseIpsetDefs_RejectsDuplicateCreates(t *testing.T) {
	section := `create runic_group_office hash:net family inet
add runic_group_office 10.0.0.1/32
create runic_group_office hash:net family inet
add runic_group_office 10.0.0.2/32`

	defs, err := parseIpsetDefs(section)
	if err == nil {
		t.Fatal("expected duplicate create error, got nil")
	}
	if defs != nil {
		t.Fatalf("expected nil definitions on duplicate create, got %v", defs)
	}
	if !strings.Contains(err.Error(), "duplicate create") {
		t.Fatalf("expected duplicate create error, got %v", err)
	}
}
