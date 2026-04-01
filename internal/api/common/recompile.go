package common

import (
	"context"
	"time"

	runiclog "runic/internal/common/log"
	"runic/internal/engine"
)

// AsyncRecompilePeers spawns a background goroutine to recompile bundles for the given peer IDs.
// It uses a 5-minute timeout context.
func AsyncRecompilePeers(compiler *engine.Compiler, peerIDs []int) {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		for _, pid := range peerIDs {
			if _, err := compiler.CompileAndStore(ctx, pid); err != nil {
				runiclog.ErrorContext(ctx, "async compile and store failed", "peer_id", pid, "error", err)
			}
		}
	}()
}

// AsyncRecompileGroup spawns a background goroutine to recompile bundles for peers affected by a group change.
// It uses a 5-minute timeout context.
func AsyncRecompileGroup(compiler *engine.Compiler, groupID int) {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		if err := compiler.RecompileAffectedPeers(ctx, groupID); err != nil {
			runiclog.ErrorContext(ctx, "async recompile affected peers failed", "group_id", groupID, "error", err)
		}
	}()
}
