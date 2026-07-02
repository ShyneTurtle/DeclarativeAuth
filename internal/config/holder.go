package config

import (
	"sync/atomic"

	"declarativeauth/internal/identity"
)

// SnapshotHolder is a process-wide, lock-free holder for the current identity
// Snapshot. Readers call Get(); the watcher/loader call Set() on every
// successful reload.
type SnapshotHolder struct {
	ptr atomic.Pointer[identity.Snapshot]
}

// Get returns the current snapshot. Safe for concurrent use.
func (h *SnapshotHolder) Get() *identity.Snapshot {
	return h.ptr.Load()
}

// Set atomically swaps in a new snapshot.
func (h *SnapshotHolder) Set(s *identity.Snapshot) {
	h.ptr.Store(s)
}
