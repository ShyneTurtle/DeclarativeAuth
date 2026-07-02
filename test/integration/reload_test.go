//go:build integration

package integration

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"declarativeauth/internal/config"
)

func writeFixtureFiles(t *testing.T, dir, groupsYAML, usersYAML string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "groups.yaml"), []byte(groupsYAML), 0o644); err != nil {
		t.Fatalf("write groups.yaml: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "users.yaml"), []byte(usersYAML), 0o644); err != nil {
		t.Fatalf("write users.yaml: %v", err)
	}
}

const baseGroups = `apiVersion: declarativeauth.io/v1
kind: GroupList
groups:
  - name: engineering
    memberOfGroups: []
`

const baseUsers = `apiVersion: declarativeauth.io/v1
kind: UserList
users:
  - username: alice
    email: alice@example.com
    enabled: true
    memberOfGroups: [engineering]
`

const updatedUsers = `apiVersion: declarativeauth.io/v1
kind: UserList
users:
  - username: alice
    email: alice@example.com
    enabled: true
    memberOfGroups: [engineering]
  - username: bob
    email: bob@example.com
    enabled: true
    memberOfGroups: [engineering]
`

const invalidUsers = `apiVersion: declarativeauth.io/v1
kind: UserList
users:
  - username: alice
    email: alice@example.com
    enabled: true
    memberOfGroups: [ghost-group]
`

func TestReload_PicksUpChangesAndRejectsInvalid(t *testing.T) {
	dir := t.TempDir()
	writeFixtureFiles(t, dir, baseGroups, baseUsers)

	holder := &config.SnapshotHolder{}
	w := &config.Watcher{
		IdentityPath: dir,
		Debounce:     50 * time.Millisecond,
		Holder:       holder,
	}
	if err := w.LoadInitial(); err != nil {
		t.Fatalf("initial load: %v", err)
	}
	if len(holder.Get().Users) != 1 {
		t.Fatalf("expected 1 user initially, got %d", len(holder.Get().Users))
	}

	stop := make(chan struct{})
	t.Cleanup(func() { close(stop) })
	go w.Run(stop)
	time.Sleep(100 * time.Millisecond) // let the watcher establish itself

	// Valid change: bob added.
	writeFixtureFiles(t, dir, baseGroups, updatedUsers)
	waitFor(t, func() bool { return len(holder.Get().Users) == 2 }, 2*time.Second)

	// Invalid change: dangling group ref -> reload must be rejected, last-good kept.
	writeFixtureFiles(t, dir, baseGroups, invalidUsers)
	time.Sleep(300 * time.Millisecond)
	if len(holder.Get().Users) != 2 {
		t.Fatalf("expected last-good snapshot (2 users) to be retained after invalid reload, got %d", len(holder.Get().Users))
	}

	// Recovery: valid content again should apply.
	writeFixtureFiles(t, dir, baseGroups, baseUsers)
	waitFor(t, func() bool { return len(holder.Get().Users) == 1 }, 2*time.Second)
}

func waitFor(t *testing.T, cond func() bool, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("condition not met before timeout")
}
