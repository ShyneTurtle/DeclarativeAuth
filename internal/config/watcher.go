package config

import (
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"declarativeauth/internal/identity"

	"github.com/fsnotify/fsnotify"
)

// ReloadResult is passed to the watcher's OnReload callback after each
// successful reload.
type ReloadResult struct {
	Diff SnapshotDiff
}

// Watcher watches identityPath's parent directory for changes (to catch
// Kubernetes ConfigMap ..data symlink swaps) and hot-reloads the identity
// Snapshot into holder on any change, debounced and validated.
type Watcher struct {
	IdentityPath string
	Debounce     time.Duration
	Holder       *SnapshotHolder
	Logger       *slog.Logger
	OnReload     func(ReloadResult)

	metrics WatcherMetrics
}

// WatcherMetrics is an optional set of callbacks the watcher invokes on
// reload outcomes, so internal/metrics can wire up Prometheus counters
// without config depending on the metrics package.
type WatcherMetrics struct {
	ReloadSuccess func()
	ReloadFailure func()
	ChangeCount   func(kind string, n int)
}

// SetMetrics wires optional Prometheus counters into the watcher.
func (w *Watcher) SetMetrics(m WatcherMetrics) {
	w.metrics = m
}

// LoadInitial performs the first, non-hot-reload load. Failure here is fatal
// to the caller (no last-good snapshot to fall back to).
func (w *Watcher) LoadInitial() error {
	snap, err := LoadIdentity(w.IdentityPath)
	if err != nil {
		return err
	}
	w.Holder.Set(snap)
	if w.Logger != nil {
		w.Logger.Info("identity config loaded",
			"component", "config",
			"users", len(snap.Users),
			"groups", len(snap.Groups),
			"oidc_clients", len(snap.OIDCClients),
		)
	}
	w.warnIfNoUsers(snap)
	return nil
}

// warnIfNoUsers logs a warning when a snapshot declares zero users -- not a
// load error (a fresh/bootstrapping deployment legitimately has none yet),
// but nobody can log in until at least one exists, so it's worth flagging
// loudly rather than only discovering it via failed logins.
func (w *Watcher) warnIfNoUsers(snap *identity.Snapshot) {
	if w.Logger != nil && len(snap.Users) == 0 {
		w.Logger.Warn("identity config declares zero users -- no one can log in until at least one is declared",
			"component", "config")
	}
}

// Run watches for changes and hot-reloads until ctx-like stop via close of
// done channel; blocks, intended to run in its own goroutine.
//
// fsnotify has no native recursive-watch support, so every subdirectory
// under IdentityPath is added individually (mirroring yamlFilesUnder's
// dot-directory skip, for the same Kubernetes ConfigMap/Secret-internals
// reason) -- this matters not just for arbitrarily nested identity YAML,
// but for a passwordHashFile secret mounted under a subdirectory of
// IdentityPath: without watching that subdirectory too, rotating the
// secret would silently never trigger a reload. A directory created after
// startup is picked up as its own Create event and added on the fly.
func (w *Watcher) Run(stop <-chan struct{}) error {
	fsw, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}
	defer fsw.Close()

	if err := addRecursive(fsw, w.IdentityPath); err != nil {
		return err
	}

	var timer *time.Timer
	debounced := make(chan struct{}, 1)

	for {
		select {
		case <-stop:
			return nil
		case ev, ok := <-fsw.Events:
			if !ok {
				return nil
			}
			if ev.Has(fsnotify.Create) {
				if info, err := os.Stat(ev.Name); err == nil && info.IsDir() && !strings.HasPrefix(filepath.Base(ev.Name), ".") {
					if err := addRecursive(fsw, ev.Name); err != nil && w.Logger != nil {
						w.Logger.Error("failed to watch new identity subdirectory", "component", "config", "path", ev.Name, "error", err)
					}
				}
			}
			if timer == nil {
				timer = time.AfterFunc(w.Debounce, func() {
					select {
					case debounced <- struct{}{}:
					default:
					}
				})
			} else {
				timer.Reset(w.Debounce)
			}
		case err, ok := <-fsw.Errors:
			if !ok {
				return nil
			}
			if w.Logger != nil {
				w.Logger.Error("config watcher error", "component", "config", "error", err)
			}
		case <-debounced:
			w.reload()
		}
	}
}

// addRecursive adds root and every non-dot subdirectory under it to fsw.
func addRecursive(fsw *fsnotify.Watcher, root string) error {
	return filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			return nil
		}
		if path != root && strings.HasPrefix(d.Name(), ".") {
			return filepath.SkipDir
		}
		return fsw.Add(path)
	})
}

func (w *Watcher) reload() {
	old := w.Holder.Get()
	snap, err := LoadIdentity(w.IdentityPath)
	if err != nil {
		if w.Logger != nil {
			w.Logger.Error("config reload rejected, keeping last-good snapshot",
				"component", "config", "error", err)
		}
		if w.metrics.ReloadFailure != nil {
			w.metrics.ReloadFailure()
		}
		return
	}
	if old != nil && snap.SourceHash == old.SourceHash {
		return
	}
	diff := DiffSnapshots(old, snap)
	w.Holder.Set(snap)

	if w.metrics.ReloadSuccess != nil {
		w.metrics.ReloadSuccess()
	}
	if w.metrics.ChangeCount != nil {
		for kind, n := range diff.counts() {
			if n > 0 {
				w.metrics.ChangeCount(kind, n)
			}
		}
	}
	if w.Logger != nil {
		w.Logger.Info("identity config reloaded",
			"component", "config",
			"users_added", diff.UsersAdded,
			"users_removed", diff.UsersRemoved,
			"users_modified", diff.UsersModified,
			"groups_added", diff.GroupsAdded,
			"groups_removed", diff.GroupsRemoved,
			"groups_modified", diff.GroupsModified,
			"oidc_clients_added", diff.OIDCClientsAdded,
			"oidc_clients_removed", diff.OIDCClientsRemoved,
			"oidc_clients_modified", diff.OIDCClientsModified,
		)
	}
	w.warnIfNoUsers(snap)
	if w.OnReload != nil {
		w.OnReload(ReloadResult{Diff: diff})
	}
}

func (d SnapshotDiff) counts() map[string]int {
	return map[string]int{
		"user_added":           len(d.UsersAdded),
		"user_removed":         len(d.UsersRemoved),
		"user_modified":        len(d.UsersModified),
		"group_added":          len(d.GroupsAdded),
		"group_removed":        len(d.GroupsRemoved),
		"group_modified":       len(d.GroupsModified),
		"oidc_client_added":    len(d.OIDCClientsAdded),
		"oidc_client_removed":  len(d.OIDCClientsRemoved),
		"oidc_client_modified": len(d.OIDCClientsModified),
	}
}
