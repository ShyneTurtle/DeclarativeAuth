package tls

import (
	"log/slog"
	"time"

	"github.com/fsnotify/fsnotify"
)

// WatchAndReload watches the parent directory of certFile (to catch
// cert-manager/K8s Secret volume atomic symlink-swaps, same pattern as
// internal/config/watcher.go) and hot-reloads the certificate on change.
// Runs until stop is closed; intended to run in its own goroutine.
func (s *Source) WatchAndReload(dir, certFile, keyFile string, logger *slog.Logger, stop <-chan struct{}) error {
	w, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}
	defer w.Close()
	if err := w.Add(dir); err != nil {
		return err
	}

	var timer *time.Timer
	debounced := make(chan struct{}, 1)
	const debounce = 500 * time.Millisecond

	for {
		select {
		case <-stop:
			return nil
		case _, ok := <-w.Events:
			if !ok {
				return nil
			}
			if timer == nil {
				timer = time.AfterFunc(debounce, func() {
					select {
					case debounced <- struct{}{}:
					default:
					}
				})
			} else {
				timer.Reset(debounce)
			}
		case err, ok := <-w.Errors:
			if !ok {
				return nil
			}
			if logger != nil {
				logger.Error("tls watcher error", "component", "tls", "error", err)
			}
		case <-debounced:
			if err := s.Reload(certFile, keyFile); err != nil {
				if logger != nil {
					logger.Error("tls cert reload rejected, keeping last-good cert", "component", "tls", "error", err)
				}
				continue
			}
			if logger != nil {
				logger.Info("tls cert reloaded", "component", "tls")
			}
		}
	}
}
