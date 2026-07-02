package config

import (
	"encoding/json"
	"fmt"
	"time"
)

// Duration wraps time.Duration so it unmarshals from human-readable strings
// (e.g. "500ms", "24h") in YAML/JSON config, since sigs.k8s.io/yaml routes
// through encoding/json, which otherwise only accepts integer nanoseconds.
type Duration time.Duration

// UnmarshalJSON parses a duration string via time.ParseDuration.
func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return fmt.Errorf("duration must be a string like \"500ms\": %w", err)
	}
	parsed, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	*d = Duration(parsed)
	return nil
}

// MarshalJSON renders the duration back to its string form.
func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Duration(d).String())
}

// Std returns the underlying time.Duration.
func (d Duration) Std() time.Duration {
	return time.Duration(d)
}
