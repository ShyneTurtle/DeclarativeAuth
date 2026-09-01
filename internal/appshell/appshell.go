// Package appshell embeds the single shared page shell (tab bar + card)
// used by both the account page (internal/web) and every /admin page
// (internal/admin), so there is exactly one file to edit for both instead
// of two independently-maintained copies that inevitably drift apart.
package appshell

import "embed"

//go:embed shell.html
var FS embed.FS
