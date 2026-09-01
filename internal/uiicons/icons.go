// Package uiicons is a tiny, dependency-free inline-SVG icon set shared by
// the web and admin templates. No icon font or external SVG sprite is
// vendored -- each icon is a short hand-authored path so the binary and
// page weight stay effectively unchanged while giving the previously
// text-only UI some visual structure.
package uiicons

import "html/template"

const svgHeader = `<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false">`

var icons = map[string]string{
	"dashboard": `<rect x="3" y="3" width="7" height="9" rx="1.5"/><rect x="14" y="3" width="7" height="5" rx="1.5"/><rect x="14" y="12" width="7" height="9" rx="1.5"/><rect x="3" y="16" width="7" height="5" rx="1.5"/>`,
	"mail":      `<rect x="3" y="5" width="18" height="14" rx="2"/><path d="M3 7l9 6 9-6"/>`,
	"graph":     `<circle cx="6" cy="18" r="2.5"/><circle cx="18" cy="18" r="2.5"/><circle cx="12" cy="5" r="2.5"/><path d="M12 7.5V13M12 13L8 15.5M12 13l4 2.5"/>`,
	"file":      `<path d="M7 3h7l5 5v13a1 1 0 0 1-1 1H7a1 1 0 0 1-1-1V4a1 1 0 0 1 1-1z"/><path d="M14 3v5h5"/>`,
	"logout":    `<path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><path d="M16 17l5-5-5-5"/><path d="M21 12H9"/>`,
	// A horizontal key silhouette (round bow on the left, shaft + teeth on
	// the right) -- an earlier diagonal version read as the Mars/male
	// gender glyph rather than a key, so this is deliberately unambiguous.
	"key":     `<circle cx="7" cy="12" r="3.5"/><path d="M10.3 12H20M14.5 12v3M18 12v2.5"/>`,
	"shield":  `<path d="M12 3l7 3v6c0 4.5-3 8-7 9-4-1-7-4.5-7-9V6l7-3z"/><path d="M9.5 12l1.8 1.8L14.5 10"/>`,
	"user":    `<circle cx="12" cy="8" r="3.5"/><path d="M4.5 20c1.4-3.8 4.4-6 7.5-6s6.1 2.2 7.5 6"/>`,
	"warning": `<path d="M12 3l10 18H2L12 3z"/><path d="M12 10v4"/><path d="M12 17.5v.01"/>`,
	"check":   `<path d="M4 12.5l5.5 5.5L20 6.5"/>`,
	"send":    `<path d="M4 11l16-7-6.5 16-3-6.5L4 11z"/>`,
	"trash":   `<path d="M4 7h16"/><path d="M9 7V4h6v3"/><path d="M6 7l1 13h10l1-13"/>`,
	"plus":    `<path d="M12 5v14M5 12h14"/>`,
	"close":   `<path d="M6 6l12 12M18 6L6 18"/>`,
	// Floppy disk -- the conventional "save" glyph, distinct from the
	// generic checkmark ("check") used for simpler confirm actions.
	"save": `<path d="M5 3h11l3 3v13a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V4a1 1 0 0 1 1-1z"/><path d="M8 3v5h6V3"/><path d="M8 21v-6h8v6"/>`,
	// Arrow into a tray -- distinct from "save" (which is for writing this
	// server's own state) since downloading is retrieving a copy instead.
	"download": `<path d="M12 3v10"/><path d="M8 9l4 4 4-4"/><path d="M4 17v2a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-2"/>`,
	// A gear/cog for the Admin tab -- distinct from "dashboard" (a grid of
	// panels), since this is specifically about settings/administration
	// rather than an overview. The teeth start exactly on the outer
	// circle's edge rather than floating off of it with a gap, which
	// matters: a gap there is what makes a ring-plus-radiating-lines shape
	// read as a sun instead of a gear.
	"settings": `<circle cx="12" cy="12" r="7"/><circle cx="12" cy="12" r="2.5"/><path d="M12 3v2M12 19v2M21 12h-2M5 12H3M18.4 5.6l-1.4 1.4M7 17l-1.4 1.4M18.4 18.4l-1.4-1.4M7 7L5.6 5.6"/>`,
}

// SVG returns the named icon as trusted inline HTML, or nothing if the name
// is unknown (fails quiet, since a missing icon shouldn't break a page).
func SVG(name string) template.HTML {
	body, ok := icons[name]
	if !ok {
		return ""
	}
	return template.HTML(svgHeader + body + `</svg>`)
}

// FuncMap is the html/template.FuncMap entry to expose SVG as {{icon "name"}}.
func FuncMap() map[string]any {
	return map[string]any{"icon": SVG}
}
