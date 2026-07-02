package admin

import (
	"fmt"
	"html/template"
	"net/http"
	"sort"

	"declarativeauth/internal/identity"
)

type graphData struct {
	pageData
	GroupCount int
	EdgeCount  int
	SVG        template.HTML
}

func (h *Handlers) handleGraph(w http.ResponseWriter, r *http.Request, username string) {
	snap := h.Snapshot()
	edgeCount := 0
	for _, g := range snap.Groups {
		edgeCount += len(g.MemberOfGroups)
	}
	render(w, graphTmpl, graphData{
		pageData:   pageData{Title: "Group graph", ConfigEditorEnabled: h.ConfigEditorEnabled},
		GroupCount: len(snap.Groups),
		EdgeCount:  edgeCount,
		SVG:        template.HTML(renderGroupGraphSVG(snap.Groups)),
	})
}

// renderGroupGraphSVG lays groups out in levels by inheritance depth (root
// groups with no parents at the top, deeper members below) and renders a
// plain, dependency-free inline SVG -- no client-side graph library is
// vendored, keeping the admin page (and the binary) lightweight and fully
// offline-capable.
func renderGroupGraphSVG(groups map[string]identity.Group) string {
	levels := map[string]int{}
	var level func(name string, seen map[string]bool) int
	level = func(name string, seen map[string]bool) int {
		if v, ok := levels[name]; ok {
			return v
		}
		if seen[name] { // defensive: cycles are rejected at config-load time
			return 0
		}
		seen[name] = true
		g, ok := groups[name]
		if !ok || len(g.MemberOfGroups) == 0 {
			levels[name] = 0
			return 0
		}
		max := 0
		for _, p := range g.MemberOfGroups {
			if lv := level(p, seen); lv > max {
				max = lv
			}
		}
		levels[name] = max + 1
		return max + 1
	}

	names := make([]string, 0, len(groups))
	for n := range groups {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		level(n, map[string]bool{})
	}

	byLevel := map[int][]string{}
	maxLevel := 0
	for _, n := range names {
		lv := levels[n]
		byLevel[lv] = append(byLevel[lv], n)
		if lv > maxLevel {
			maxLevel = lv
		}
	}

	const colWidth, rowHeight, nodeW, nodeH = 180, 90, 140, 40
	pos := map[string][2]int{}
	width := colWidth
	for lv := 0; lv <= maxLevel; lv++ {
		row := byLevel[lv]
		sort.Strings(row)
		for i, n := range row {
			x := 40 + i*colWidth
			y := 40 + lv*rowHeight
			pos[n] = [2]int{x, y}
			if x+colWidth > width {
				width = x + colWidth
			}
		}
	}
	height := 80 + (maxLevel+1)*rowHeight

	svg := fmt.Sprintf(`<svg width="%d" height="%d" xmlns="http://www.w3.org/2000/svg">`, width, height)
	svg += `<defs><marker id="arrow" markerWidth="8" markerHeight="8" refX="8" refY="4" orient="auto"><path class="group-edge-arrow" d="M0,0 L8,4 L0,8 z"/></marker></defs>`

	for _, n := range names {
		g := groups[n]
		p := pos[n]
		for _, parent := range g.MemberOfGroups {
			pp, ok := pos[parent]
			if !ok {
				continue
			}
			x1, y1 := p[0]+nodeW/2, p[1]+nodeH
			x2, y2 := pp[0]+nodeW/2, pp[1]
			svg += fmt.Sprintf(`<line class="group-edge" x1="%d" y1="%d" x2="%d" y2="%d"/>`, x1, y1, x2, y2)
		}
	}
	for _, n := range names {
		p := pos[n]
		svg += fmt.Sprintf(`<rect class="group-node" x="%d" y="%d" width="%d" height="%d" rx="6"/>`, p[0], p[1], nodeW, nodeH)
		svg += fmt.Sprintf(`<text class="group-label" x="%d" y="%d" text-anchor="middle">%s</text>`,
			p[0]+nodeW/2, p[1]+nodeH/2+4, template.HTMLEscapeString(n))
	}
	svg += `</svg>`
	return svg
}
