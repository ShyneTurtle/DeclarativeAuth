package admin

import (
	"encoding/json"
	"fmt"
	"html/template"
	"math"
	"sort"

	"declarativeauth/internal/identity"
)

// graphViewData is the subset of adminHomeData the group graph section
// needs; computeGraphData is shared by handleAdmin (the merged email
// test + graph page) so there's exactly one place that turns a snapshot
// into graph SVG + counts.
type graphViewData struct {
	GroupCount int
	EdgeCount  int
	SVG        template.HTML
	// DetailsJSON is every group's computeGroupDetails, keyed by name, as a
	// single embedded JSON blob -- see admin_home.html's click handler.
	// Embedding it avoids a second request just to inspect a group that's
	// already fully described by the snapshot the page was rendered from.
	DetailsJSON template.JS
}

func computeGraphData(snap *identity.Snapshot) graphViewData {
	edgeCount := 0
	for _, g := range snap.Groups {
		edgeCount += len(g.MemberOfGroups)
	}
	memberCounts := make(map[string]int, len(snap.Groups))
	for name := range snap.Groups {
		memberCounts[name] = len(snap.FlattenedMembers[name])
	}
	detailsJSON, _ := json.Marshal(computeGroupDetails(snap))
	return graphViewData{
		GroupCount:  len(snap.Groups),
		EdgeCount:   edgeCount,
		SVG:         template.HTML(renderGroupGraphSVG(snap.Groups, memberCounts)),
		DetailsJSON: template.JS(detailsJSON),
	}
}

type graphNode struct {
	name        string
	x, y        float64
	w, h        float64
	memberCount int
	requireMFA  bool
	// degree is direct parents + direct children -- used as this node's
	// "importance" for the centering gravity in forceDirectedLayout (see
	// there) so well-connected hub groups end up nearer the middle of the
	// graph and peripheral ones settle further out, rather than everything
	// being laid out in strict top-to-bottom hierarchy rows.
	degree int
}

// renderGroupGraphSVG lays groups out with a 2D force-directed (Fruchterman-
// Reingold style) simulation and renders a plain, dependency-free inline
// SVG -- no client-side graph library is vendored, keeping the admin page
// (and the binary) lightweight and fully offline-capable.
//
// This is deliberately NOT a layered top-to-bottom hierarchy diagram (an
// earlier version fixed every node's y by root/leaf depth, Sugiyama-style).
// That produced a graph that visibly read as a stack of rows, and rows
// don't actually help avoid collisions or crossings: a row with many
// members still has to cram them all into one horizontal band regardless
// of how much vertical room is sitting unused above and below it. Letting
// both axes move freely lets crowded areas actually spread into whichever
// direction has space, and a more central rank/gravity per node (see
// forceDirectedLayout) gives well-connected groups a stable center to
// radiate around instead of forcing an artificial top/bottom reading
// order. Edges are still routed to curve around anything in the way (see
// routeEdges) and drawn *after* every node, so an arrow is never hidden
// behind a card it merely passes close to.
func renderGroupGraphSVG(groups map[string]identity.Group, memberCounts map[string]int) string {
	names := make([]string, 0, len(groups))
	for n := range groups {
		names = append(names, n)
	}
	sort.Strings(names)
	if len(names) == 0 {
		return `<svg width="100" height="60" xmlns="http://www.w3.org/2000/svg"></svg>`
	}

	children := map[string][]string{} // group -> direct child groups
	for name, g := range groups {
		for _, parent := range g.MemberOfGroups {
			children[parent] = append(children[parent], name)
		}
	}

	nodes := make(map[string]*graphNode, len(names))
	// Taller than a single line of text to fit the member-count line
	// underneath the group name (see the second <text> below).
	const nodeH = 56
	for _, n := range names {
		w := float64(len(n))*7.5 + 48
		if w < 120 {
			w = 120
		}
		nodes[n] = &graphNode{
			name:        n,
			w:           w,
			h:           nodeH,
			memberCount: memberCounts[n],
			requireMFA:  groups[n].RequireMFA,
			degree:      len(groups[n].MemberOfGroups) + len(children[n]),
		}
	}

	radius := seedCircular(nodes, names)
	forceDirectedLayout(nodes, names, groups, radius)
	resolveOverlaps(nodes, names)

	minX, minY, maxX, maxY := boundingBox(nodes)
	const margin = 40
	offX, offY := margin-minX, margin-minY
	width := int(math.Ceil(maxX-minX)) + 2*margin
	height := int(math.Ceil(maxY-minY)) + 2*margin

	// Bake the margin translation into the node positions themselves,
	// once, before either loop below reads them -- both the rects and the
	// edges (which clip to each node's border via its x/y/w/h) need to
	// agree on where a node actually is. Applying the offset only when
	// drawing rects (and not when computing edges from the same nodes) is
	// exactly what previously made every arrow land tens of pixels off
	// from the node it's supposed to touch.
	for _, n := range names {
		nodes[n].x += offX
		nodes[n].y += offY
	}

	var svg fmtBuilder
	svg.printf(`<svg width="%d" height="%d" viewBox="0 0 %d %d" xmlns="http://www.w3.org/2000/svg">`, width, height, width, height)
	// Two markers, not one: hovering a node (see admin_home.html's JS)
	// swaps its direct edges' marker-end to "arrow-active" so the
	// arrowhead lights up along with the line -- a marker is referenced by
	// id, not styled by the edge's own class, so highlighting the stroke
	// alone would leave a mismatched-color arrowhead.
	svg.WriteString(`<defs>` +
		`<marker id="arrow" markerWidth="9" markerHeight="9" refX="7.5" refY="4" orient="auto"><path class="group-edge-arrow" d="M0,0 L8,4 L0,8 z"/></marker>` +
		`<marker id="arrow-active" markerWidth="9" markerHeight="9" refX="7.5" refY="4" orient="auto"><path class="group-edge-arrow-active" d="M0,0 L8,4 L0,8 z"/></marker>` +
		`</defs>`)

	// Nodes first, edges on top -- see the doc comment above for why. Each
	// node is wrapped in a <g class="group-node-hit" data-group="..."> so
	// plain client-side JS (see admin_home.html) can turn a click into
	// "show this group's members/ancestry panel" without a graph library.
	for _, n := range names {
		node := nodes[n]
		nodeClass := "group-node"
		if node.requireMFA {
			// A visibly different color for groups that force MFA on their
			// members -- a real security-relevant property of the group,
			// worth being able to spot in the graph at a glance rather
			// than only in the config file.
			nodeClass = "group-node-mfa"
		}
		cx := node.x + node.w/2
		svg.printf(`<g class="group-node-hit" data-group="%s" tabindex="0" role="button">`, template.HTMLEscapeString(n))
		svg.printf(`<rect class="%s" x="%.1f" y="%.1f" width="%.1f" height="%.1f" rx="8"/>`, nodeClass, node.x, node.y, node.w, node.h)
		svg.printf(`<text class="group-label" x="%.1f" y="%.1f" text-anchor="middle">%s</text>`,
			cx, node.y+node.h/2-2, template.HTMLEscapeString(n))
		member := "members"
		if node.memberCount == 1 {
			member = "member"
		}
		svg.printf(`<text class="group-count" x="%.1f" y="%.1f" text-anchor="middle">%d %s</text>`,
			cx, node.y+node.h/2+16, node.memberCount, member)
		svg.WriteString(`</g>`)
	}

	routeEdges(names, groups, nodes, &svg)
	svg.WriteString(`</svg>`)
	return svg.String()
}

// seedCircular gives the simulation a deterministic, non-degenerate
// starting point: every node placed around a circle (by sorted name, not
// time/rand, so the same graph always starts the same way), with
// higher-degree ("more important") nodes seeded closer to the center --
// a head start for forceDirectedLayout's own centering gravity rather than
// something it strictly depends on. Returns the seed radius, used to scale
// the simulation's forces to the graph's actual size.
func seedCircular(nodes map[string]*graphNode, names []string) float64 {
	maxDegree := 1
	for _, n := range names {
		if d := nodes[n].degree; d > maxDegree {
			maxDegree = d
		}
	}
	radius := 90.0 * math.Sqrt(float64(len(names)))
	if radius < 220 {
		radius = 220
	}
	for i, n := range names {
		node := nodes[n]
		angle := 2 * math.Pi * float64(i) / float64(len(names))
		importance := float64(node.degree) / float64(maxDegree)
		r := radius * (1 - 0.6*importance)
		node.x = radius + r*math.Cos(angle)
		node.y = radius + r*math.Sin(angle)
	}
	return radius
}

// forceDirectedLayout runs a 2D Fruchterman-Reingold simulation: every
// pair of nodes repels (so cards spread out and stop overlapping), every
// edge attracts (so related groups stay close), every node is pulled
// towards the graph's center with strength proportional to its own degree
// (see graphNode.degree) so well-connected "hub" groups gravitate to the
// middle and peripheral ones settle further out, and a shrinking
// "temperature" caps how far a node can move per step so the layout
// settles instead of oscillating.
//
// An earlier version fixed y outright from each node's root/leaf depth and
// only ever let this simulation move x -- a layered hierarchy diagram
// rather than a general graph layout. That's what produced the
// "everything in rows" look: a rank with many members had nowhere to
// expand but sideways within its own fixed band, no matter how much
// vertical space sat unused elsewhere. Letting both axes move, with degree
// determining how strongly a node is pulled to the shared center instead
// of a fixed row/column, lets crowded areas actually use whichever
// direction has room.
func forceDirectedLayout(nodes map[string]*graphNode, names []string, groups map[string]identity.Group, radius float64) {
	n := len(names)
	area := (radius * 2) * (radius * 2)
	k := math.Sqrt(area / float64(n))
	centerX, centerY := radius, radius
	// Repulsion beyond this range is ignored entirely, so it behaves as
	// collision avoidance between nodes that are actually near each other
	// rather than a global "everyone pushes everyone apart forever" force
	// that would otherwise fight the centering gravity below at every
	// distance, no matter how far things have already spread. Wider than a
	// simple "just clear of touching" range so that several high-degree
	// hubs -- which all get pulled towards the same center point below --
	// still have enough repulsive range to spread out from each other
	// before they're close enough for the degree-boosted push (see below)
	// to kick in.
	repulseCutoff := k * 4

	maxDegree := 1
	for _, n := range names {
		if d := nodes[n].degree; d > maxDegree {
			maxDegree = d
		}
	}

	type edge struct{ a, b string }
	var edges []edge
	for _, name := range names {
		for _, parent := range groups[name].MemberOfGroups {
			if _, ok := nodes[parent]; ok {
				edges = append(edges, edge{name, parent})
			}
		}
	}

	const iterations = 400
	temp := k * 2
	for iter := 0; iter < iterations; iter++ {
		dispX := make(map[string]float64, n)
		dispY := make(map[string]float64, n)

		for i := 0; i < len(names); i++ {
			for j := i + 1; j < len(names); j++ {
				a, b := nodes[names[i]], nodes[names[j]]
				dx, dy := a.x-b.x, a.y-b.y
				dist := math.Hypot(dx, dy)
				if dist < 0.01 {
					dist = 0.01
					dx = 0.01
				}
				// Extra separation so wider cards (longer names) don't
				// overlap even after repulsion balances out, and don't
				// just barely clear each other either -- enough gap to
				// read as clearly distinct cards.
				minSep := math.Max(a.w, a.h)/2 + math.Max(b.w, b.h)/2 + 26
				if dist > repulseCutoff && dist >= minSep {
					continue
				}
				// Two high-degree hubs both feel a strong pull toward the
				// same center point (see the gravity loop below), so
				// without something counteracting it they tend to end up
				// almost on top of each other -- which then tangles all
				// of their many fan-in/fan-out edges into the same small
				// area. Boosting repulsion between a pair in proportion to
				// their combined degree pushes important hubs apart from
				// *each other* specifically, giving their edges room to
				// fan out instead of converging on one spot.
				degreeBoost := 1.0 + 0.12*float64(a.degree+b.degree)
				force := (k * k * degreeBoost) / dist
				if dist < minSep {
					force += (minSep - dist) * 2
				}
				ux, uy := dx/dist, dy/dist
				dispX[names[i]] += ux * force
				dispY[names[i]] += uy * force
				dispX[names[j]] -= ux * force
				dispY[names[j]] -= uy * force
			}
		}

		for _, e := range edges {
			a, b := nodes[e.a], nodes[e.b]
			dx, dy := a.x-b.x, a.y-b.y
			dist := math.Hypot(dx, dy)
			if dist < 0.01 {
				dist = 0.01
			}
			force := (dist * dist) / k
			ux, uy := dx/dist, dy/dist
			dispX[e.a] -= ux * force
			dispY[e.a] -= uy * force
			dispX[e.b] += ux * force
			dispY[e.b] += uy * force
		}

		// Centering gravity, scaled by each node's own degree: a
		// well-connected hub feels a stronger pull to the middle than a
		// peripheral group with only one or two links, which otherwise
		// relies on repulsion/edge springs alone to find its resting
		// place further out. Every node still gets a small baseline pull
		// so a fully isolated group (degree 0) doesn't drift away
		// unbounded under pure repulsion. Capped well short of
		// overwhelming the degree-boosted repulsion above -- a stronger
		// pull here was letting several different hubs all converge on
		// essentially the same point, which is its own kind of clutter
		// (every one of their edges then tangles in that one spot) even
		// though no two cards actually overlapped.
		for _, name := range names {
			importance := float64(nodes[name].degree) / float64(maxDegree)
			gravity := 0.02 + 0.14*importance
			dispX[name] += (centerX - nodes[name].x) * gravity
			dispY[name] += (centerY - nodes[name].y) * gravity
		}

		for _, name := range names {
			dx, dy := dispX[name], dispY[name]
			dist := math.Hypot(dx, dy)
			if dist < 0.01 {
				continue
			}
			capped := math.Min(dist, temp)
			nodes[name].x += (dx / dist) * capped
			nodes[name].y += (dy / dist) * capped
		}

		temp *= 0.97
	}
}

// resolveOverlaps guarantees no two node cards overlap, regardless of how
// well the physics simulation actually converged: repeatedly find
// overlapping pairs and push each apart along whichever axis has the
// smaller overlap (the smallest nudge that actually separates them), for a
// bounded number of passes.
//
// forceDirectedLayout's repulsion is a soft, iterative force competing
// against every other force in the same system; in a denser graph that
// competition doesn't always fully resolve within a fixed iteration
// budget. This pass is the hard guarantee the soft force alone couldn't
// reliably provide -- it only ever increases separation, so it can't
// reintroduce a crossing the routing pass (which runs after this, from
// these same final positions) would have to account for.
func resolveOverlaps(nodes map[string]*graphNode, names []string) {
	const passes = 60
	for pass := 0; pass < passes; pass++ {
		moved := false
		for i := 0; i < len(names); i++ {
			for j := i + 1; j < len(names); j++ {
				a, b := nodes[names[i]], nodes[names[j]]
				// a.x/a.y (like everywhere else in this file) are the
				// rectangle's top-left corner, not its center -- overlap
				// on each axis is how much the [x,x+w]/[y,y+h] intervals
				// intersect, not (w1+w2)/2 - |x1-x2| (which is only valid
				// when x is a center coordinate, and silently gives wrong
				// answers, including false negatives, otherwise).
				overlapX := math.Min(a.x+a.w, b.x+b.w) - math.Max(a.x, b.x)
				overlapY := math.Min(a.y+a.h, b.y+b.h) - math.Max(a.y, b.y)
				if overlapX <= 0 || overlapY <= 0 {
					continue // not overlapping on at least one axis
				}
				// Push apart based on each rect's actual center, not its
				// corner -- with differently-sized cards, corner-based
				// dx/dy doesn't reliably say which side a box's center is
				// really on.
				dx := (a.x + a.w/2) - (b.x + b.w/2)
				dy := (a.y + a.h/2) - (b.y + b.h/2)
				if overlapX < overlapY {
					shift := overlapX/2 + 1
					if dx < 0 {
						shift = -shift
					}
					a.x += shift
					b.x -= shift
				} else {
					shift := overlapY/2 + 1
					if dy < 0 {
						shift = -shift
					}
					a.y += shift
					b.y -= shift
				}
				moved = true
			}
		}
		if !moved {
			break
		}
	}
}

func boundingBox(nodes map[string]*graphNode) (minX, minY, maxX, maxY float64) {
	first := true
	for _, node := range nodes {
		x0, y0, x1, y1 := node.x, node.y, node.x+node.w, node.y+node.h
		if first {
			minX, minY, maxX, maxY = x0, y0, x1, y1
			first = false
			continue
		}
		minX, minY = math.Min(minX, x0), math.Min(minY, y0)
		maxX, maxY = math.Max(maxX, x1), math.Max(maxY, y1)
	}
	return
}

// edgeRoute is one child->parent inheritance edge, computed in two passes
// by routeEdges before anything is written to the SVG: first its straight
// chord (clipped to each node's border), then how much (if at all) it
// needs to bow to avoid an obstruction.
type edgeRoute struct {
	child, parent *graphNode
	start, end    [2]float64
	// bow is the perpendicular offset applied at the curve's midpoint;
	// zero means "draw a plain straight line". Curvature here exists
	// purely to route around something in the way, not for visual style --
	// see routeEdges.
	bow float64
}

// routeEdges computes every child->parent edge's path and writes them all,
// curving an edge only when its straight chord would otherwise cut through
// an unrelated node's card or overlap another edge's chord -- a short,
// unobstructed edge is drawn as a plain straight line. An earlier version
// bowed every single edge by a fixed amount regardless of whether anything
// was actually in the way, which added visual noise (and made truly short,
// direct edges look unnecessarily indirect) without helping the graphs
// that actually had crossings. This works with any node positions, so it's
// unaffected by whatever layout algorithm placed them.
func routeEdges(names []string, groups map[string]identity.Group, nodes map[string]*graphNode, svg *fmtBuilder) {
	var routes []*edgeRoute
	for _, n := range names {
		child := nodes[n]
		for _, parent := range groups[n].MemberOfGroups {
			parentNode, ok := nodes[parent]
			if !ok {
				continue
			}
			cx0, cy0 := child.x+child.w/2, child.y+child.h/2
			cx1, cy1 := parentNode.x+parentNode.w/2, parentNode.y+parentNode.h/2
			routes = append(routes, &edgeRoute{
				child:  child,
				parent: parentNode,
				start:  clipToRect(cx0, cy0, cx1, cy1, child),
				end:    clipToRect(cx1, cy1, cx0, cy0, parentNode),
			})
		}
	}

	// Pass 1: bow around any node (other than this edge's own two
	// endpoints) that the straight chord would otherwise pass through.
	for _, r := range routes {
		dx, dy := r.end[0]-r.start[0], r.end[1]-r.start[1]
		dist := math.Hypot(dx, dy)
		if dist < 0.01 {
			dist = 0.01
		}
		px, py := -dy/dist, dx/dist // unit perpendicular to the chord

		for _, other := range nodes {
			if other == r.child || other == r.parent {
				continue
			}
			if !segmentIntersectsRect(r.start[0], r.start[1], r.end[0], r.end[1], other) {
				continue
			}
			// Bow away from whichever side the obstruction's center is
			// on, by enough to clear its half-diagonal plus a margin.
			ocx, ocy := other.x+other.w/2, other.y+other.h/2
			side := (ocx-r.start[0])*px + (ocy-r.start[1])*py
			clearance := math.Hypot(other.w, other.h)/2 + 16
			needed := clearance
			if side >= 0 {
				needed = -clearance
			}
			if math.Abs(needed) > math.Abs(r.bow) {
				r.bow = needed
			}
		}
	}

	// Pass 2: for pairs of edges that are still straight (nothing to route
	// around) but whose chords cross each other, bow both apart just
	// enough that they're visibly two lines instead of one -- a real
	// topological crossing generally can't be eliminated without a much
	// longer detour, but overlapping into what reads as a single stroke is
	// avoidable and worth fixing.
	for i := 0; i < len(routes); i++ {
		a := routes[i]
		if a.bow != 0 {
			continue
		}
		for j := i + 1; j < len(routes); j++ {
			b := routes[j]
			if b.bow != 0 {
				continue
			}
			if !segmentsIntersect(a.start[0], a.start[1], a.end[0], a.end[1], b.start[0], b.start[1], b.end[0], b.end[1]) {
				continue
			}
			bow := 16.0
			// Alternate which of the pair bows which way from a hash of
			// the endpoints, so the same graph always separates the same
			// crossing the same way instead of flipping between renders.
			if fnv32(a.child.name+"|"+a.parent.name)%2 == 0 {
				a.bow, b.bow = bow, -bow
			} else {
				a.bow, b.bow = -bow, bow
			}
		}
	}

	for _, r := range routes {
		writeEdgePath(svg, r)
	}
}

// writeEdgePath renders one already-routed edge: a plain line when bow is
// zero, otherwise a quadratic bezier bowed at its midpoint.
func writeEdgePath(svg *fmtBuilder, r *edgeRoute) {
	// data-child/data-parent let admin_home.html's hover handler find this
	// edge from either endpoint without walking the DOM for it -- see the
	// "light up direct links on hover" JS there.
	attrs := fmt.Sprintf(`data-child="%s" data-parent="%s"`,
		template.HTMLEscapeString(r.child.name), template.HTMLEscapeString(r.parent.name))

	if r.bow == 0 {
		svg.printf(`<path class="group-edge" %s d="M%.1f,%.1f L%.1f,%.1f" marker-end="url(#arrow)"/>`,
			attrs, r.start[0], r.start[1], r.end[0], r.end[1])
		return
	}
	dx, dy := r.end[0]-r.start[0], r.end[1]-r.start[1]
	dist := math.Hypot(dx, dy)
	if dist < 0.01 {
		dist = 0.01
	}
	px, py := -dy/dist, dx/dist
	midX, midY := (r.start[0]+r.end[0])/2+px*r.bow, (r.start[1]+r.end[1])/2+py*r.bow
	svg.printf(`<path class="group-edge" %s d="M%.1f,%.1f Q%.1f,%.1f %.1f,%.1f" marker-end="url(#arrow)"/>`,
		attrs, r.start[0], r.start[1], midX, midY, r.end[0], r.end[1])
}

// segmentIntersectsRect reports whether the segment (x1,y1)-(x2,y2) passes
// through node's rectangle, via the Liang-Barsky line-clipping algorithm:
// clip the segment's parameter range t in [0,1] against each of the
// rectangle's four half-planes in turn, and see whether any range survives.
func segmentIntersectsRect(x1, y1, x2, y2 float64, node *graphNode) bool {
	xmin, xmax := node.x, node.x+node.w
	ymin, ymax := node.y, node.y+node.h
	dx, dy := x2-x1, y2-y1
	tMin, tMax := 0.0, 1.0
	p := [4]float64{-dx, dx, -dy, dy}
	q := [4]float64{x1 - xmin, xmax - x1, y1 - ymin, ymax - y1}
	for i := 0; i < 4; i++ {
		if p[i] == 0 {
			if q[i] < 0 {
				return false // parallel to this edge and entirely outside it
			}
			continue
		}
		t := q[i] / p[i]
		if p[i] < 0 {
			if t > tMax {
				return false
			}
			if t > tMin {
				tMin = t
			}
		} else {
			if t < tMin {
				return false
			}
			if t < tMax {
				tMax = t
			}
		}
	}
	return tMin < tMax
}

// segmentsIntersect reports whether segments (x1,y1)-(x2,y2) and
// (x3,y3)-(x4,y4) cross, via orientation tests (does not special-case
// collinear overlap, which doesn't occur for distinct graph edges here).
func segmentsIntersect(x1, y1, x2, y2, x3, y3, x4, y4 float64) bool {
	cross := func(ax, ay, bx, by float64) float64 { return ax*by - ay*bx }
	d1 := cross(x4-x3, y4-y3, x1-x3, y1-y3)
	d2 := cross(x4-x3, y4-y3, x2-x3, y2-y3)
	d3 := cross(x2-x1, y2-y1, x3-x1, y3-y1)
	d4 := cross(x2-x1, y2-y1, x4-x1, y4-y1)
	return ((d1 > 0 && d2 < 0) || (d1 < 0 && d2 > 0)) && ((d3 > 0 && d4 < 0) || (d3 < 0 && d4 > 0))
}

// clipToRect returns the point where the segment from (x0,y0) towards
// (x1,y1) exits node's rectangle, starting from the rectangle's center --
// i.e. where a line drawn from this node to the other one should actually
// start, so it touches the border rather than overlapping the card.
func clipToRect(x0, y0, x1, y1 float64, node *graphNode) [2]float64 {
	dx, dy := x1-x0, y1-y0
	if dx == 0 && dy == 0 {
		return [2]float64{x0, y0}
	}
	hw, hh := node.w/2, node.h/2
	// Find the smallest positive t such that (x0,y0)+t*(dx,dy) lies on the
	// rectangle's border.
	best := math.Inf(1)
	if dx != 0 {
		for _, edgeX := range [2]float64{-hw, hw} {
			t := edgeX / dx
			if t > 0 {
				y := t * dy
				if y >= -hh && y <= hh && t < best {
					best = t
				}
			}
		}
	}
	if dy != 0 {
		for _, edgeY := range [2]float64{-hh, hh} {
			t := edgeY / dy
			if t > 0 {
				x := t * dx
				if x >= -hw && x <= hw && t < best {
					best = t
				}
			}
		}
	}
	if math.IsInf(best, 1) {
		return [2]float64{x0, y0}
	}
	return [2]float64{x0 + best*dx, y0 + best*dy}
}

func fnv32(s string) uint32 {
	var h uint32 = 2166136261
	for i := 0; i < len(s); i++ {
		h ^= uint32(s[i])
		h *= 16777619
	}
	return h
}

// fmtBuilder is a tiny strings.Builder wrapper so the SVG-assembly code
// above can use fmt.Fprintf-style calls without importing strings directly
// in every call site.
type fmtBuilder struct {
	b []byte
}

func (f *fmtBuilder) printf(format string, args ...any) {
	f.b = append(f.b, []byte(fmt.Sprintf(format, args...))...)
}

func (f *fmtBuilder) WriteString(s string) {
	f.b = append(f.b, s...)
}

func (f *fmtBuilder) String() string {
	return string(f.b)
}
