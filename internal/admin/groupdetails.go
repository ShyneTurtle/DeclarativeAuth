package admin

import (
	"sort"

	"declarativeauth/internal/identity"
)

// pathEntry is one member/ancestor of a group, together with a chain
// showing how it got there. Path always starts at the "far end" (the user,
// or the descendant/ancestor group) and ends at the group this pathEntry
// belongs to -- e.g. for engineering's Users list, a pathEntry might be
// {Name: "jsmith", Path: ["jsmith", "oncall", "backend-team", "engineering"]},
// read as "jsmith, via oncall, via backend-team, into engineering". Groups
// can inherit the same ancestor through more than one path (the diamond
// example in examples/identity/groups.yaml); only the shortest is shown,
// since listing every possible path would make the panel unreadable for
// not much benefit.
type pathEntry struct {
	Name string   `json:"name"`
	Path []string `json:"path"`
}

// groupDetail is everything the admin graph's click-to-inspect panel shows
// for one group. Users/Subgroups/FlattenedMemberOf each include direct
// memberships too (as a length-2 Path: [item, this group]) rather than
// listing them separately -- the client just renders a length-2 path as a
// plain chip instead of a breadcrumb, so there's one merged list per
// category instead of a "direct" list duplicating part of a "everyone"
// list right next to it.
type groupDetail struct {
	Name              string      `json:"name"`
	RequireMFA        bool        `json:"requireMFA"`
	Users             []pathEntry `json:"users"`             // every transitive member user
	Subgroups         []pathEntry `json:"subgroups"`         // every transitive member group
	FlattenedMemberOf []pathEntry `json:"flattenedMemberOf"` // every group this one transitively belongs to
}

// computeGroupDetails builds the click-to-inspect data for every group in
// snap, for the admin group graph. It's independent of (and doesn't reuse)
// identity.Snapshot's own FlattenedMemberOf/FlattenedMembers, since those
// only record *whether* a membership holds, not *the path* that produced
// it -- which is the whole point of this panel.
func computeGroupDetails(snap *identity.Snapshot) map[string]groupDetail {
	groups := snap.Groups

	children := map[string][]string{} // group -> direct child groups
	for name, g := range groups {
		for _, parent := range g.MemberOfGroups {
			children[parent] = append(children[parent], name)
		}
	}

	parentsOf := func(n string) []string { return groups[n].MemberOfGroups }
	childrenOf := func(n string) []string { return children[n] }

	details := make(map[string]groupDetail, len(groups))
	for name, g := range groups {
		// []pathEntry{}, not nil -- this is serialized straight to JSON for
		// the graph's client-side click handler, which indexes .length on
		// every one of these fields unconditionally; a bare nil slice
		// would round-trip as JSON `null` and throw there.
		users := []pathEntry{}
		for uname, u := range snap.Users {
			if path := shortestPath(u.MemberOfGroups, name, parentsOf); path != nil {
				users = append(users, pathEntry{Name: uname, Path: append([]string{uname}, path...)})
			}
		}
		sort.Slice(users, func(i, j int) bool { return users[i].Name < users[j].Name })

		details[name] = groupDetail{
			Name:       name,
			RequireMFA: g.RequireMFA,
			Users:      users,
			// bfsPaths(name, childrenOf) walks DOWN from this group to each
			// descendant, so it naturally produces [this group, ...,
			// descendant] -- backwards from every other path in this
			// struct (which all end AT this group, matching the graph's
			// own child-to-parent arrow direction) and backwards from the
			// arrows themselves, since a descendant's arrow points UP
			// towards this group, not down towards the descendant.
			// Reversed here once so the client never has to know which
			// direction a particular list happens to have been walked in.
			Subgroups:         reversedPaths(bfsPaths(name, childrenOf)),
			FlattenedMemberOf: bfsPaths(name, parentsOf),
		}
	}
	return details
}

// reversedPaths flips the Path of every entry in place order (front to
// back), leaving Name untouched -- see the Subgroups comment above for why
// bfsPaths's natural output needs this for that one case.
func reversedPaths(entries []pathEntry) []pathEntry {
	out := make([]pathEntry, len(entries))
	for i, e := range entries {
		rev := make([]string, len(e.Path))
		for j, s := range e.Path {
			rev[len(e.Path)-1-j] = s
		}
		out[i] = pathEntry{Name: e.Name, Path: rev}
	}
	return out
}

// bfsPaths finds the shortest path from start to every node reachable via
// edges, breadth-first (so the first path found to any node is already
// shortest), and returns them sorted by name for a stable render. Returns
// []pathEntry{} rather than nil when start has no reachable nodes -- see
// the same note on `users` in computeGroupDetails.
func bfsPaths(start string, edges func(string) []string) []pathEntry {
	visited := map[string]bool{start: true}
	paths := map[string][]string{start: {start}}
	queue := []string{start}
	out := []pathEntry{}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		for _, next := range edges(cur) {
			if visited[next] {
				continue
			}
			visited[next] = true
			path := append(append([]string{}, paths[cur]...), next)
			paths[next] = path
			out = append(out, pathEntry{Name: next, Path: path})
			queue = append(queue, next)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// shortestPath finds the shortest path from any of sources to target,
// following edges, and returns it starting from whichever source produced
// the shortest route (nil if target isn't reachable from any source). Used
// for "which of this user's direct groups leads to the clicked group, and
// how".
func shortestPath(sources []string, target string, edges func(string) []string) []string {
	visited := map[string]bool{}
	paths := map[string][]string{}
	var queue []string
	for _, s := range sources {
		if visited[s] {
			continue
		}
		visited[s] = true
		paths[s] = []string{s}
		queue = append(queue, s)
		if s == target {
			return paths[s]
		}
	}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		for _, next := range edges(cur) {
			if visited[next] {
				continue
			}
			visited[next] = true
			path := append(append([]string{}, paths[cur]...), next)
			paths[next] = path
			if next == target {
				return path
			}
			queue = append(queue, next)
		}
	}
	return nil
}
