package identity

import (
	"fmt"
	"sort"
	"strings"
)

// CycleError is returned when the group graph contains a cycle.
type CycleError struct {
	Path []string
}

func (e *CycleError) Error() string {
	s := "group cycle detected: "
	for i, n := range e.Path {
		if i > 0 {
			s += " -> "
		}
		s += n
	}
	return s
}

const (
	colorWhite = 0
	colorGray  = 1
	colorBlack = 2
)

// DetectCycle runs a DFS-based cycle check over the group graph. Returns a
// *CycleError naming the offending path if a cycle exists.
func DetectCycle(groups map[string]Group) error {
	color := make(map[string]int, len(groups))
	var path []string

	var visit func(name string) error
	visit = func(name string) error {
		switch color[name] {
		case colorBlack:
			return nil
		case colorGray:
			cyclePath := append(append([]string{}, path...), name)
			return &CycleError{Path: cyclePath}
		}
		color[name] = colorGray
		path = append(path, name)
		g, ok := groups[name]
		if ok {
			for _, parent := range g.MemberOfGroups {
				if err := visit(parent); err != nil {
					return err
				}
			}
		}
		path = path[:len(path)-1]
		color[name] = colorBlack
		return nil
	}

	names := make([]string, 0, len(groups))
	for n := range groups {
		names = append(names, n)
	}
	sort.Strings(names)

	for _, n := range names {
		if color[n] == colorWhite {
			if err := visit(n); err != nil {
				return err
			}
		}
	}
	return nil
}

// ReferentialError is returned when a group/user references a group name that
// does not exist.
type ReferentialError struct {
	From, MissingGroup string
}

func (e *ReferentialError) Error() string {
	return fmt.Sprintf("%q references non-existent group %q", e.From, e.MissingGroup)
}

// CheckReferences validates that every MemberOfGroups entry (in both groups
// and users) points at a group that exists.
func CheckReferences(users map[string]User, groups map[string]Group) error {
	for name, g := range groups {
		for _, parent := range g.MemberOfGroups {
			if _, ok := groups[parent]; !ok {
				return &ReferentialError{From: "group:" + name, MissingGroup: parent}
			}
		}
	}
	for name, u := range users {
		for _, parent := range u.MemberOfGroups {
			if _, ok := groups[parent]; !ok {
				return &ReferentialError{From: "user:" + name, MissingGroup: parent}
			}
		}
	}
	return nil
}

// ResolveFlattenedMemberOf computes, for every user, the transitive closure
// of group membership (diamond-safe, memoized per group). Callers must run
// CheckReferences and DetectCycle first — this function assumes a valid DAG.
func ResolveFlattenedMemberOf(users map[string]User, groups map[string]Group) map[string][]string {
	closures := make(map[string]map[string]struct{}, len(groups))

	var closureOf func(name string) map[string]struct{}
	closureOf = func(name string) map[string]struct{} {
		if c, ok := closures[name]; ok {
			return c
		}
		set := map[string]struct{}{name: {}}
		if g, ok := groups[name]; ok {
			for _, parent := range g.MemberOfGroups {
				for k := range closureOf(parent) {
					set[k] = struct{}{}
				}
			}
		}
		closures[name] = set
		return set
	}

	names := make([]string, 0, len(groups))
	for n := range groups {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		closureOf(n)
	}

	result := make(map[string][]string, len(users))
	for username, u := range users {
		set := map[string]struct{}{}
		for _, g := range u.MemberOfGroups {
			for k := range closureOf(g) {
				set[k] = struct{}{}
			}
		}
		list := make([]string, 0, len(set))
		for k := range set {
			list = append(list, k)
		}
		sort.Strings(list)
		result[username] = list
	}
	return result
}

// ResolveFlattenedMembers inverts a user -> flattened-groups map (as
// returned by ResolveFlattenedMemberOf) into a group -> flattened-members
// map: for every group, every user transitively in it, sorted. This is the
// other half of group-inheritance flattening -- ResolveFlattenedMemberOf
// answers "what groups is this user in" (rendered as a user's LDAP
// memberOf), this answers "who is in this group" (rendered as a group's
// LDAP member), and RFC 4519's groupOfNames requires the latter as a MUST
// attribute, so a group entry needs it even though nothing else in this
// codebase needs the reverse index.
// customAttrSource labels which declared field contributed a candidate
// value for a user's custom attribute key, purely for
// ResolveCustomAttributes' conflict messages.
type customAttrSource struct {
	label  string
	values []string
}

// ResolveCustomAttributes merges every source of custom LDAP attributes
// into a final per-user and per-group view. A group's own entry only ever
// gets its own Group.CustomAttributes (no merging possible: nothing else
// targets it). A user's entry gets the union of:
//   - their own User.CustomAttributes
//   - every group they're transitively (flattened) a member of, via that
//     group's UserCustomAttributes
//   - every group they're a DIRECT member of, via that group's
//     DirectUserCustomAttributes
//
// When a key is contributed by more than one of those sources for the same
// user, there is no principled way to pick a winner, so it isn't guessed
// at: the collision is recorded in the returned conflicts list (one
// message per key per user, naming every contributing source) and the key
// is dropped entirely from that user's resolved attributes. Callers must
// treat conflicts as non-fatal -- see config.LoadIdentity, which never
// fails a load over this, only surfaces it (config.Watcher logs each
// entry).
func ResolveCustomAttributes(users map[string]User, groups map[string]Group, flattenedMemberOf map[string][]string) (perUser, perGroup map[string]map[string][]string, conflicts []string) {
	perGroup = make(map[string]map[string][]string, len(groups))
	for name, g := range groups {
		if len(g.CustomAttributes) > 0 {
			perGroup[name] = g.CustomAttributes
		}
	}

	usernames := make([]string, 0, len(users))
	for username := range users {
		usernames = append(usernames, username)
	}
	sort.Strings(usernames)

	perUser = make(map[string]map[string][]string, len(users))
	for _, username := range usernames {
		u := users[username]
		contributions := map[string][]customAttrSource{}
		addContribution := func(label string, attrs map[string][]string) {
			keys := make([]string, 0, len(attrs))
			for k := range attrs {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				contributions[k] = append(contributions[k], customAttrSource{label: label, values: attrs[k]})
			}
		}

		addContribution("this user's own customAttribute", u.CustomAttributes)

		for _, group := range flattenedMemberOf[username] {
			if g, ok := groups[group]; ok {
				addContribution(fmt.Sprintf("group %q's userCustomAttribute", group), g.UserCustomAttributes)
			}
		}
		directGroups := append([]string{}, u.MemberOfGroups...)
		sort.Strings(directGroups)
		for _, group := range directGroups {
			if g, ok := groups[group]; ok {
				addContribution(fmt.Sprintf("group %q's directUserCustomAttribute", group), g.DirectUserCustomAttributes)
			}
		}

		keys := make([]string, 0, len(contributions))
		for k := range contributions {
			keys = append(keys, k)
		}
		sort.Strings(keys)

		resolved := map[string][]string{}
		for _, k := range keys {
			sources := contributions[k]
			if len(sources) > 1 {
				labels := make([]string, len(sources))
				for i, s := range sources {
					labels[i] = s.label
				}
				conflicts = append(conflicts, fmt.Sprintf("user %q: attribute %q declared by more than one source (%s) -- dropped",
					username, k, strings.Join(labels, ", ")))
				continue
			}
			resolved[k] = sources[0].values
		}
		if len(resolved) > 0 {
			perUser[username] = resolved
		}
	}
	return perUser, perGroup, conflicts
}

func ResolveFlattenedMembers(flattenedMemberOf map[string][]string) map[string][]string {
	result := map[string][]string{}
	usernames := make([]string, 0, len(flattenedMemberOf))
	for username := range flattenedMemberOf {
		usernames = append(usernames, username)
	}
	sort.Strings(usernames)

	for _, username := range usernames {
		for _, group := range flattenedMemberOf[username] {
			result[group] = append(result[group], username)
		}
	}
	return result
}
