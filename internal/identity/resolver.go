package identity

import (
	"fmt"
	"sort"
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
