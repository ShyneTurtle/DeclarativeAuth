package config

import (
	"sort"

	"declarativeauth/internal/identity"
)

// SnapshotDiff summarizes what changed between two identity snapshots.
type SnapshotDiff struct {
	UsersAdded, UsersRemoved, UsersModified                   []string
	GroupsAdded, GroupsRemoved, GroupsModified                []string
	OIDCClientsAdded, OIDCClientsRemoved, OIDCClientsModified []string
}

// IsEmpty reports whether the diff represents no change at all.
func (d SnapshotDiff) IsEmpty() bool {
	return len(d.UsersAdded)+len(d.UsersRemoved)+len(d.UsersModified)+
		len(d.GroupsAdded)+len(d.GroupsRemoved)+len(d.GroupsModified)+
		len(d.OIDCClientsAdded)+len(d.OIDCClientsRemoved)+len(d.OIDCClientsModified) == 0
}

// DiffSnapshots computes the added/removed/modified users and groups between
// an old and new snapshot, for reload change-summary logging.
func DiffSnapshots(old, updated *identity.Snapshot) SnapshotDiff {
	var d SnapshotDiff

	if old == nil {
		old = &identity.Snapshot{}
	}

	for name, nu := range updated.Users {
		ou, existed := old.Users[name]
		if !existed {
			d.UsersAdded = append(d.UsersAdded, name)
			continue
		}
		if !usersEqual(ou, nu) {
			d.UsersModified = append(d.UsersModified, name)
		}
	}
	for name := range old.Users {
		if _, stillExists := updated.Users[name]; !stillExists {
			d.UsersRemoved = append(d.UsersRemoved, name)
		}
	}

	for name, ng := range updated.Groups {
		og, existed := old.Groups[name]
		if !existed {
			d.GroupsAdded = append(d.GroupsAdded, name)
			continue
		}
		if !groupsEqual(og, ng) {
			d.GroupsModified = append(d.GroupsModified, name)
		}
	}
	for name := range old.Groups {
		if _, stillExists := updated.Groups[name]; !stillExists {
			d.GroupsRemoved = append(d.GroupsRemoved, name)
		}
	}

	for id, nc := range updated.OIDCClients {
		oc, existed := old.OIDCClients[id]
		if !existed {
			d.OIDCClientsAdded = append(d.OIDCClientsAdded, id)
			continue
		}
		if !oidcClientsEqual(oc, nc) {
			d.OIDCClientsModified = append(d.OIDCClientsModified, id)
		}
	}
	for id := range old.OIDCClients {
		if _, stillExists := updated.OIDCClients[id]; !stillExists {
			d.OIDCClientsRemoved = append(d.OIDCClientsRemoved, id)
		}
	}

	sort.Strings(d.UsersAdded)
	sort.Strings(d.UsersRemoved)
	sort.Strings(d.UsersModified)
	sort.Strings(d.GroupsAdded)
	sort.Strings(d.GroupsRemoved)
	sort.Strings(d.GroupsModified)
	sort.Strings(d.OIDCClientsAdded)
	sort.Strings(d.OIDCClientsRemoved)
	sort.Strings(d.OIDCClientsModified)
	return d
}

func usersEqual(a, b identity.User) bool {
	if a.Email != b.Email || a.FirstName != b.FirstName || a.Name != b.Name ||
		a.DisplayName != b.DisplayName || a.Enabled != b.Enabled || a.MFAEnabled != b.MFAEnabled {
		return false
	}
	return stringSlicesEqualAsSets(a.MemberOfGroups, b.MemberOfGroups)
}

func groupsEqual(a, b identity.Group) bool {
	if a.Description != b.Description || a.RequireMFA != b.RequireMFA {
		return false
	}
	return stringSlicesEqualAsSets(a.MemberOfGroups, b.MemberOfGroups)
}

func oidcClientsEqual(a, b identity.OIDCClient) bool {
	if a.Public != b.Public || a.ClientSecret != b.ClientSecret {
		return false
	}
	return stringSlicesEqualAsSets(a.RedirectURIs, b.RedirectURIs)
}

func stringSlicesEqualAsSets(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	as := append([]string{}, a...)
	bs := append([]string{}, b...)
	sort.Strings(as)
	sort.Strings(bs)
	for i := range as {
		if as[i] != bs[i] {
			return false
		}
	}
	return true
}
