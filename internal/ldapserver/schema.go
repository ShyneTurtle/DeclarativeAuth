package ldapserver

import "declarativeauth/internal/identity"

// Attribute is a single LDAP attribute with its (possibly multi-valued) values.
type Attribute struct {
	Name   string
	Values []string
}

// UserEntry renders a user's LDAP attributes, including the fully flattened
// memberOf list read directly off the snapshot — O(1), no per-request graph
// traversal.
func UserEntry(baseDN string, u identity.User, flattenedGroups []string) []Attribute {
	memberOf := make([]string, len(flattenedGroups))
	for i, g := range flattenedGroups {
		memberOf[i] = GroupDN(baseDN, g)
	}
	return []Attribute{
		{Name: "objectClass", Values: []string{"declarativeAuthUser", "inetOrgPerson"}},
		{Name: "uid", Values: []string{u.Username}},
		{Name: "cn", Values: []string{u.DisplayNameOrDefault()}},
		{Name: "givenName", Values: nonEmpty(u.FirstName)},
		{Name: "sn", Values: nonEmpty(u.Name)},
		{Name: "mail", Values: nonEmpty(u.Email)},
		{Name: "memberOf", Values: memberOf},
	}
}

// GroupEntry renders a group's LDAP attributes.
func GroupEntry(g identity.Group) []Attribute {
	return []Attribute{
		{Name: "objectClass", Values: []string{"groupOfNames"}},
		{Name: "cn", Values: []string{g.Name}},
		{Name: "description", Values: nonEmpty(g.Description)},
	}
}

func nonEmpty(s string) []string {
	if s == "" {
		return nil
	}
	return []string{s}
}
