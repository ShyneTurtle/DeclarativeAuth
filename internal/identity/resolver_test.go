package identity

import (
	"reflect"
	"strconv"
	"testing"
)

func TestDetectCycle_None(t *testing.T) {
	groups := map[string]Group{
		"backend":     {Name: "backend", MemberOfGroups: []string{"engineering"}},
		"engineering": {Name: "engineering"},
	}
	if err := DetectCycle(groups); err != nil {
		t.Fatalf("unexpected cycle error: %v", err)
	}
}

func TestDetectCycle_SelfReference(t *testing.T) {
	groups := map[string]Group{
		"a": {Name: "a", MemberOfGroups: []string{"a"}},
	}
	if err := DetectCycle(groups); err == nil {
		t.Fatal("expected cycle error, got nil")
	}
}

func TestDetectCycle_MultiNode(t *testing.T) {
	groups := map[string]Group{
		"a": {Name: "a", MemberOfGroups: []string{"b"}},
		"b": {Name: "b", MemberOfGroups: []string{"c"}},
		"c": {Name: "c", MemberOfGroups: []string{"a"}},
	}
	err := DetectCycle(groups)
	if err == nil {
		t.Fatal("expected cycle error, got nil")
	}
	if _, ok := err.(*CycleError); !ok {
		t.Fatalf("expected *CycleError, got %T", err)
	}
}

func TestCheckReferences_Dangling(t *testing.T) {
	groups := map[string]Group{
		"a": {Name: "a", MemberOfGroups: []string{"ghost"}},
	}
	if err := CheckReferences(nil, groups); err == nil {
		t.Fatal("expected referential error, got nil")
	}
}

func TestResolveFlattenedMemberOf_LinearChain(t *testing.T) {
	groups := map[string]Group{
		"backend":     {Name: "backend", MemberOfGroups: []string{"engineering"}},
		"engineering": {Name: "engineering"},
	}
	users := map[string]User{
		"jsmith": {Username: "jsmith", MemberOfGroups: []string{"backend"}},
	}
	got := ResolveFlattenedMemberOf(users, groups)
	want := []string{"backend", "engineering"}
	if !reflect.DeepEqual(got["jsmith"], want) {
		t.Fatalf("got %v, want %v", got["jsmith"], want)
	}
}

func TestResolveFlattenedMemberOf_DiamondDeduped(t *testing.T) {
	groups := map[string]Group{
		"engineering": {Name: "engineering"},
		"backend":     {Name: "backend", MemberOfGroups: []string{"engineering"}},
		"platform":    {Name: "platform", MemberOfGroups: []string{"engineering"}},
		"oncall":      {Name: "oncall", MemberOfGroups: []string{"backend", "platform"}},
	}
	users := map[string]User{
		"jsmith": {Username: "jsmith", MemberOfGroups: []string{"oncall"}},
	}
	got := ResolveFlattenedMemberOf(users, groups)
	want := []string{"backend", "engineering", "oncall", "platform"}
	if !reflect.DeepEqual(got["jsmith"], want) {
		t.Fatalf("got %v, want %v", got["jsmith"], want)
	}
}

func TestResolveFlattenedMemberOf_NoGroups(t *testing.T) {
	users := map[string]User{
		"jsmith": {Username: "jsmith"},
	}
	got := ResolveFlattenedMemberOf(users, map[string]Group{})
	if len(got["jsmith"]) != 0 {
		t.Fatalf("expected empty closure, got %v", got["jsmith"])
	}
}

func TestResolveFlattenedMemberOf_DeepChainPerf(t *testing.T) {
	const n = 1000
	groups := make(map[string]Group, n)
	for i := 0; i < n; i++ {
		name := groupName(i)
		g := Group{Name: name}
		if i > 0 {
			g.MemberOfGroups = []string{groupName(i - 1)}
		}
		groups[name] = g
	}
	users := map[string]User{
		"u": {Username: "u", MemberOfGroups: []string{groupName(n - 1)}},
	}
	got := ResolveFlattenedMemberOf(users, groups)
	if len(got["u"]) != n {
		t.Fatalf("expected %d groups in closure, got %d", n, len(got["u"]))
	}
}

func groupName(i int) string {
	return "g" + strconv.Itoa(i)
}

func TestResolveFlattenedMembers_DiamondDeduped(t *testing.T) {
	groups := map[string]Group{
		"engineering": {Name: "engineering"},
		"backend":     {Name: "backend", MemberOfGroups: []string{"engineering"}},
		"platform":    {Name: "platform", MemberOfGroups: []string{"engineering"}},
		"oncall":      {Name: "oncall", MemberOfGroups: []string{"backend", "platform"}},
	}
	users := map[string]User{
		"jsmith": {Username: "jsmith", MemberOfGroups: []string{"oncall"}},
		"asmith": {Username: "asmith", MemberOfGroups: []string{"backend"}},
	}
	memberOf := ResolveFlattenedMemberOf(users, groups)
	members := ResolveFlattenedMembers(memberOf)

	want := []string{"asmith", "jsmith"}
	if !reflect.DeepEqual(members["engineering"], want) {
		t.Fatalf("engineering members: got %v, want %v", members["engineering"], want)
	}
	if !reflect.DeepEqual(members["backend"], want) {
		t.Fatalf("backend members: got %v, want %v", members["backend"], want)
	}
	if !reflect.DeepEqual(members["oncall"], []string{"jsmith"}) {
		t.Fatalf("oncall members: got %v, want [jsmith]", members["oncall"])
	}
	if !reflect.DeepEqual(members["platform"], []string{"jsmith"}) {
		t.Fatalf("platform members: got %v, want [jsmith]", members["platform"])
	}
}

func TestResolveFlattenedMembers_NoUsers(t *testing.T) {
	members := ResolveFlattenedMembers(map[string][]string{})
	if len(members) != 0 {
		t.Fatalf("expected no members, got %v", members)
	}
}

func TestResolveCustomAttributes_UserOwnAttribute(t *testing.T) {
	users := map[string]User{
		"jsmith": {Username: "jsmith", CustomAttributes: map[string][]string{"phone": {"+1-555-0100"}}},
	}
	perUser, _, conflicts := ResolveCustomAttributes(users, nil, nil)
	if len(conflicts) != 0 {
		t.Fatalf("expected no conflicts, got %v", conflicts)
	}
	if got := perUser["jsmith"]["phone"]; len(got) != 1 || got[0] != "+1-555-0100" {
		t.Fatalf("expected phone [+1-555-0100], got %v", got)
	}
}

func TestResolveCustomAttributes_UserCustomAttributeIsFlattened(t *testing.T) {
	groups := map[string]Group{
		"engineering": {Name: "engineering", UserCustomAttributes: map[string][]string{"department": {"Engineering"}}},
		"backend":     {Name: "backend", MemberOfGroups: []string{"engineering"}},
	}
	users := map[string]User{
		"jsmith": {Username: "jsmith", MemberOfGroups: []string{"backend"}},
	}
	flattened := ResolveFlattenedMemberOf(users, groups)
	perUser, _, conflicts := ResolveCustomAttributes(users, groups, flattened)
	if len(conflicts) != 0 {
		t.Fatalf("expected no conflicts, got %v", conflicts)
	}
	if got := perUser["jsmith"]["department"]; len(got) != 1 || got[0] != "Engineering" {
		t.Fatalf("expected jsmith to inherit department via transitive membership, got %v", got)
	}
}

func TestResolveCustomAttributes_DirectUserCustomAttributeNotInheritedTransitively(t *testing.T) {
	groups := map[string]Group{
		"engineering": {Name: "engineering", DirectUserCustomAttributes: map[string][]string{"badge": {"eng-direct"}}},
		"backend":     {Name: "backend", MemberOfGroups: []string{"engineering"}},
	}
	users := map[string]User{
		"jsmith": {Username: "jsmith", MemberOfGroups: []string{"backend"}}, // only a transitive member of engineering
		"asmith": {Username: "asmith", MemberOfGroups: []string{"engineering"}},
	}
	flattened := ResolveFlattenedMemberOf(users, groups)
	perUser, _, conflicts := ResolveCustomAttributes(users, groups, flattened)
	if len(conflicts) != 0 {
		t.Fatalf("expected no conflicts, got %v", conflicts)
	}
	if got := perUser["jsmith"]["badge"]; len(got) != 0 {
		t.Fatalf("expected jsmith (transitive-only member) to NOT get directUserCustomAttribute, got %v", got)
	}
	if got := perUser["asmith"]["badge"]; len(got) != 1 || got[0] != "eng-direct" {
		t.Fatalf("expected asmith (direct member) to get directUserCustomAttribute, got %v", got)
	}
}

func TestResolveCustomAttributes_ConflictDroppedAndReported(t *testing.T) {
	groups := map[string]Group{
		"engineering": {Name: "engineering", UserCustomAttributes: map[string][]string{"department": {"Engineering"}}},
		"oncall":      {Name: "oncall", UserCustomAttributes: map[string][]string{"department": {"Oncall"}}},
	}
	users := map[string]User{
		"jsmith": {Username: "jsmith", MemberOfGroups: []string{"engineering", "oncall"}},
	}
	flattened := ResolveFlattenedMemberOf(users, groups)
	perUser, _, conflicts := ResolveCustomAttributes(users, groups, flattened)
	if got := perUser["jsmith"]["department"]; len(got) != 0 {
		t.Fatalf("expected the conflicting attribute to be dropped, got %v", got)
	}
	if len(conflicts) != 1 {
		t.Fatalf("expected exactly one conflict to be reported, got %v", conflicts)
	}
}

func TestResolveCustomAttributes_GroupOwnAttributeNoMerging(t *testing.T) {
	groups := map[string]Group{
		"engineering": {Name: "engineering", CustomAttributes: map[string][]string{"costCenter": {"1234"}}},
	}
	_, perGroup, conflicts := ResolveCustomAttributes(nil, groups, nil)
	if len(conflicts) != 0 {
		t.Fatalf("expected no conflicts, got %v", conflicts)
	}
	if got := perGroup["engineering"]["costCenter"]; len(got) != 1 || got[0] != "1234" {
		t.Fatalf("expected costCenter [1234], got %v", got)
	}
}
