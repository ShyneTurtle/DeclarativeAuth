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
