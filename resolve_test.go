package license

import (
	"testing"
)

func TestResolveModules_NoRequirements(t *testing.T) {
	c := &LicenseClaims{Modules: []ModuleEntry{
		{Code: "a"},
		{Code: "b"},
	}}
	res := c.ResolveModules()
	if len(res.Codes) != 2 || len(res.Filtered) != 0 {
		t.Fatalf("Codes=%v Filtered=%v, want both granted", res.Codes, res.Filtered)
	}
}

func TestResolveModules_RequiresAllSatisfied(t *testing.T) {
	c := &LicenseClaims{Modules: []ModuleEntry{
		{Code: "a"},
		{Code: "b", Requires: []string{"a"}},
	}}
	res := c.ResolveModules()
	want := []string{"a", "b"}
	if !sameStrings(res.Codes, want) {
		t.Errorf("Codes=%v, want %v", res.Codes, want)
	}
	if len(res.Filtered) != 0 {
		t.Errorf("Filtered=%v, want none", res.Filtered)
	}
}

func TestResolveModules_RequiresMissing(t *testing.T) {
	c := &LicenseClaims{Modules: []ModuleEntry{
		{Code: "b", Requires: []string{"a"}},
	}}
	res := c.ResolveModules()
	if !sameStrings(res.Codes, []string{}) {
		t.Errorf("Codes=%v, want none", res.Codes)
	}
	if !sameStrings(res.Filtered, []string{"b"}) {
		t.Errorf("Filtered=%v, want [b]", res.Filtered)
	}
}

func TestResolveModules_RequiresAnyOneGranted(t *testing.T) {
	c := &LicenseClaims{Modules: []ModuleEntry{
		{Code: "a"},
		{Code: "b", RequiresAny: []string{"a", "x"}},
	}}
	res := c.ResolveModules()
	if !sameStrings(res.Codes, []string{"a", "b"}) {
		t.Errorf("Codes=%v, want [a b]", res.Codes)
	}
	if len(res.Filtered) != 0 {
		t.Errorf("Filtered=%v, want none", res.Filtered)
	}
}

func TestResolveModules_RequiresAnyNoneGranted(t *testing.T) {
	c := &LicenseClaims{Modules: []ModuleEntry{
		{Code: "b", RequiresAny: []string{"a", "x"}},
	}}
	res := c.ResolveModules()
	if !sameStrings(res.Codes, []string{}) {
		t.Errorf("Codes=%v, want none", res.Codes)
	}
	if !sameStrings(res.Filtered, []string{"b"}) {
		t.Errorf("Filtered=%v, want [b]", res.Filtered)
	}
}

func TestResolveModules_Transitive(t *testing.T) {
	c := &LicenseClaims{Modules: []ModuleEntry{
		{Code: "a"},
		{Code: "b", Requires: []string{"a"}},
		{Code: "c", Requires: []string{"b"}},
	}}
	res := c.ResolveModules()
	if !sameStrings(res.Codes, []string{"a", "b", "c"}) {
		t.Errorf("Codes=%v, want [a b c]", res.Codes)
	}
	if len(res.Filtered) != 0 {
		t.Errorf("Filtered=%v, want none", res.Filtered)
	}
}

func TestResolveModules_TransitiveMissing(t *testing.T) {
	c := &LicenseClaims{Modules: []ModuleEntry{
		{Code: "b", Requires: []string{"a"}},
		{Code: "c", Requires: []string{"b"}},
	}}
	res := c.ResolveModules()
	if !sameStrings(res.Codes, []string{}) {
		t.Errorf("Codes=%v, want none", res.Codes)
	}
	if !sameStrings(res.Filtered, []string{"b", "c"}) {
		t.Errorf("Filtered=%v, want [b c]", res.Filtered)
	}
}

func TestResolveModules_Nil(t *testing.T) {
	var c *LicenseClaims
	res := c.ResolveModules()
	if len(res.Codes) != 0 || len(res.Filtered) != 0 {
		t.Fatalf("nil claims: Codes=%v Filtered=%v, want empty", res.Codes, res.Filtered)
	}
}

func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	seen := make(map[string]int, len(a))
	for _, s := range a {
		seen[s]++
	}
	for _, s := range b {
		seen[s]--
		if seen[s] < 0 {
			return false
		}
	}
	return true
}
