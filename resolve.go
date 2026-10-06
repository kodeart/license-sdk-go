package license

// ModuleResolution is the result of resolving a license's module list against
// its dependency requirements. Codes are the modules a consumer may build;
// Filtered lists the granted modules that were skipped because a dependency
// was not granted. It is the SDK's answer to "which of these modules can I
// actually use", mirroring the server's product_modules.requires validation.
type ModuleResolution struct {
	Codes    []string
	Filtered []string
}

// ResolveModules returns the modules that are usable given their Requires (all
// listed codes must be granted) and RequiresAny (at least one of the listed
// codes must be granted) requirements. The license-server rejects invalid
// combinations at issuance, so this is a safety net rather than the primary
// rule. Resolution runs to a fixpoint so transitive requirements clear too.
func (c *LicenseClaims) ResolveModules() ModuleResolution {
	if c == nil {
		return ModuleResolution{}
	}

	usable := make(map[string]struct{})
	for _, m := range c.Modules {
		if requirementsMet(m, usable) {
			usable[m.Code] = struct{}{}
		}
	}

	// A module whose requirements only clear after a dependency above was added
	// must be picked up on a later pass. Repeat until nothing changes.
	for {
		added := false
		for _, m := range c.Modules {
			if _, ok := usable[m.Code]; ok {
				continue
			}
			if requirementsMet(m, usable) {
				usable[m.Code] = struct{}{}
				added = true
			}
		}
		if !added {
			break
		}
	}

	res := ModuleResolution{}
	for _, m := range c.Modules {
		if _, ok := usable[m.Code]; ok {
			res.Codes = append(res.Codes, m.Code)
		} else {
			res.Filtered = append(res.Filtered, m.Code)
		}
	}
	return res
}

// requirementsMet checks all-requires and at-least-one-requires-any against a
// set of granted codes. A module with no requirements is always usable.
func requirementsMet(m ModuleEntry, usable map[string]struct{}) bool {
	for _, req := range m.Requires {
		if _, ok := usable[req]; !ok {
			return false
		}
	}
	if len(m.RequiresAny) == 0 {
		return true
	}
	for _, req := range m.RequiresAny {
		if _, ok := usable[req]; ok {
			return true
		}
	}
	return false
}
