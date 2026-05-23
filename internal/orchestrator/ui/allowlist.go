// SPDX-License-Identifier: Apache-2.0
package ui

import "net/http"

func (h *Handler) handleAllowlist(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	pkg := r.URL.Query().Get("package")

	all, err := h.store.ListAllowEntries(ctx)
	if err != nil {
		h.logger.Warn("ui allowlist: ListAllowEntries", "err", err)
	}

	// Split into global vs package-scoped for the template; both lists
	// stay sorted in the order storage returned (scope, package, kind).
	type bucket struct {
		Global  []any
		ByPkg   map[string][]any
		PkgList []string // stable iteration order
	}
	view := bucket{ByPkg: map[string][]any{}}
	for _, e := range all {
		// Optional ?package filter narrows to ONE package's bucket plus globals.
		if pkg != "" && e.PackageName != "" && e.PackageName != pkg {
			continue
		}
		switch e.PackageName {
		case "":
			view.Global = append(view.Global, e)
		default:
			view.ByPkg[e.PackageName] = append(view.ByPkg[e.PackageName], e)
		}
	}
	for k := range view.ByPkg {
		view.PkgList = append(view.PkgList, k)
	}
	// Stable display order.
	sortStrings(view.PkgList)

	h.render(w, "allowlist", map[string]any{
		"Global":   view.Global,
		"ByPkg":    view.ByPkg,
		"PkgList":  view.PkgList,
		"Filter":   pkg,
		"Total":    len(all),
		"Filtered": len(view.Global) + sumLens(view.ByPkg),
	})
}

func sumLens(m map[string][]any) int {
	n := 0
	for _, v := range m {
		n += len(v)
	}
	return n
}

func sortStrings(s []string) {
	// Insertion sort — tiny lists; stdlib sort would also work fine.
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j-1] > s[j]; j-- {
			s[j-1], s[j] = s[j], s[j-1]
		}
	}
}
