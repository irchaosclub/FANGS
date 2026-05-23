// SPDX-License-Identifier: Apache-2.0
package ui

import (
	"errors"
	"net/http"
	"sort"

	"github.com/irchaosclub/FANGS/internal/orchestrator/storage"
)

func (h *Handler) handlePackages(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	pkgs, err := h.store.ListPackages(ctx)
	if err != nil {
		h.logger.Warn("ui packages: ListPackages", "err", err)
	}
	sort.Slice(pkgs, func(i, j int) bool { return pkgs[i].Name < pkgs[j].Name })

	watched, _ := h.store.ListWatchedPackages(ctx)
	watchSet := map[string]bool{}
	for _, w := range watched {
		watchSet[w.Name] = true
	}

	h.render(w, "packages", map[string]any{
		"Packages": pkgs,
		"Watched":  watchSet,
	})
}

func (h *Handler) handlePackageDetail(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if name == "" {
		http.NotFound(w, r)
		return
	}
	ctx := r.Context()

	runs, err := h.store.ListRunsByPackage(ctx, name, 50)
	if err != nil && !errors.Is(err, storage.ErrNotFound) {
		h.logger.Warn("ui package: ListRunsByPackage", "err", err)
	}

	releases, err := h.store.ListReleasesByPackage(ctx, name, 50)
	if err != nil && !errors.Is(err, storage.ErrNotFound) {
		h.logger.Warn("ui package: ListReleasesByPackage", "err", err)
	}

	baseline, err := h.store.LoadBaseline(ctx, name)
	if err != nil {
		h.logger.Warn("ui package: LoadBaseline", "err", err)
	}

	h.render(w, "package_detail", map[string]any{
		"PackageName":  name,
		"Runs":         runs,
		"Releases":     releases,
		"Baseline":     baseline,
		"BaselineSize": len(baseline),
	})
}
