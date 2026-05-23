// SPDX-License-Identifier: Apache-2.0
package ui

import "net/http"

func (h *Handler) handleNotifiers(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	rows, err := h.store.ListNotifiers(ctx)
	if err != nil {
		h.logger.Warn("ui notifiers: ListNotifiers", "err", err)
	}
	h.render(w, "notifiers", map[string]any{
		"Notifiers": rows,
	})
}
