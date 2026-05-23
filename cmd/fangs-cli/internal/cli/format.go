// SPDX-License-Identifier: Apache-2.0
package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
)

// renderTable writes header + rows as aligned columns. row count = 0
// emits "(none)".
func renderTable(w io.Writer, header []string, rows [][]string) {
	if len(rows) == 0 {
		fmt.Fprintln(w, "(none)")
		return
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, strings.Join(header, "\t"))
	for _, r := range rows {
		fmt.Fprintln(tw, strings.Join(r, "\t"))
	}
	_ = tw.Flush()
}

// renderJSON marshals v as indented JSON.
func renderJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// truncate returns s capped to n chars (with a "…" suffix if cut).
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n <= 1 {
		return s[:n]
	}
	return s[:n-1] + "…"
}

// shortID returns the first 12 chars of an id — enough for prefix
// matching in a typical FANGS install (low collision probability among
// concurrent runs). Use the displayed prefix directly with
// `fangs run show <prefix>`.
func shortID(id string) string {
	if len(id) <= 12 {
		return id
	}
	return id[:12]
}
