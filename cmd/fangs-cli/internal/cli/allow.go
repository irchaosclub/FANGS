// SPDX-License-Identifier: Apache-2.0
package cli

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/irchaosclub/FANGS/internal/orchestrator/storage"
)

func (a *app) allowCmd(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return errors.New("allow: expected subcommand (list|add|remove)")
	}
	switch args[0] {
	case "list":
		return a.allowList(ctx, args[1:])
	case "add":
		return a.allowAdd(ctx, args[1:])
	case "remove", "rm":
		return a.allowRemove(ctx, args[1:])
	default:
		return fmt.Errorf("allow: unknown subcommand %q", args[0])
	}
}

func (a *app) allowList(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("allow list", flag.ContinueOnError)
	pkg := fs.String("package", "", "filter to a specific package (omit: show all)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	all, err := a.store.ListAllowEntries(ctx)
	if err != nil {
		return err
	}
	rows := all
	if *pkg != "" {
		rows = storage.EntriesForPackage(all, *pkg)
	}
	if a.asJSON {
		return renderJSON(a.out, rows)
	}
	if len(rows) == 0 {
		fmt.Fprintln(a.out, "no allowlist entries.")
		fmt.Fprintln(a.out, "  fangs allow add -kind cidr  -value 10.0.0.0/8 -note 'internal net'")
		fmt.Fprintln(a.out, "  fangs allow add -kind sni   -value telemetry.internal -package my-pkg")
		return nil
	}
	headers := []string{"ID", "SCOPE", "PACKAGE", "KIND", "VALUE", "NOTE", "CREATED"}
	tbl := make([][]string, 0, len(rows))
	for _, e := range rows {
		scope := string(e.Scope)
		pkgCol := e.PackageName
		if pkgCol == "" {
			pkgCol = "—"
		}
		tbl = append(tbl, []string{
			shortID(e.ID), scope, pkgCol, string(e.Kind), truncate(e.Value, 40),
			truncate(e.Note, 30), e.CreatedAt.Format(time.RFC3339),
		})
	}
	renderTable(a.out, headers, tbl)
	return nil
}

func (a *app) allowAdd(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("allow add", flag.ContinueOnError)
	kind := fs.String("kind", "", "cidr | path | sni (required)")
	value := fs.String("value", "", "the rule value (CIDR, path prefix, or SNI string)")
	pkg := fs.String("package", "", "scope to a specific package (omit = global)")
	note := fs.String("note", "", "free-form comment")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *kind == "" || *value == "" {
		return errors.New("allow add: -kind and -value required")
	}
	k := storage.AllowKind(*kind)
	switch k {
	case storage.AllowKindCIDR:
		if _, _, err := net.ParseCIDR(*value); err != nil {
			return fmt.Errorf("allow add: -value is not a valid CIDR: %w", err)
		}
	case storage.AllowKindPath:
		if !strings.HasPrefix(*value, "/") {
			return errors.New("allow add: path values should be absolute (start with /)")
		}
	case storage.AllowKindSNI:
		// no structural check — SNI strings are operator-supplied
	default:
		return fmt.Errorf("allow add: unknown -kind %q (cidr|path|sni)", *kind)
	}

	scope := storage.AllowScopeGlobal
	if *pkg != "" {
		scope = storage.AllowScopePackage
	}
	entry := storage.AllowEntry{
		ID:          newAllowID(),
		Scope:       scope,
		PackageName: *pkg,
		Kind:        k,
		Value:       *value,
		Note:        *note,
		CreatedAt:   time.Now().UTC(),
	}
	if err := a.store.AddAllowEntry(ctx, entry); err != nil {
		return err
	}
	if scope == storage.AllowScopeGlobal {
		fmt.Fprintf(a.out, "added global %s allowlist entry %s — %s\n", k, shortID(entry.ID), *value)
	} else {
		fmt.Fprintf(a.out, "added %s/%s allowlist entry %s — %s\n", *pkg, k, shortID(entry.ID), *value)
	}
	return nil
}

func (a *app) allowRemove(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return errors.New("allow remove: expected <id_prefix>")
	}
	e, err := a.store.ResolveAllowPrefix(ctx, args[0])
	if errors.Is(err, storage.ErrAmbiguous) {
		return fmt.Errorf("allow remove: prefix %q matches more than one entry; use a longer prefix", args[0])
	}
	if errors.Is(err, storage.ErrNotFound) {
		return fmt.Errorf("allow remove: no entry matches %q", args[0])
	}
	if err != nil {
		return err
	}
	if err := a.store.DeleteAllowEntry(ctx, e.ID); err != nil {
		return err
	}
	fmt.Fprintf(a.out, "removed %s allowlist entry %s\n", e.Kind, shortID(e.ID))
	return nil
}

func newAllowID() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
