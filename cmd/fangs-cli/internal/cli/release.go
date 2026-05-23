// SPDX-License-Identifier: Apache-2.0
package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
)

func (a *app) releaseCmd(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return errors.New("release: missing subcommand (list)")
	}
	switch args[0] {
	case "list":
		return a.releaseList(ctx, args[1:])
	default:
		return fmt.Errorf("release: unknown subcommand %q", args[0])
	}
}

func (a *app) releaseList(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("release list", flag.ContinueOnError)
	fs.SetOutput(a.err)
	pkg := fs.String("package", "", "package_name (required)")
	limit := fs.Int("limit", 50, "max rows")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *pkg == "" {
		return errors.New("release list: -package is required")
	}
	rels, err := a.store.ListReleasesByPackage(ctx, *pkg, *limit)
	if err != nil {
		return err
	}
	if a.asJSON {
		return renderJSON(a.out, rels)
	}
	rows := make([][]string, 0, len(rels))
	for _, r := range rels {
		published := "-"
		if !r.PublishedAt.IsZero() {
			published = r.PublishedAt.UTC().Format("2006-01-02 15:04:05")
		}
		discovered := r.DiscoveredAt.UTC().Format("2006-01-02 15:04:05")
		rows = append(rows, []string{r.PackageName, r.Version, published, discovered, truncate(r.TarballSHA256, 16)})
	}
	renderTable(a.out, []string{"PACKAGE", "VERSION", "PUBLISHED", "DISCOVERED", "TARBALL_SHA"}, rows)
	return nil
}
