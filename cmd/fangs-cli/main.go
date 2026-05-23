// SPDX-License-Identifier: Apache-2.0
//
// fangs-cli is the operator console — query runs / deviations /
// baselines and promote / reject runs. Talks directly to the storage
// backend (sqlite default, postgres opt-in) the same way the
// orchestrator does, so an operator running this on the orchestrator
// host sees the same data the orchestrator persisted.
//
// Usage:
//
//	fangs run list [-package P] [-limit N]
//	fangs run show <run_id>
//	fangs deviation list [-package P] [-severity warn] [-run-id R] [-limit N]
//	fangs deviation show <deviation_id>
//	fangs baseline list [-package P]
//	fangs baseline promote <run_id>
//	fangs package list
//
// Global flags:
//
//	-storage      sqlite|postgres|none  (default: sqlite)
//	-sqlite-path  /var/lib/fangs/fangs.db
//	-postgres-dsn $FANGS_PG_DSN
//	-json         emit JSON instead of table
package main

import (
	"context"
	"fmt"
	"os"

	"github.com/irchaosclub/FANGS/cmd/fangs-cli/internal/cli"
)

func main() {
	ctx := context.Background()
	if err := cli.Run(ctx, os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "fangs:", err)
		os.Exit(1)
	}
}
