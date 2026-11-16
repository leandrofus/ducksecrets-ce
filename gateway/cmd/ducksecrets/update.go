package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/leandrofus/ducksecrets/gateway/internal/selfupdate"
)

func runUpdate(args []string) {
	if err := selfupdate.RunCLI("ducksecrets", version, args); err != nil {
		if err == flag.ErrHelp {
			return
		}
		fmt.Fprintf(os.Stderr, "update failed: %v\n", err)
		os.Exit(1)
	}
}
