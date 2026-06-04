package main

import (
	"errors"
	"flag"
	"fmt"
	"os"

	"runveil/internal/policy"
)

func runTestPolicy(args []string) {
	fs := flag.NewFlagSet("test-policy", flag.ExitOnError)
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, "usage: runveil test-policy <path>\n")
		fs.PrintDefaults()
	}
	_ = fs.Parse(args)

	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "test-policy: <path> argument is required")
		fs.Usage()
		os.Exit(2)
	}
	path := fs.Arg(0)

	p, err := policy.LoadFromFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			fmt.Fprintf(os.Stderr, "test-policy: %s: file not found\n", path)
			os.Exit(1)
		}
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
	fmt.Printf("%s: ok (%d rules)\n", path, len(p.Rules))
}
