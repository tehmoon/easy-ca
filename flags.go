package main

import (
	"flag"
	"os"
)

type GlobalFlags struct {
	Path string
}

func  parseFlags() (*GlobalFlags, []string, error) {
	var (
		path string
		set = flag.NewFlagSet(os.Args[0], flag.ContinueOnError)
	)

	flag.CommandLine = set

	set.StringVar(&path, "path", "", "Path to the easy-ca directory database")

	err := set.Parse(os.Args[1:])
	if err != nil {
		return nil, set.Args(), err
	}

	gf := &GlobalFlags{
		Path: path,
	}

	return gf, set.Args(), nil
}
