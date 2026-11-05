//go:build !linux && !android

// The probe drives sockets and reads cgroup state, which only exist on Linux and
// Android. This stub keeps the package buildable, and therefore lintable, on
// every other platform.

package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "trafficgen only runs on linux and android")
	os.Exit(1)
}
