//go:build !linux && !android

// The probe walks BPF program IDs through the bpf() syscall, which only exists
// on Linux and Android. This stub keeps the package buildable, and therefore
// lintable, on every other platform.

package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "statsprobe only runs on linux and android")
	os.Exit(1)
}
