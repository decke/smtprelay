//go:build !linux

package main

import (
	"fmt"
	"os"
)

func enableLinuxJournal() {
	fmt.Println("Not supported")
	os.Exit(0)
}
