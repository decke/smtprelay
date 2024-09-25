//go:build linux

package main

import (
	"github.com/wercker/journalhook"
)

func enableLinuxJournal() {
	journalhook.Enable()
}
