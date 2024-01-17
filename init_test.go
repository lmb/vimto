package main

import (
	"testing"

	"github.com/go-quicktest/qt"
)

func TestFsMagic(t *testing.T) {
	for _, mp := range earlyMounts {
		_, ok := fsMagic[mp.fstype]
		qt.Assert(t, qt.IsTrue(ok), qt.Commentf("Unknown magic for fstype %q", mp.fstype))
	}
}
