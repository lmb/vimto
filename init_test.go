package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/go-quicktest/qt"
)

func TestFsMagic(t *testing.T) {
	for _, mp := range earlyMounts {
		_, ok := fsMagic[mp.fstype]
		qt.Check(t, qt.IsTrue(ok), qt.Commentf("Unknown magic for fstype %q", mp.fstype))
	}
}

func TestCheckHostShadowing(t *testing.T) {
	root := t.TempDir()
	mustMkdirAll(t, root, "usr/lib")
	qt.Assert(t, qt.IsNil(os.Symlink("usr/lib", filepath.Join(root, "lib"))))

	overlay := t.TempDir()
	mustMkdirAll(t, overlay, "usr/lib")
	qt.Assert(t, qt.IsNil(checkHostShadowing(root, overlay)), qt.Commentf("Nothing shadows"))

	qt.Assert(t, qt.IsNil(os.Symlink("usr/lib", filepath.Join(overlay, "lib"))))
	qt.Assert(t, qt.IsNil(checkHostShadowing(root, overlay)), qt.Commentf("Symlink shadow"))

	qt.Assert(t, qt.IsNil(os.Remove(filepath.Join(overlay, "lib"))))
	mustMkdirAll(t, overlay, "lib")
	qt.Assert(t, qt.ErrorIs(checkHostShadowing(root, overlay), errShadowedDirectory), qt.Commentf("Directory shadows symlink"))
}

func mustMkdirAll(tb testing.TB, parts ...string) {
	tb.Helper()

	qt.Assert(tb, qt.IsNil(os.MkdirAll(filepath.Join(parts...), 0755)))
}
