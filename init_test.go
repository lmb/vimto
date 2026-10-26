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

func TestCheckBaseShadowing(t *testing.T) {
	mustMkdirAll := func(parts ...string) {
		t.Helper()
		qt.Assert(t, qt.IsNil(os.MkdirAll(filepath.Join(parts...), 0755)))
	}

	// An usrmerged base, e.g. the host root.
	base := t.TempDir()
	mustMkdirAll(base, "usr/lib")
	qt.Assert(t, qt.IsNil(os.Symlink("usr/lib", filepath.Join(base, "lib"))))

	kernel := t.TempDir()
	qt.Assert(t, qt.IsNil(checkLayerShadowing(base, kernel)), qt.Commentf("empty kernel image"))

	mustMkdirAll(kernel, "usr/lib/modules")
	qt.Assert(t, qt.IsNil(checkLayerShadowing(base, kernel)), qt.Commentf("modules in /usr"))

	qt.Assert(t, qt.IsNil(os.Symlink("usr/lib", filepath.Join(kernel, "lib"))))
	qt.Assert(t, qt.IsNil(checkLayerShadowing(base, kernel)), qt.Commentf("symlink over symlink"))

	qt.Assert(t, qt.IsNil(os.Remove(filepath.Join(kernel, "lib"))))
	mustMkdirAll(kernel, "lib")
	qt.Assert(t, qt.ErrorIs(checkLayerShadowing(base, kernel), errShadowedPath), qt.Commentf("directory over symlink"))

	// A base with a real /lib, e.g. alpine.
	base = t.TempDir()
	mustMkdirAll(base, "lib")
	qt.Assert(t, qt.IsNil(checkLayerShadowing(base, kernel)), qt.Commentf("directory over directory"))

	qt.Assert(t, qt.IsNil(os.RemoveAll(filepath.Join(kernel, "lib"))))
	qt.Assert(t, qt.IsNil(os.Symlink("usr/lib", filepath.Join(kernel, "lib"))))
	qt.Assert(t, qt.ErrorIs(checkLayerShadowing(base, kernel), errShadowedPath), qt.Commentf("symlink over directory"))
}

func TestEnsurePathBinDirs(t *testing.T) {
	env := []string{
		"HOME=/root",
		"PATH=/usr/local/bin:/usr/bin",
	}

	env = ensurePathBinDirs(env)
	qt.Assert(t, qt.Equals(env[0], "HOME=/root"))
	qt.Assert(t, qt.Equals(env[1], "PATH=/usr/local/bin:/usr/bin:/usr/local/sbin:/usr/sbin:/sbin:/bin"))
}
