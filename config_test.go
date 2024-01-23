package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/BurntSushi/toml"
	"github.com/go-quicktest/qt"
)

func TestParseConfigFromTOML(t *testing.T) {
	tmp := t.TempDir()

	want := &config{"A", "B", "C", "", nil, nil}

	have := *want
	qt.Assert(t, qt.IsNil(parseConfigFromTOML(tmp, &have)))
	qt.Assert(t, qt.DeepEquals(&have, want),
		qt.Commentf("config shouldn't change if file doesn't exist"))

	toml := []byte(`
kernel = "foo"
memory = "bar"
`)

	err := os.WriteFile(filepath.Join(tmp, configFileName), toml, 0644)
	qt.Assert(t, qt.IsNil(err))

	qt.Assert(t, qt.IsNil(parseConfigFromTOML(tmp, &have)))
	qt.Assert(t, qt.DeepEquals(&have, &config{
		"foo", "bar", want.SMP, want.User, nil, nil,
	}))
}

func TestRefuseExtraneousConfig(t *testing.T) {
	tmp := t.TempDir()

	mustWriteConfig(t, tmp, `bazbar = 1`)
	qt.Assert(t, qt.ErrorIs(parseConfigFromTOML(tmp, &config{}), errUnrecognisedKeys))
}

func TestFindGitRoot(t *testing.T) {
	root, err := findGitRoot(t.TempDir())
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(root, ""))

	wd, err := os.Getwd()
	qt.Assert(t, qt.IsNil(err))

	root, err = findGitRoot(".")
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(root, wd))
}

func TestFindConfigFile(t *testing.T) {
	root := t.TempDir()
	output, err := exec.Command("git", "-C", root, "init").CombinedOutput()
	qt.Assert(t, qt.IsNil(err), qt.Commentf("output: %s", string(output)))

	_, err = findConfigFile(root)
	qt.Assert(t, qt.ErrorIs(err, os.ErrNotExist))

	subdir := filepath.Join(root, "subdir")
	qt.Assert(t, qt.IsNil(os.Mkdir(subdir, 0755)))

	rootCfg := mustWriteConfig(t, root, `foo=1`)
	f, err := findConfigFile(subdir)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(f.Name(), rootCfg))

	subdirCfg := mustWriteConfig(t, subdir, `foo=2`)
	f, err = findConfigFile(subdir)
	qt.Assert(t, qt.IsNil(err))
	f.Close()
	qt.Assert(t, qt.Equals(f.Name(), subdirCfg))

	f, err = findConfigFile(root)
	qt.Assert(t, qt.IsNil(err))
	f.Close()
	qt.Assert(t, qt.Equals(f.Name(), rootCfg))
}

func TestWriteConfig(t *testing.T) {
	f, err := os.Create("testdata/default.toml")
	qt.Assert(t, qt.IsNil(err))
	defer f.Close()
	qt.Assert(t, qt.IsNil(toml.NewEncoder(f).Encode(defaultConfig)))
}

func mustWriteConfig(tb testing.TB, dir, contents string) string {
	tb.Helper()
	filename := filepath.Join(dir, configFileName)
	qt.Assert(tb, qt.IsNil(os.WriteFile(filename, []byte(contents), 0644)))
	return filename
}
