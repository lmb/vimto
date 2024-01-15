package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/BurntSushi/toml"
)

type config struct {
	Kernel string `toml:"kernel"`
	Memory string `toml:"memory"`
	SMP    string `toml:"smp"`
}

const configFileName = ".vimto.toml"

var errUnrecognisedKeys = errors.New("unrecognised key(s)")

func parseConfigFromTOML(dir string, cfg *config) error {
	f, err := findConfigFile(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return nil
	}
	defer f.Close()

	md, err := toml.NewDecoder(f).Decode(cfg)
	if err != nil {
		return fmt.Errorf("read %q: %w", f.Name(), err)
	}

	if len(md.Undecoded()) == 0 {
		return nil
	}

	var keys []string
	for _, key := range md.Undecoded() {
		keys = append(keys, strings.Join(key, "."))
	}

	return fmt.Errorf("%q: %w: %s", f.Name(), errUnrecognisedKeys, strings.Join(keys, ", "))
}

func findConfigFile(dir string) (*os.File, error) {
	dirs := []string{dir}
	root, err := findGitRoot(dir)
	if err != nil {
		return nil, err
	}
	if root != "" {
		dirs = append(dirs, root)
	}

	for _, dir := range dirs {
		f, err := os.Open(filepath.Join(dir, configFileName))
		if err == nil {
			return f, nil
		}
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		return nil, err
	}

	return nil, os.ErrNotExist
}

func findGitRoot(dir string) (string, error) {
	git := exec.Command("git", "rev-parse", "--show-toplevel")
	git.Dir = dir
	output, err := git.CombinedOutput()
	if errors.Is(err, exec.ErrNotFound) {
		return "", nil
	}

	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		// Not a git directory
		return "", nil
	}

	if err != nil {
		return "", err
	}

	path := string(bytes.TrimSpace(output))
	if !filepath.IsAbs(path) {
		path = filepath.Join(dir, path)
	}

	return path, nil
}