package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/BurntSushi/toml"
)

type config struct {
	Kernel   string          `toml:"kernel"`
	Userland string          `toml:"userland"`
	Volumes  []string        `toml:"volumes"`
	Memory   string          `toml:"memory"`
	SMP      string          `toml:"smp"`
	User     string          `toml:"user"`
	GDB      string          `toml:"-"`
	Console  bool            `toml:"-"`
	Setup    []configCommand `toml:"setup"`
	Teardown []configCommand `toml:"teardown"`
}

var defaultConfig = &config{
	Volumes:  []string{},
	Memory:   "size=128M",
	SMP:      "cpus=1",
	Setup:    []configCommand{},
	Teardown: []configCommand{},
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

func configFlags(name string, cfg *config) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.Func("kernel", "`path or url` to the Linux image (use ':tag' to substitute tag in url)", func(s string) error {
		if !strings.HasPrefix(s, ":") {
			cfg.Kernel = s
			return nil
		}

		tag := s[1:]
		if strings.Contains(tag, ":") {
			return fmt.Errorf("tag %q contains colons", tag)
		}
		image, _, found := strings.Cut(cfg.Kernel, ":")
		if !found {
			return fmt.Errorf("no tag in image %q (missing colon)", cfg.Kernel)
		}

		cfg.Kernel = fmt.Sprintf("%s:%s", image, tag)
		return nil
	})
	fs.Func("userland", "`path or url` of an OCI image containing the guest's userland, for example 'alpine:latest'", func(s string) error {
		cfg.Userland = s
		return nil
	})
	fs.Func("volume", "`host:guest` mapping of a directory shared with the VM (repeatable)", func(s string) error {
		cfg.Volumes = append(cfg.Volumes, s)
		return nil
	})
	fs.Func("memory", "memory to give to the VM", func(s string) error {
		cfg.Memory = s
		return nil
	})
	fs.Func("smp", "", func(s string) error {
		cfg.SMP = s
		return nil
	})
	fs.BoolFunc("sudo", "execute as root", func(s string) error {
		if s != "true" {
			return errors.New("flag only accepts true")
		}

		cfg.User = "root"
		return nil
	})
	fs.BoolFunc("gdb", "enable GDB server", func(s string) error {
		if s != "true" {
			return errors.New("flag only accepts true")
		}

		cfg.GDB = "localhost:1234"
		return nil
	})
	fs.BoolFunc("console", "stream the guest's console to stderr", func(s string) error {
		if s != "true" {
			return errors.New("flag only accepts true")
		}

		cfg.Console = true
		return nil
	})

	return fs
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
