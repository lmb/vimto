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
	"github.com/kballard/go-shellquote"
)

type config struct {
	Kernel   string          `toml:"kernel"`
	Memory   string          `toml:"memory"`
	SMP      string          `toml:"smp"`
	User     string          `toml:"user"`
	Setup    []configCommand `toml:"setup"`
	Teardown []configCommand `toml:"teardown"`
}

type configCommand []string

func (cc *configCommand) UnmarshalText(text []byte) error {
	words, err := shellquote.Split(string(text))
	if err != nil {
		return err
	}

	*cc = configCommand(words)
	return nil
}

func (cc *configCommand) MarshalText() ([]byte, error) {
	return []byte(shellquote.Join(*cc...)), nil
}

var defaultConfig = &config{
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
