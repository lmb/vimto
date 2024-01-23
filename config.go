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
	Memory: "size=128M",
	SMP:    "cpus=1",
	Setup: []configCommand{
		[]string{"ip", "link", "set", "dev", "lo", "up"},
	},
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

func defaultConfigAndFlags() (*config, *flag.FlagSet) {
	cfg := *defaultConfig
	fs := flag.NewFlagSet("vimto", flag.ContinueOnError)
	fs.StringVar(&cfg.Kernel, "vm.kernel", defaultConfig.Kernel, "`path or url` to the Linux image")
	fs.StringVar(&cfg.Memory, "vm.memory", defaultConfig.Memory, "memory to give to the VM")
	fs.StringVar(&cfg.SMP, "vm.smp", defaultConfig.SMP, "")
	fs.BoolFunc("vm.sudo", "execute as root", func(s string) error {
		if s != "true" {
			return errors.New("flag only accepts true")
		}

		cfg.User = "root"
		return nil
	})

	return &cfg, fs
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
