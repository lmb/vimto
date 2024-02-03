package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/BurntSushi/toml"
	docker "github.com/docker/docker/client"
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

func (cfg *config) deriveKernelAndOverlay(cache *imageCache) (vmlinuz, overlay string, _ *image, _ error) {
	if cfg.Kernel == "" {
		return "", "", nil, fmt.Errorf("specify a kernel via -vm.kernel")
	}

	var img *image
	if info, err := os.Stat(cfg.Kernel); errors.Is(err, os.ErrNotExist) {
		// Assume that kernel is a reference to an image.
		cli, err := docker.NewClientWithOpts(docker.FromEnv, docker.WithAPIVersionNegotiation())
		if err != nil {
			return "", "", nil, fmt.Errorf("create docker client: %w", err)
		}
		defer cli.Close()

		img, err = cache.Acquire(context.Background(), cli, cfg.Kernel)
		if err != nil {
			return "", "", nil, fmt.Errorf("retrieve kernel from OCI image: %w", err)
		}

		overlay = img.Directory
		vmlinuz = filepath.Join(img.Directory, imageKernelPath)
	} else if err == nil {
		if info.IsDir() {
			// Kernel is path to an extracted image on disk.
			overlay = cfg.Kernel
			vmlinuz = filepath.Join(overlay, imageKernelPath)
		} else {
			// Kernel is a file on disk.
			vmlinuz = cfg.Kernel
		}
	} else {
		// Unexpected error from stat, maybe not allowed to access it?
		return "", "", nil, fmt.Errorf("kernel: %w", err)
	}

	if _, err := os.Stat(vmlinuz); err != nil {
		if img != nil {
			img.Release()
		}
		return "", "", nil, fmt.Errorf("invalid kernel: %w", err)
	}

	return vmlinuz, overlay, img, nil
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

func configFlags(fs *flag.FlagSet) *config {
	cfg := *defaultConfig
	fs.Func("vm.kernel", "`path or url` to the Linux image", func(s string) error {
		cfg.Kernel = s
		return nil
	})
	fs.Func("vm.memory", "memory to give to the VM", func(s string) error {
		cfg.Memory = s
		return nil
	})
	fs.Func("vm.smp", "", func(s string) error {
		cfg.SMP = s
		return nil
	})
	fs.BoolFunc("vm.sudo", "execute as root", func(s string) error {
		if s != "true" {
			return errors.New("flag only accepts true")
		}

		cfg.User = "root"
		return nil
	})
	return &cfg
}
