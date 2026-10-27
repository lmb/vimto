package main

import (
	"context"
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"slices"
	"strings"

	"github.com/kballard/go-shellquote"
	"golang.org/x/sys/unix"
	"lmb.io/vimto/internal/guest"
)

func main() {
	err := run(os.Args[1:])
	if err == nil || errors.Is(err, flag.ErrHelp) {
		return
	}

	var exitError *guest.ExitError
	if errors.As(err, &exitError) {
		os.Exit(exitError.ExitCode)
	}

	fmt.Fprintln(os.Stderr, "Error:", err)
	os.Exit(128)
}

var usage = `
Usage: %s [flags] [command] [--] ...

Available commands:
	exec        Execute a command inside a VM
	flush-cache Clear the image cache

Environment:
	GOARCH      Boot a guest of the given architecture, using emulation if
	            necessary. Requires -userland since the host's binaries can't
	            be executed by the guest.

Flags:
`

func run(args []string) error {
	cfg := *defaultConfig
	fs := configFlags("vimto", &cfg)
	fs.Usage = func() {
		o := fs.Output()
		fmt.Fprintf(o, strings.TrimSpace(usage), fs.Name())
		fs.PrintDefaults()
	}
	if err := parseConfigFromTOML(".", &cfg); err != nil {
		return fmt.Errorf("read config: %w", err)
	}
	if err := fs.Parse(args); err != nil {
		return err
	}

	if fs.NArg() < 1 {
		return fmt.Errorf("expected at least one argument")
	}

	var err error
	switch cmd := fs.Arg(0); {
	case cmd == "exec":
		err = execCmd(&cfg, fs.Args()[1:])

	case cmd == "flush-cache":
		err = flushCacheCmd(fs.Args()[1:])

	case strings.HasPrefix(cmd, "go"):
		// This is an invocation of go test, possibly via a pre-relase binary
		// like go1.21rc2.
		var flags []string
		flags, err = splitFlagsFromArgs(args)
		if err != nil {
			return err
		}

		err = goTestCmd(&cfg, flags, cmd, fs.Args()[1:])

	default:
		fs.Usage()
		return fmt.Errorf("unknown command %q", fs.Arg(0))
	}

	if err != nil {
		return fmt.Errorf("%s: %w", fs.Arg(0), err)
	}

	return nil
}

// goTestCmd executes a go test command inside a VM.
func goTestCmd(cfg *config, flags []string, goBinary string, goArgs []string) error {
	if len(goArgs) < 1 || goArgs[0] != "test" {
		return fmt.Errorf("first argument to go binary must be 'test'")
	}

	for _, arg := range goArgs {
		if strings.HasPrefix(arg, "-exec") {
			return fmt.Errorf("specifying -exec on the go command line is not supported")
		}
	}

	if cfg.GDB != "" {
		return fmt.Errorf("can't enable gdb integration when invoking via go toolchain")
	}

	exe, err := findExecutable()
	if err != nil {
		return err
	}

	arch := guestArch()
	if err := checkUserland(cfg, arch); err != nil {
		return err
	}

	// Prime the cache before invoking the go binary.
	bf, err := findBootFiles(cfg.Kernel, arch)
	if err != nil {
		return err
	}
	defer bf.Image.Close()

	// Fetch the userland first before invoking go, since it renders animated
	// output.
	if cfg.Userland != "" {
		_, img, err := findUserland(cfg.Userland, arch)
		if err != nil {
			return err
		}
		defer img.Close()
	}

	execArgs := []string{exe}
	// Retain command line arguments
	// TODO: Make -kernel parameter absolute?
	execArgs = append(execArgs, flags...)
	// Execute exec command and ignore all test flags.
	execArgs = append(execArgs, "exec", "--")

	goArgs = slices.Insert(goArgs, 1, "-exec", shellquote.Join(execArgs...))

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	cmd := commandWithGracefulTermination(ctx, goBinary, goArgs...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func execCmd(cfg *config, args []string) error {
	fs := flag.NewFlagSet("exec", flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: %s [--] </path/to/binary> [flags of binary]\n", fs.Name())
		fmt.Fprintln(fs.Output())
		fs.PrintDefaults()
		fmt.Fprintln(fs.Output())
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	if fs.NArg() < 1 {
		fs.Usage()
		return fmt.Errorf("missing arguments")
	}

	arch := guestArch()
	if err := checkUserland(cfg, arch); err != nil {
		return err
	}

	bf, err := findBootFiles(cfg.Kernel, arch)
	if err != nil {
		return err
	}
	defer bf.Image.Close()

	var userland string
	if cfg.Userland != "" {
		dir, img, err := findUserland(cfg.Userland, arch)
		if err != nil {
			return err
		}
		defer img.Close()
		userland = dir
	}

	if cfg.GDB != "" {
		fmt.Println("Starting GDB server with CPU halted, connect using:")
		args := []string{
			"-ex", fmt.Sprintf("target remote %s", cfg.GDB),
		}
		if bf.Overlay != "" {
			if strings.Contains(bf.Overlay, ":") {
				// Can't figure out how to avoid gdb interpreting the colon
				// as a directory separator.
				return fmt.Errorf("path %q contains a colon", bf.Overlay)
			}
			args = append(args, "-ex", fmt.Sprintf("dir %q", bf.Overlay))
		}

		kernel := bf.Kernel
		if bf.Symbols != "" {
			kernel = bf.Symbols
		}
		fmt.Printf("\tgdb %s %s\n", shellquote.Join(args...), kernel)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	// Ensure that the repository root is available in the VM.
	var sharedDirectories []volume
	addShare := func(sd volume) {
		if !slices.Contains(sharedDirectories, sd) {
			sharedDirectories = append(sharedDirectories, sd)
		}
	}

	repo, err := findGitRoot(".")
	if err != nil {
		return err
	}
	if repo != "" {
		addShare(volume{repo, repo})
	}

	// Ensure that the binary is available in the VM. Mainly used for Go test
	// binaries specified as `/tmp/go-build*/pkg.test`. Bare commands are
	// resolved via PATH in the guest instead.
	path := fs.Arg(0)
	if strings.ContainsRune(path, os.PathSeparator) {
		binDir, err := filepath.Abs(filepath.Dir(path))
		if err != nil {
			return err
		}
		addShare(volume{binDir, binDir})
	}

	// Ensure that the working directory is available.
	wd, err := os.Getwd()
	if err != nil {
		return err
	}
	addShare(volume{wd, wd})

	// Expose host directories specified by the user.
	for _, v := range cfg.Volumes {
		sd, err := parseVolume(v)
		if err != nil {
			return err
		}
		addShare(sd)
	}

	tmp := make([]byte, 2)
	rand.Read(tmp)
	corePrefix := fmt.Sprintf("core-%x-", tmp)

	cmd := &command{
		Kernel:      bf.Kernel,
		Arch:        arch,
		Memory:      cfg.Memory,
		SMP:         cfg.SMP,
		Path:        path,
		Args:        fs.Args(),
		Dir:         wd,
		GDB:         cfg.GDB,
		User:        cfg.User,
		Stdin:       os.Stdin,
		Stdout:      os.Stdout,
		Stderr:      os.Stderr,
		KernelImage: bf.Overlay,
		Base:        userland,
		Sysctls: []guest.Sysctl{
			{Name: "kernel.core_pattern", Value: filepath.Join(wd, corePrefix+"%e.%p.%t")},
		},
		Rlimits: map[int]unix.Rlimit{
			unix.RLIMIT_CORE: {Cur: unix.RLIM_INFINITY, Max: unix.RLIM_INFINITY},
		},
		Setup:             cfg.Setup,
		Teardown:          cfg.Teardown,
		SharedDirectories: sharedDirectories,
	}

	if cfg.Console {
		cmd.Console = os.Stderr
	}

	if err := cmd.Start(ctx); err != nil {
		return err
	}

	waitErr := cmd.Wait()
	if waitErr == nil {
		return nil
	}

	// Something went wrong, try to retain the go test binary if appropriate.
	if err := preserveTestBinary(cmd.Path, wd, corePrefix); err != nil {
		return err
	}

	return waitErr
}

// guestArch returns the architecture of the guest VM.
//
// Honours the GOARCH environment variable so that 'GOARCH=... vimto -- go
// test' executes foreign test binaries in a matching guest.
func guestArch() string {
	if arch := os.Getenv("GOARCH"); arch != "" {
		return arch
	}
	return runtime.GOARCH
}

// checkUserland ensures that a userland is configured for guests which can't
// execute the host's binaries.
func checkUserland(cfg *config, arch string) error {
	if arch == runtime.GOARCH || cfg.Userland != "" {
		return nil
	}

	return fmt.Errorf("the host's binaries can't be executed in a %s guest, specify an image via -userland or %s", arch, configFileName)
}

func findBootFiles(kernel, arch string) (_ *bootFiles, err error) {
	bf, err := resolveBootFiles(kernel, arch)
	if err != nil {
		return nil, err
	}

	// QEMU doesn't validate the kernel format. Booting a kernel binary of the
	// wrong format can hang the VM without any console output.
	if err := validateKernel(bf.Kernel, arch); err != nil {
		bf.Image.Close()
		return nil, err
	}

	return bf, nil
}

func resolveBootFiles(kernel, arch string) (_ *bootFiles, err error) {
	closeOnError := func(c io.Closer) {
		if err != nil {
			c.Close()
		}
	}

	if kernel == "" {
		return nil, errors.New("no kernel specified")
	}

	info, err := os.Stat(kernel)
	if err == nil {
		if info.IsDir() {
			return newBootFiles(kernel, arch)
		}

		// Kernel is a file on disk.
		return &bootFiles{Kernel: kernel}, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		// Unexpected error from stat, maybe not allowed to access it?
		return nil, fmt.Errorf("stat kernel: %w", err)
	} else if first, _, ok := strings.Cut(kernel, "/"); ok && (first == "" || first == "." || first == "..") {
		// This can't be a URL, so we don't fall through to treating it
		// as an image.
		return nil, fmt.Errorf("kernel %q: %w", kernel, os.ErrNotExist)
	}

	// Assume that kernel is a reference to an image.
	cache, err := newImageCache()
	if err != nil {
		return nil, fmt.Errorf("image cache: %w", err)
	}

	img, err := cache.Acquire(context.Background(), kernel, arch, "kernel", os.Stdout, stripLibSymlink)
	if err != nil {
		return nil, fmt.Errorf("retrieve kernel from OCI image: %w", err)
	}
	defer closeOnError(img)

	return newBootFilesFromImage(img, arch)
}

// findUserland locates the directory containing a userland, fetching it from
// an OCI image if necessary.
func findUserland(userland, arch string) (string, *image, error) {
	info, err := os.Stat(userland)
	if errors.Is(err, os.ErrNotExist) {
		// Assume that userland is a reference to an image.
		cache, err := newImageCache()
		if err != nil {
			return "", nil, fmt.Errorf("image cache: %w", err)
		}

		img, err := cache.Acquire(context.Background(), userland, arch, "", os.Stdout, nil)
		if err != nil {
			return "", nil, fmt.Errorf("retrieve userland from OCI image: %w", err)
		}

		return img.Directory, img, nil
	}
	if err != nil {
		return "", nil, err
	}

	if !info.IsDir() {
		return "", nil, fmt.Errorf("userland %q is not a directory", userland)
	}

	return userland, nil, nil
}

// parseVolume parses a Docker-style volume mapping.
//
// A single path is made available at the same location in the guest.
func parseVolume(v string) (volume, error) {
	host, guest, found := strings.Cut(v, ":")
	if !found {
		guest = host
	}

	if host == "" || guest == "" {
		return volume{}, fmt.Errorf("invalid volume %q", v)
	}

	if !filepath.IsAbs(guest) {
		return volume{}, fmt.Errorf("volume %q: guest path must be absolute", v)
	}

	host, err := filepath.Abs(host)
	if err != nil {
		return volume{}, err
	}

	return volume{host, guest}, nil
}

// stripLibSymlink removes a top-level lib symlink from an extracted kernel
// image.
//
// Legacy kernel images contain a lib -> usr/lib symlink to match usrmerged
// hosts. Merging it over a base with a real /lib would shadow the directory.
// The modules remain reachable via usr/lib/modules.
func stripLibSymlink(dir string) error {
	path := filepath.Join(dir, "lib")
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}

	if info.Mode().Type() != os.ModeSymlink {
		return nil
	}

	return os.Remove(path)
}

func findExecutable() (string, error) {
	// https://man7.org/linux/man-pages/man5/proc.5.html
	buf := make([]byte, unix.NAME_MAX)
	n, err := unix.Readlink("/proc/self/exe", buf)
	if err != nil {
		return "", fmt.Errorf("readlink /proc/self/exe: %w", err)
	}

	if n == unix.NAME_MAX {
		return "", fmt.Errorf("readlink returned truncated name")
	}

	path := unix.ByteSliceToString(buf)
	if _, err := os.Stat(path); err != nil {
		// Make sure the symlink doesn't reference a deleted file.
		return "", err
	}

	return path, nil
}

func splitFlagsFromArgs(args []string) ([]string, error) {
	var flags []string
	for _, arg := range args {
		if arg == "--" {
			return flags, nil
		}

		flags = append(flags, arg)
	}

	return nil, fmt.Errorf("missing '--' in arguments")
}

func preserveTestBinary(path, wd, corePrefix string) error {
	if isGoTest := strings.HasPrefix(path, os.TempDir()); !isGoTest {
		return nil
	}

	if files, err := filepath.Glob(filepath.Join(wd, corePrefix+"*")); err != nil {
		return err
	} else if len(files) == 0 {
		return nil
	}

	src, err := os.Open(path)
	if err != nil {
		return err
	}
	defer src.Close()

	dst, err := os.OpenFile(filepath.Join(wd, filepath.Base(path)), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer dst.Close()

	_, err = io.Copy(dst, src)
	return err
}

// flushCacheCmd deletes the image cache directory by first renaming it
// and then removing it to handle concurrent access.
func flushCacheCmd(args []string) error {
	if len(args) > 0 {
		return fmt.Errorf("flush-cache command takes no arguments")
	}

	// Generate a random suffix for the temporary directory
	tmp := make([]byte, 4)
	if _, err := rand.Read(tmp); err != nil {
		return fmt.Errorf("generate random suffix: %w", err)
	}
	tmpDir := userCacheDir + fmt.Sprintf(".%x", tmp)

	// Rename the cache directory to prevent another process from seeing
	// a partially delete cache.
	if err := os.Rename(userCacheDir, tmpDir); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("rename cache directory: %w", err)
	}

	// Remove the renamed directory
	if err := os.RemoveAll(tmpDir); err != nil {
		return fmt.Errorf("remove cache directory: %w", err)
	}

	return nil
}
