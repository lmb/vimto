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
	"slices"
	"strings"

	"github.com/kballard/go-shellquote"
	"golang.org/x/sys/unix"
)

func main() {
	args := os.Args[1:]

	var err error
	if os.Getpid() == 1 {
		err = minimalInit(realSyscaller{}, args)
	} else {
		err = run(args)
	}

	if err == nil || errors.Is(err, flag.ErrHelp) {
		return
	}

	var exitError *guestExitError
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
		return fmt.Errorf("can't enable gdb integration when running multiple tests")
	}

	exe, err := findExecutable()
	if err != nil {
		return err
	}

	// Prime the cache before invoking the go binary.
	bf, err := findBootFiles(cfg.Kernel)
	if err != nil {
		return err
	}
	defer bf.Image.Close()

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

	if !staticBuild {
		return errors.New("binary is not statically linked (did you build with CGO_ENABLED=0?)")
	}

	bf, err := findBootFiles(cfg.Kernel)
	if err != nil {
		return err
	}
	defer bf.Image.Close()

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
		fmt.Printf("\tgdb %s %s\n", shellquote.Join(args...), bf.Kernel)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	// Ensure that the repository root is available in the VM.
	var sharedDirectories []string
	if repo, err := findGitRoot("."); err != nil {
		return err
	} else if repo != "" {
		sharedDirectories = append(sharedDirectories, repo)
	}

	// Ensure that the binary is available in the VM.
	path := fs.Arg(0)
	sharedDirectories = append(sharedDirectories, filepath.Dir(path))

	// Ensure that the working directory is available.
	wd, err := os.Getwd()
	if err != nil {
		return err
	}
	sharedDirectories = append(sharedDirectories, wd)

	tmp := make([]byte, 2)
	rand.Read(tmp)
	corePrefix := fmt.Sprintf("core-%x-", tmp)

	cmd := &command{
		Kernel:      bf.Kernel,
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
		RootOverlay: bf.Overlay,
		Sysctls: []sysctl{
			{"kernel.core_pattern", filepath.Join(wd, corePrefix+"%e.%p.%t")},
		},
		Rlimits: map[int]unix.Rlimit{
			unix.RLIMIT_CORE: {Cur: unix.RLIM_INFINITY, Max: unix.RLIM_INFINITY},
		},
		Setup:             cfg.Setup,
		Teardown:          cfg.Teardown,
		SharedDirectories: slices.Compact(sharedDirectories),
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

func findBootFiles(kernel string) (_ *bootFiles, err error) {
	closeOnError := func(c io.Closer) {
		if err != nil {
			c.Close()
		}
	}

	if kernel == "" {
		return nil, errors.New("no kernel specified")
	}

	info, err := os.Stat(kernel)
	if errors.Is(err, os.ErrNotExist) {
		// Assume that kernel is a reference to an image.
		cache, err := newImageCache()
		if err != nil {
			return nil, fmt.Errorf("image cache: %w", err)
		}

		img, err := cache.Acquire(context.Background(), kernel, os.Stdout)
		if err != nil {
			return nil, fmt.Errorf("retrieve kernel from OCI image: %w", err)
		}
		defer closeOnError(img)

		return newBootFilesFromImage(img)
	} else if err != nil {
		// Unexpected error from stat, maybe not allowed to access it?
		return nil, err
	}

	if info.IsDir() {
		return newBootFiles(kernel)
	}

	// Kernel is a file on disk.
	return &bootFiles{Kernel: kernel}, nil
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
