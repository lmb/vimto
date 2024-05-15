package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"

	docker "github.com/docker/docker/client"
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

	exe, err := findExecutable()
	if err != nil {
		return err
	}

	// Prime the cache before invoking the go binary.
	_, _, cleanup, err := findKernel(cfg.Kernel)
	if err != nil {
		return err
	}
	defer cleanup()

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

	vmlinuz, rootOverlay, cleanup, err := findKernel(cfg.Kernel)
	if err != nil {
		return err
	}
	defer cleanup()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	// Ensure that the repository root is available in the VM.
	var sharedDirectories []string
	if repo, err := findGitRoot("."); err != nil {
		return err
	} else if repo != "" {
		sharedDirectories = append(sharedDirectories, repo)
	}

	cmd := &command{
		Kernel:            vmlinuz,
		Memory:            cfg.Memory,
		SMP:               cfg.SMP,
		Path:              fs.Arg(0),
		Args:              fs.Args(),
		User:              cfg.User,
		Stdin:             os.Stdin,
		Stdout:            os.Stdout,
		Stderr:            os.Stderr,
		RootOverlay:       rootOverlay,
		Setup:             cfg.Setup,
		Teardown:          cfg.Teardown,
		SharedDirectories: sharedDirectories,
	}

	if err := cmd.Start(ctx); err != nil {
		return err
	}

	if dur, err := time.ParseDuration(os.Getenv("COREDUMP_TIMEOUT")); err == nil {
		go func() {
			select {
			case <-time.After(dur):
				fmt.Fprintln(os.Stderr, "Timed out, sending SIGQUIT")
				cmd.cmd.Process.Signal(syscall.SIGQUIT)
			case <-ctx.Done():
				return
			}
		}()
	}

	if err := cmd.Wait(); err != nil {
		return err
	}

	return nil
}

func findKernel(kernel string) (vmlinuz, overlay string, cleanup func() error, err error) {
	closeOnError := func(c io.Closer) {
		if err != nil {
			c.Close()
		}
	}
	cleanup = func() error { return nil }

	if info, err := os.Stat(kernel); errors.Is(err, os.ErrNotExist) {
		// Assume that kernel is a reference to an image.
		cli, err := docker.NewClientWithOpts(docker.FromEnv, docker.WithAPIVersionNegotiation())
		if err != nil {
			return "", "", nil, fmt.Errorf("create docker client: %w", err)
		}
		defer cli.Close()

		cache, err := newImageCache(cli)
		if err != nil {
			return "", "", nil, fmt.Errorf("image cache: %w", err)
		}

		oi, err := cache.Acquire(context.Background(), kernel, os.Stdout)
		if err != nil {
			return "", "", nil, fmt.Errorf("retrieve kernel from OCI image: %w", err)
		}
		defer closeOnError(oi)
		cleanup = oi.Close

		overlay = oi.Directory
		vmlinuz = oi.Kernel()
	} else if err == nil {
		if info.IsDir() {
			// Kernel is path to an extracted image on disk.
			overlay = kernel
			vmlinuz = filepath.Join(overlay, imageKernelPath)
		} else {
			// Kernel is a file on disk.
			vmlinuz = kernel
		}
	} else {
		// Unexpected error from stat, maybe not allowed to access it?
		return "", "", nil, fmt.Errorf("kernel: %w", err)
	}

	if _, err := os.Stat(vmlinuz); err != nil {
		return "", "", nil, fmt.Errorf("invalid kernel: %w", err)
	}

	return vmlinuz, overlay, cleanup, nil
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
