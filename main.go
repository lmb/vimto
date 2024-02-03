package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"

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

func run(args []string) error {
	if len(args) > 0 && filepath.IsAbs(args[0]) && unix.Access(args[0], unix.X_OK) == nil {
		// This is an invocation via go test -exec. Patch up the command line.
		fs := flag.NewFlagSet("", flag.ContinueOnError)
		configFlags(fs)
		args = append([]string{"exec"}, sortArgs(fs, args)...)
	}

	fs := flag.NewFlagSet("vimto", flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: %s [command] ...\n", fs.Name())
		fmt.Fprintln(fs.Output())
		fmt.Fprintln(fs.Output(), "Available commands:")
		fmt.Fprintln(fs.Output(), "\texec    Execute a command inside a VM")
		fmt.Fprintln(fs.Output())
	}
	if err := fs.Parse(args); err != nil {
		return err
	}

	if fs.NArg() < 1 {
		return fmt.Errorf("expected at least one argument")
	}

	var err error
	switch fs.Arg(0) {
	case "exec":
		err = cliExec(fs.Args()[1:])
	case "delve":
		err = cliDelve(fs.Args()[1:])
	default:
		fs.Usage()
		return fmt.Errorf("unknown command %q", fs.Arg(0))
	}

	if err != nil {
		return fmt.Errorf("%s: %w", fs.Arg(0), err)
	}

	return nil
}

func cliExec(args []string) error {
	fs := flag.NewFlagSet("exec", flag.ContinueOnError)
	cfg := configFlags(fs)
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: %s [flags] [--] </path/to/binary> [flags of binary]\n", fs.Name())
		fmt.Fprintln(fs.Output())
		fs.PrintDefaults()
		fmt.Fprintln(fs.Output())
	}

	if err := parseConfigFromTOML(".", cfg); err != nil {
		return fmt.Errorf("read config: %w", err)
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	if fs.NArg() < 1 {
		fs.Usage()
		return fmt.Errorf("missing arguments")
	}

	cache, err := newImageCache()
	if err != nil {
		return fmt.Errorf("image cache: %w", err)
	}

	vmlinuz, rootOverlay, img, err := cfg.deriveKernelAndOverlay(cache)
	if err != nil {
		return err
	}
	defer img.Release()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	cmd := &command{
		Kernel:           vmlinuz,
		Memory:           cfg.Memory,
		SMP:              cfg.SMP,
		Path:             fs.Arg(0),
		Args:             fs.Args(),
		User:             cfg.User,
		Stdin:            os.Stdin,
		Stdout:           os.Stdout,
		Stderr:           os.Stderr,
		RootOverlay:      rootOverlay,
		Setup:            cfg.Setup,
		Teardown:         cfg.Teardown,
		EnableNetworking: true,
	}

	if err := cmd.Start(ctx); err != nil {
		return err
	}

	if err := cmd.Wait(); err != nil {
		return err
	}

	return nil
}

func cliDelve(args []string) error {
	fs := flag.NewFlagSet("delve", flag.ContinueOnError)
	cfg := configFlags(fs)
	port := fs.Int("port", 2345, "host and port to listen on")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: %s [flags]\n", fs.Name())
		fmt.Fprintln(fs.Output())
		fs.PrintDefaults()
		fmt.Fprintln(fs.Output())
	}

	if err := parseConfigFromTOML(".", cfg); err != nil {
		return fmt.Errorf("read config: %w", err)
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	if fs.NArg() != 0 {
		fs.Usage()
		return fmt.Errorf("command does not accept arguments")
	}

	if *port == 0 {
		return fmt.Errorf("invalid port %d", *port)
	}

	cache, err := newImageCache()
	if err != nil {
		return err
	}

	vmlinuz, rootOverlay, img, err := cfg.deriveKernelAndOverlay(cache)
	if err != nil {
		return err
	}
	defer img.Release()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	cmd := &command{
		Kernel: vmlinuz,
		Memory: cfg.Memory,
		SMP:    cfg.SMP,
		Path:   "netcat",
		Args:   []string{"netcat", "-l", "localhost", fmt.Sprint(*port)},
		// Args:              []string{"dlv", "dap", "--listen", fmt.Sprintf("localhost:%d", *port)},
		User:              cfg.User,
		Stdin:             os.Stdin,
		Stdout:            os.Stdout,
		Stderr:            os.Stderr,
		RootOverlay:       rootOverlay,
		Setup:             cfg.Setup,
		Teardown:          cfg.Teardown,
		EnableNetworking:  true,
		ForwardedTCPPorts: []int{*port},
	}

	if err := cmd.Start(ctx); err != nil {
		return err
	}

	if err := cmd.Wait(); err != nil {
		return err
	}

	return nil
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

	if !staticBuild {
		return "", fmt.Errorf("executable %q is not statically linked", path)
	}

	// TODO: This should validate that the file is statically linked.
	return path, nil
}

func sortArgs(fs *flag.FlagSet, args []string) []string {
	type boolFlag interface {
		IsBoolFlag() bool
	}

	testArgs := []string{args[0]}
	var flags []string
	var nextArgIsValue bool
	for _, arg := range args[1:] {
		if nextArgIsValue {
			flags = append(flags, arg)
			nextArgIsValue = false
			continue
		}

		if !strings.HasPrefix(arg, "-") {
			// This is not a flag. Pretend it's an argument.
			testArgs = append(testArgs, arg)
			continue
		}

		name, _, found := strings.Cut(arg[1:], "=")
		def := fs.Lookup(name)
		if def == nil {
			// Not a flag we recognise.
			testArgs = append(testArgs, arg)
			continue
		}

		flags = append(flags, arg)
		if found {
			// We have already appended the value via arg.
			continue
		} else if bf, ok := def.Value.(boolFlag); ok && bf.IsBoolFlag() {
			// Boolean flags don't require a value.
			continue
		}

		nextArgIsValue = true
	}

	return append(flags, testArgs...)
}
