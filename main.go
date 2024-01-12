package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

func main() {
	args := os.Args[1:]

	var err error
	if os.Getpid() == 1 {
		err = minimalInit(realSyscaller{}, args, executeTest)
	} else {
		err = run(args)
	}

	if err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	fs := flag.NewFlagSet("vimto", flag.ContinueOnError)
	kernel := fs.String("vm.kernel", "", "`path` to the Linux image")
	image := fs.String("vm.image", "", "OCI `url:tag` containing a Linux image")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: %s [flags] [--] </path/to/binary> [flags of binary]\n", fs.Name())
		fmt.Fprintln(fs.Output())
		fs.PrintDefaults()
	}

	if len(args) > 0 && unix.Access(args[0], unix.X_OK) == nil {
		// This is an invocation via go test -exec.
		args = sortArgs(fs, args)
	}

	if err := fs.Parse(args); errors.Is(err, flag.ErrHelp) {
		return nil
	} else if err != nil {
		return err
	}

	var vmlinuz string
	var cache ociCache
	if *image != "" {
		oi, err := cache.Acquire(context.Background(), *image)
		if err != nil {
			return fmt.Errorf("retrieve kernel from OCI image: %w", err)
		}
		defer oi.Release()

		vmlinuz = oi.Kernel
	}

	if *kernel != "" {
		if vmlinuz != "" {
			return fmt.Errorf("conflicting kernel source")
		}

		if _, err := os.Stat(*kernel); err != nil {
			return fmt.Errorf("file %q doesn't exist", *kernel)
		}

		vmlinuz = *kernel
	}

	if vmlinuz == "" {
		return fmt.Errorf("need kernel")
	}

	if fs.NArg() < 1 {
		fs.Usage()
		return fmt.Errorf("missing arguments")
	}

	args = fs.Args()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	cmd := &command{
		Kernel: vmlinuz,
		Args:   args,
		Stdin:  os.Stdin,
		Stdout: os.Stdout,
		Stderr: os.Stderr,
		SharedDirectories: []string{
			// Ensure that the executable path is always available in the guest.
			filepath.Dir(args[0]),
		},
	}

	err := cmd.execInVM(ctx)
	if err != nil {
		return err
	}

	if err := cmd.Wait(); err != nil {
		return err
	}

	return nil
}

func executeTest(env *env) error {
	cmd := exec.Command(env.Args[0], env.Args[1:]...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
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
