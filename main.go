package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"

	"golang.org/x/sys/unix"
)

func main() {
	args := os.Args[1:]

	var err error
	if os.Getpid() == 1 {
		err = executeTest(args)
	} else {
		err = run(args)
	}

	if err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	args, testBinary, testArgs := splitArgs(args)
	fs := flag.NewFlagSet("vimto", flag.ContinueOnError)
	kernel := fs.String("kernel", "", "`path` to the Linux image")
	image := fs.String("image", "", "OCI `url:tag` containing a Linux image")
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

	if testBinary == "" {
		return fmt.Errorf("need executable")
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	cmd := &command{
		Kernel: vmlinuz,
		Args:   append([]string{testBinary}, testArgs...),
		Stdin:  os.Stdin,
		Stdout: os.Stdout,
		Stderr: os.Stderr,
	}

	err := cmd.execInVM(ctx)
	if err != nil {
		return err
	}

	if err := cmd.Wait(); err != nil {
		return fmt.Errorf("qemu: %w", err)
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

const flagPrefix = "-vm."

func splitArgs(args []string) (vmArgs []string, testBinary string, testArgs []string) {
	if len(args) < 1 || unix.Access(args[0], unix.X_OK) != nil {
		// First argument needs to be an executable for this to be a `go test`
		// invocation.
		return args, "", nil
	}

	testBinary = args[0]
	for _, arg := range args[1:] {
		if strings.HasPrefix(arg, flagPrefix) {
			// TODO: Doesn't handle space separated flags.
			vmArgs = append(vmArgs, "-"+strings.TrimPrefix(arg, flagPrefix))
		} else {
			testArgs = append(testArgs, arg)
		}
	}

	return
}
