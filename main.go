package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"

	"golang.org/x/sys/unix"
)

func main() {
	var err error
	if os.Getpid() == 1 {
		err = dummy()
	} else {
		err = run(os.Args[1:])
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

	init, err := findExecutable()
	if err != nil {
		return err
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	cons, err := os.Create("console.log")
	if err != nil {
		return err
	}
	defer cons.Close()

	vm, err := execInVM(ctx, &command{
		Kernel:  vmlinuz,
		Init:    init,
		Args:    fs.Args(),
		Console: cons,
		SerialPorts: map[string]*os.File{
			stdoutPort: os.Stdout,
			stderrPort: os.Stderr,
		},
	})
	if err != nil {
		return err
	}

	if err := vm.Wait(); err != nil {
		return fmt.Errorf("qemu: %w", err)
	}

	return nil
}

func dummy() error {
	pid1, err := minimalInit(realSyscaller{})
	if err != nil {
		return err
	}

	_, err = io.WriteString(os.Stderr, "testing\n")
	if err != nil {
		return err
	}
	fmt.Println(pid1.Ports)

	return pid1.Shutdown()
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

	// TODO: This should validate that the file is statically linked.
	return path, nil
}
