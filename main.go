package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"

	"golang.org/x/sys/unix"
)

func main() {
	var err error
	if os.Getpid() == 1 {
		err = minimalInit(realSyscaller{}, os.Args[1:])
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
	if err := fs.Parse(args); errors.Is(err, flag.ErrHelp) {
		return nil
	} else if err != nil {
		return err
	}

	if *kernel == "" {
		return fmt.Errorf("need kernel")
	}

	_, err := findExecutable()
	if err != nil {
		return err
	}

	vm, err := execInVM(&command{
		Kernel: *kernel,
		Path:   initPath,
		Args:   fs.Args(),
		Stdin:  os.Stdin,
		Stdout: os.Stdout,
		Stderr: os.Stderr,
	})
	if err != nil {
		return err
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	go func() {
		<-ctx.Done()
		vm.Process.Kill()
	}()

	if err := vm.Wait(); err != nil {
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

	return path, nil
}
