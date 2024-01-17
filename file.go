package main

import (
	"fmt"
	"os"
	"runtime"
	"syscall"

	"golang.org/x/sys/unix"
)

func replaceFdWithFile(sys syscaller, fd int, file *os.File) error {
	raw, err := file.SyscallConn()
	if err != nil {
		return err
	}

	var dupErr error
	err = raw.Control(func(replacement uintptr) {
		// dup2 overwrites fd with the newly opened file.
		dupErr = sys.dup2(int(replacement), fd)
	})
	if err != nil {
		return err
	}
	return dupErr
}

func flock(f *os.File, how int) error {
	sys, err := f.SyscallConn()
	if err != nil {
		return err
	}

	var flockErr error
	err = sys.Control(func(fd uintptr) {
		flockErr = unix.Flock(int(fd), how)
	})
	if err != nil {
		return fmt.Errorf("control fd: %w", err)
	}
	if flockErr != nil {
		return fmt.Errorf("flock: %w", err)
	}
	return nil
}

func unixSocketpair() (*os.File, *os.File, error) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("create unix socket pair: %w", err)
	}

	return os.NewFile(uintptr(fds[0]), ""), os.NewFile(uintptr(fds[1]), ""), nil
}

func fileIsDevZero(f *os.File) (bool, error) {
	info, err := f.Stat()
	if err != nil {
		return false, err
	}

	fStat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return false, fmt.Errorf("GOOS not supported: %s", runtime.GOOS)
	}

	nullInfo, err := os.Stat(os.DevNull)
	if err != nil {
		return false, err
	}

	nullStat, ok := nullInfo.Sys().(*syscall.Stat_t)
	if !ok {
		return false, fmt.Errorf("GOOS not supported: %s", runtime.GOOS)
	}

	return fStat.Rdev == nullStat.Rdev, nil
}
