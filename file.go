package main

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"syscall"

	"golang.org/x/sys/unix"
)

func replaceFdWithFile(sys syscaller, fd int, file *os.File) error {
	_, err := fileControl(file, func(replacement uintptr) (struct{}, error) {
		// dup2 overwrites fd with the newly opened file.
		return struct{}{}, sys.dup2(int(replacement), fd)
	})
	if err != nil {
		return fmt.Errorf("dup2: %w", err)
	}
	return nil
}

func flock(f *os.File, how int) error {
	_, err := fileControl(f, func(fd uintptr) (struct{}, error) {
		return struct{}{}, unix.Flock(int(fd), how)
	})
	return err
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

func fileIsTTY(f *os.File) (bool, error) {
	return fileControl(f, func(fd uintptr) (bool, error) {
		_, err := unix.IoctlGetTermios(int(fd), unix.TCGETS)
		if err != nil && !errors.Is(err, unix.ENOTTY) {
			return false, err
		}
		return err == nil, nil
	})
}

func fileControl[T any](f *os.File, fn func(fd uintptr) (T, error)) (T, error) {
	var result T
	sys, err := f.SyscallConn()
	if err != nil {
		return result, err
	}

	var opErr error
	err = sys.Control(func(fd uintptr) {
		result, opErr = fn(fd)
	})
	if err != nil {
		return result, fmt.Errorf("control fd: %w", err)
	}
	if opErr != nil {
		return result, opErr
	}

	return result, nil
}
