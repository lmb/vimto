package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"syscall"

	"golang.org/x/sys/unix"
)

// Name of the init binary inside the boot directory.
const bootDirInit = "init"

// makeBootDir creates a directory for the guest to boot from. It contains
// only the init binary and the mountpoints required during early boot.
func makeBootDir(init string) (string, error) {
	dir, err := os.MkdirTemp("", "vimto-boot-*")
	if err != nil {
		return "", err
	}
	defer func() {
		if err != nil {
			os.RemoveAll(dir)
		}
	}()

	// dev is required for the devtmpfs automount (and therefore the init's
	// console), tmp for the pivot to tmpfs.
	for _, sub := range []string{"dev", "tmp"} {
		if err := os.Mkdir(filepath.Join(dir, sub), 0755); err != nil {
			return "", err
		}
	}

	if err := linkOrCopy(init, filepath.Join(dir, bootDirInit)); err != nil {
		return "", err
	}

	return dir, nil
}

// linkOrCopy makes src available at dst, copying if hard linking fails, e.g.
// across file systems.
func linkOrCopy(src, dst string) error {
	if err := os.Link(src, dst); err == nil {
		return nil
	}

	srcFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	dstFile, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0755)
	if err != nil {
		return err
	}
	defer dstFile.Close()

	if _, err := io.Copy(dstFile, srcFile); err != nil {
		return err
	}

	return dstFile.Close()
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
