package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
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

// createLockedDirectory atomically creates a directory at path.
//
// Returns a file descriptor for path, locked in LOCK_EX mode.
func createLockedDirectory(path string, perm fs.FileMode) (*os.File, error) {
	tmpdir, err := os.MkdirTemp(filepath.Dir(path), "")
	if err != nil {
		return nil, err
	}
	defer os.Remove(tmpdir)

	if err := os.Chmod(tmpdir, perm); err != nil {
		return nil, err
	}

	dir, err := os.Open(tmpdir)
	if err != nil {
		return nil, err
	}

	if err := flock(dir, unix.LOCK_EX); err != nil {
		dir.Close()
		return nil, fmt.Errorf("lock %q: %w", dir.Name(), err)
	}

	if err := unix.Renameat2(unix.AT_FDCWD, tmpdir, unix.AT_FDCWD, path, unix.RENAME_NOREPLACE); err != nil {
		dir.Close()
		return nil, fmt.Errorf("atomic rename: %w", err)
	}

	return dir, nil
}

// removeAllLocked removes a (possible locked) directory and its contents.
//
// Returns nil if path doesn't exist, like [os.RemoveAll].
func removeAllLocked(path string) error {
	dir, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		// Directory doesn't exist, nothing to do.
		return nil
	} else if err != nil {
		return err
	}
	defer dir.Close()

	if err := flock(dir, unix.LOCK_EX); err != nil {
		return err
	}

	return os.RemoveAll(path)
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
