package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/creack/pty/v2"
	"github.com/go-quicktest/qt"
	"golang.org/x/sys/unix"
)

func TestFileControl(t *testing.T) {
	f, err := os.CreateTemp("", "")
	qt.Assert(t, qt.IsNil(err))
	defer f.Close()
	defer os.Remove(f.Name())

	sentinel := errors.New("sentinel")

	_, err = fileControl(f, func(fd uintptr) (struct{}, error) {
		return struct{}{}, sentinel
	})

	qt.Assert(t, qt.ErrorIs(err, sentinel))
}

func TestFlock(t *testing.T) {
	tmp := t.TempDir()
	f1, err := os.Open(tmp)
	qt.Assert(t, qt.IsNil(err))
	defer f1.Close()

	f2, err := os.Open(tmp)
	qt.Assert(t, qt.IsNil(err))
	defer f2.Close()

	qt.Assert(t, qt.IsNil(flock(f1, unix.LOCK_SH)))
	qt.Assert(t, qt.ErrorIs(flock(f2, unix.LOCK_EX|unix.LOCK_NB), unix.EWOULDBLOCK))

	f1.Close()
	qt.Assert(t, qt.IsNil(flock(f2, unix.LOCK_EX|unix.LOCK_NB)))
}

func TestCreateLockedDirectory(t *testing.T) {
	tmpdir := t.TempDir()
	path := filepath.Join(tmpdir, "test")

	d1, err := createLockedDirectory(path, 0755)
	qt.Assert(t, qt.IsNil(err))
	defer d1.Close()

	_, err = createLockedDirectory(path, 0755)
	qt.Assert(t, qt.ErrorIs(err, os.ErrExist))

	tmp, err := os.Open(path)
	qt.Assert(t, qt.IsNil(err))
	defer tmp.Close()

	qt.Assert(t, qt.ErrorIs(flock(tmp, unix.LOCK_SH|unix.LOCK_NB), unix.EWOULDBLOCK))
}

func TestFileIsTTY(t *testing.T) {
	pty, tty, err := pty.Open()
	qt.Assert(t, qt.IsNil(err))
	defer pty.Close()
	defer tty.Close()

	ok, err := fileIsTTY(pty)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(ok, true))

	ok, err = fileIsTTY(tty)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(ok, true))

	dir, err := os.Open(t.TempDir())
	qt.Assert(t, qt.IsNil(err))
	defer dir.Close()

	ok, err = fileIsTTY(dir)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(ok, false))
}
