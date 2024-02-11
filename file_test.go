package main

import (
	"errors"
	"os"
	"testing"

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
