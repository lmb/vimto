package main

import (
	"errors"
	"os"
	"testing"

	"github.com/go-quicktest/qt"
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
