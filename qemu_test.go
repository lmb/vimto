package main

import (
	"bytes"
	"context"
	"os"
	"testing"
	"time"

	"github.com/creack/pty/v2"
	"github.com/go-quicktest/qt"
	"golang.org/x/sys/unix"
)

func TestQemuTTY(t *testing.T) {
	t.Parallel()

	pty, tty, err := pty.Open()
	qt.Assert(t, qt.IsNil(err))
	defer pty.Close()
	defer tty.Close()

	get := func(f *os.File) (*unix.Termios, error) {
		return fileControl(f, func(fd uintptr) (*unix.Termios, error) {
			return unix.IoctlGetTermios(int(fd), unix.TCGETS)
		})
	}

	old, err := get(tty)
	qt.Assert(t, qt.IsNil(err))

	image := mustFetchKernelImage(t)

	r, w, err := os.Pipe()
	qt.Assert(t, qt.IsNil(err))
	defer r.Close()
	defer w.Close()

	var stderr bytes.Buffer
	cmd := command{
		Kernel: image.Kernel(),
		Memory: "128M",
		SMP:    "cpus=1",
		Path:   "sh",
		Args:   []string{"sh", "-c", "echo a; sleep 60"},
		Stdin:  tty,
		Stdout: w,
		Stderr: &stderr,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	qt.Assert(t, qt.IsNil(cmd.Start(ctx)))

	// Make sure we get EOF if the VM exits.
	qt.Assert(t, qt.IsNil(w.Close()))

	// qemu changes the tty settings before changing signal handlers. Cancelling
	// too early means that the process is killed immediately, which aborts
	// the shutdown.
	// Wait for the vm to write to stdout as a proxy for signal handlers
	// being up.
	_, err = r.Read(make([]byte, 1))
	qt.Assert(t, qt.IsNil(err))

	new, err := get(tty)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Not(qt.Equals(*new, *old)), qt.Commentf("termios should change"))

	cancel()

	err = cmd.Wait()
	if stderr.Len() > 0 {
		t.Log(stderr.String())
	}
	qt.Assert(t, qt.ErrorIs(err, context.Canceled))

	// Ensure that the tty settings were restored.
	new, err = get(tty)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(*new, *old), qt.Commentf("termios should be restored"))
}
