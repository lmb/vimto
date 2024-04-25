package main

import (
	"context"
	"os"
	"os/exec"
	"time"
)

// send SIGINT and wait for a while instead of SIGKILL.
func commandWithGracefulTermination(ctx context.Context, name string, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Cancel = func() error {
		return cmd.Process.Signal(os.Interrupt)
	}
	cmd.WaitDelay = 500 * time.Millisecond
	return cmd
}
