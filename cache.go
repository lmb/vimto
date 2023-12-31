package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// ociCache ensures that multiple invocations of vimto don't download the
// same images over and over again.
//
// The main concern is startup speed of vimto.
type ociCache struct {
}

func (oc *ociCache) Acquire(ctx context.Context, image string) (*ociImage, error) {
	targetDirectory, err := os.MkdirTemp("", "vimto")
	if err != nil {
		return nil, err
	}

	cmd := exec.CommandContext(ctx, "docker", "buildx", "build",
		"--quiet",                   // don't output build steps
		"--output", targetDirectory, // write the result of the build here
		"-", // read the Dockerfile from stdin
	)

	cmd.Stdin = bytes.NewReader([]byte(fmt.Sprintf("FROM %s\n", image)))
	output, err := cmd.CombinedOutput()
	if err != nil {
		os.RemoveAll(targetDirectory)
		return nil, fmt.Errorf("%w: %s", err, string(output))
	}

	kernel := filepath.Join(targetDirectory, "boot", "vmlinuz")
	if _, err := os.Stat(kernel); err != nil {
		os.RemoveAll(targetDirectory)
		return nil, fmt.Errorf("image %q doesn't contain /boot/vmlinux", image)
	}

	return &ociImage{kernel, targetDirectory}, nil
}

type ociImage struct {
	Kernel    string
	directory string
}

func (oi *ociImage) Release() error {
	return os.RemoveAll(oi.directory)
}
