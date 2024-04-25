package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-quicktest/qt"
	"rsc.io/script"
	"rsc.io/script/scripttest"
)

func TestExecutable(t *testing.T) {
	path := t.TempDir()
	cmd := exec.Command("go", "build", "-o", path, ".")
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Log(string(output))
		t.Fatal("Failed to compile binary:", err)
	}

	t.Setenv("PATH", fmt.Sprintf("%s:%s", path, os.Getenv("PATH")))

	e := script.NewEngine()
	e.Cmds["vimto"] = script.Program("vimto", nil, time.Second)
	e.Cmds["config"] = script.Command(script.CmdUsage{
		Summary: "Write to the configuration file",
		Args:    "items...",
	}, func(s *script.State, args ...string) (script.WaitFunc, error) {
		contents := strings.Join(args, "\n")
		return nil, os.WriteFile(filepath.Join(s.Getwd(), configFileName), []byte(contents), 0644)
	})

	var env []string
	for _, v := range os.Environ() {
		for _, prefix := range []string{
			"GO",
			"XDG_",
			"PATH=",
			"HOME=",
			"VIMTO_",
		} {
			if strings.HasPrefix(v, prefix) {
				env = append(env, v)
				break
			}
		}
	}

	image := os.Getenv("CI_KERNEL")
	if image == "" {
		image = "ghcr.io/cilium/ci-kernels:stable"
	}

	cache, err := newImageCache(mustNewDockerClient(t))
	qt.Assert(t, qt.IsNil(err))
	img, err := cache.Acquire(context.Background(), image)
	qt.Assert(t, qt.IsNil(err))
	defer img.Close()

	env = append(env, "IMAGE="+image)
	env = append(env, "KERNEL="+filepath.Join(img.Directory, imageKernelPath))
	env = append(env, fmt.Sprintf("UID=%d", os.Geteuid()))

	scripttest.Test(t, context.Background(), e, env, "testdata/*.txt")
}
