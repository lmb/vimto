package main

import (
	"context"
	"flag"
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

	cache, err := newImageCache()
	qt.Assert(t, qt.IsNil(err))
	img, err := cache.Acquire(context.Background(), mustNewDockerClient(t), image)
	qt.Assert(t, qt.IsNil(err))
	defer img.Release()

	env = append(env, "IMAGE="+image)
	env = append(env, "KERNEL="+filepath.Join(img.Directory, imageKernelPath))
	env = append(env, fmt.Sprintf("UID=%d", os.Geteuid()))

	scripttest.Test(t, context.Background(), e, env, "testdata/*.txt")
}

func TestSortFlags(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	fs.Bool("bool", false, "")
	fs.String("vm.kernel", "", "")

	for _, tc := range []struct {
		input, want []string
	}{
		{
			[]string{"/foo/bar", "-bool", "-test.v", "-test.run", "XXX", "-vm.kernel", "flarp"},
			[]string{"-bool", "-vm.kernel", "flarp", "/foo/bar", "-test.v", "-test.run", "XXX"},
		},
		{
			[]string{"/tmp/TestExecutablego-test664702905/001/tmp/go-build1359646099/b001/test.test", "-test.paniconexit0", "-test.timeout=10m0s", "-test.run=Success", "-vm.kernel=testdata/vmlinuz", "-test.v=true", "."},
			[]string{"-vm.kernel=testdata/vmlinuz", "/tmp/TestExecutablego-test664702905/001/tmp/go-build1359646099/b001/test.test", "-test.paniconexit0", "-test.timeout=10m0s", "-test.run=Success", "-test.v=true", "."},
		},
	} {
		got := sortArgs(fs, tc.input)
		qt.Assert(t, qt.DeepEquals(got, tc.want))
	}
}
