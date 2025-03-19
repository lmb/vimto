package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-quicktest/qt"
	"golang.org/x/sys/unix"
	"rsc.io/script"
	"rsc.io/script/scripttest"
)

func TestMain(m *testing.M) {
	if os.Getpid() == 1 {
		err := minimalInit(realSyscaller{}, os.Args[1:])
		if err != nil {
			fmt.Fprintln(os.Stderr, "Error from minimalInit:", err)
			os.Exit(1)
		}
	}

	os.Exit(m.Run())
}

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
	e.Cmds["glob-exists"] = globExists
	e.Cmds["gdb"] = gdbCommand
	e.Cmds["new-tmp"] = script.Command(script.CmdUsage{
		Summary: "use a distinct temp directory",
		Detail: []string{
			"Create a new TMPDIR which is not a subdirectory of WORK.",
		},
	}, func(s *script.State, args ...string) (script.WaitFunc, error) {
		if len(args) != 0 {
			return nil, script.ErrUsage
		}

		s.Setenv("TMPDIR", t.TempDir())
		return nil, nil
	})
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

	bf := mustFetchKernelImage(t)
	env = append(env, "IMAGE="+bf.Image.Name)
	env = append(env, "KERNEL="+bf.Kernel)
	env = append(env, fmt.Sprintf("UID=%d", os.Geteuid()))

	scripttest.Test(t, context.Background(), e, env, "testdata/*.txt")
}

func kernelImage() string {
	image := os.Getenv("CI_KERNEL")
	if image == "" {
		image = "ghcr.io/cilium/ci-kernels:stable"
	}
	return image
}

var fetchKernelImage = sync.OnceValues(func() (*bootFiles, error) {
	cache, err := newImageCache()
	if err != nil {
		return nil, err
	}

	img, err := cache.Acquire(context.Background(), kernelImage(), io.Discard)
	if err != nil {
		return nil, err
	}

	return newBootFilesFromImage(img)
})

// mustFetchKernelImage fetches a kernel image once for the entire lifetime
// of the test binary.
func mustFetchKernelImage(tb testing.TB) *bootFiles {
	bf, err := fetchKernelImage()
	qt.Assert(tb, qt.IsNil(err))
	// NB: Do not call image.Close()!
	return bf
}

var globExists = script.Command(
	script.CmdUsage{
		Summary: "check that files exist",
		Args:    "pattern...",
	},
	func(s *script.State, patterns ...string) (script.WaitFunc, error) {
		if len(patterns) == 0 {
			return nil, script.ErrUsage
		}

		for _, pattern := range patterns {
			files, err := filepath.Glob(s.Path(pattern))
			if err != nil {
				return nil, err
			}

			if len(files) == 0 {
				return nil, fmt.Errorf("no file(s) matched pattern %q", pattern)
			}

			for _, file := range files {
				file, err := filepath.Rel(s.Getwd(), file)
				if err != nil {
					return nil, err
				}

				s.Logf("pattern %q matched %v", pattern, file)
			}

		}

		return nil, nil
	},
)

var gdbCommand = script.Command(
	script.CmdUsage{
		Summary: "send raw commands to a gdb stub",
		Args:    "target packets...",
	},
	func(s *script.State, args ...string) (script.WaitFunc, error) {
		if len(args) < 1 {
			return nil, script.ErrUsage
		}

		target := args[0]

		var packets []string
		for _, cmd := range args[1:] {
			packets = append(packets, fmt.Sprintf("$%s#%02x", cmd, gdbChecksum(cmd)))
		}

		var stdout, stderr strings.Builder
		errs := make(chan error, 1)
		go func() {
			defer close(errs)

			ctx, cancel := context.WithTimeout(s.Context(), 5*time.Second)
			defer cancel()

			conn, err := tryDial(ctx, "tcp", target)
			if err != nil {
				errs <- fmt.Errorf("connect to gdb stub: %w", err)
				return
			}
			defer conn.Close()

			buf := bufio.NewReader(conn)
			for _, packet := range packets {
				if err := conn.SetWriteDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
					errs <- err
					return
				}

				_, err := io.WriteString(conn, packet)
				if err != nil {
					errs <- err
					return
				}

				response, err := gdbReadResponse(buf)
				if err != nil {
					errs <- fmt.Errorf("read response: %w", err)
					return
				}

				if response == "" {
					errs <- fmt.Errorf("packet %q is not implemented", packet)
					return
				}

				fmt.Fprintln(&stdout, response)
			}
		}()

		return func(s *script.State) (string, string, error) {
			err := <-errs
			return stdout.String(), stderr.String(), err
		}, nil
	},
)

func tryDial(ctx context.Context, network, addr string) (net.Conn, error) {
	var d net.Dialer
	for {
		conn, err := d.DialContext(ctx, network, addr)
		if errors.Is(err, unix.ECONNREFUSED) {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(50 * time.Millisecond):
				continue
			}
		} else if err != nil {
			return nil, err
		}

		return conn, nil
	}
}
