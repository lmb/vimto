package main

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/docker/docker/api/types"
	docker "github.com/docker/docker/client"
	"github.com/go-quicktest/qt"
)

func TestCacheAcquire(t *testing.T) {
	cli := mustNewDockerClient(t)
	cache := imageCache{cli, t.TempDir()}

	img1, err := cache.Acquire(context.Background(), "busybox", io.Discard)
	qt.Assert(t, qt.IsNil(err))
	defer img1.Close()

	start := time.Now()
	img2, err := cache.Acquire(context.Background(), "busybox", io.Discard)
	delta := time.Since(start)
	qt.Assert(t, qt.IsTrue(delta < 100*time.Millisecond))
	qt.Assert(t, qt.IsNil(err))
	defer img2.Close()

	qt.Assert(t, qt.Equals(img2.Directory, img1.Directory))
}

func TestFetchAndExtractImage(t *testing.T) {
	tmp := t.TempDir()
	cli := mustNewDockerClient(t)

	cli.ImageRemove(context.Background(), "busybox", types.ImageRemoveOptions{Force: true})

	refStr, digest, err := fetchImage(context.Background(), cli, "busybox", io.Discard)
	qt.Assert(t, qt.IsNil(err))

	refStr2, digest2, err := imageID(context.Background(), cli, refStr)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(refStr, refStr2))
	qt.Assert(t, qt.Equals(digest, digest2))

	t.Log("digest is", digest)

	err = extractImage(context.Background(), cli, refStr, tmp)
	qt.Assert(t, qt.IsNil(err))

	_, err = os.Stat(filepath.Join(tmp, "bin", "sh"))
	qt.Assert(t, qt.IsNil(err))
}

func TestPopulateDirectoryOnce(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "test")

	running := make(chan struct{}, 1)
	quit := make(chan struct{})
	errs := make(chan error, 2)
	go func() {
		f, err := populateDirectoryOnce(tmp, func(s string) error {
			running <- struct{}{}
			<-quit
			return nil
		})
		if err == nil {
			f.Close()
		}
		errs <- err
	}()

	select {
	case <-running:
	case err := <-errs:
		t.Fatal("Got error from first invoke:", err)
	}

	go func() {
		running <- struct{}{}
		f, err := populateDirectoryOnce(tmp, func(s string) error {
			return errors.New("invoked second fn")
		})
		if err == nil {
			f.Close()
		}
		errs <- err
	}()

	select {
	case <-running:
	case err := <-errs:
		t.Fatal("Got error:", err)
	}

	close(quit)

	qt.Assert(t, qt.IsNil(<-errs))
	qt.Assert(t, qt.IsNil(<-errs))
}

func TestSecureJoin(t *testing.T) {
	for _, tc := range []struct {
		base   string
		parts  []string
		result string
	}{
		{
			"/foo",
			[]string{"/foo/usr/bin", "../../bin/env"},
			"/foo/bin/env",
		},
	} {
		path, err := secureJoin(tc.base, tc.parts...)
		qt.Assert(t, qt.IsNil(err))
		qt.Assert(t, qt.Equals(path, tc.result))
	}
}

func BenchmarkExtractImage(b *testing.B) {
	cli := mustNewDockerClient(b)
	refStr, _, err := fetchImage(context.Background(), cli, "busybox", io.Discard)
	qt.Assert(b, qt.IsNil(err))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		tmp := b.TempDir()
		b.StartTimer()

		extractImage(context.Background(), cli, refStr, tmp)

		b.StopTimer()
		os.RemoveAll(tmp)
		b.StartTimer()
	}
}

func mustNewDockerClient(tb testing.TB) *docker.Client {
	tb.Helper()

	cli, err := docker.NewClientWithOpts(docker.FromEnv, docker.WithAPIVersionNegotiation())
	qt.Assert(tb, qt.IsNil(err))
	tb.Cleanup(func() { cli.Close() })
	return cli
}
