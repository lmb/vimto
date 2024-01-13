package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	docker "github.com/docker/docker/client"
	"github.com/go-quicktest/qt"
)

func TestCacheAcquire(t *testing.T) {
	cli := mustNewDockerClient(t)
	cache := imageCache{cli, t.TempDir()}

	img1, err := cache.Acquire(context.Background(), "busybox")
	qt.Assert(t, qt.IsNil(err))
	defer img1.Release()

	qt.Assert(t, qt.IsFalse(img1.cached))

	start := time.Now()
	img2, err := cache.Acquire(context.Background(), "busybox")
	delta := time.Since(start)
	qt.Assert(t, qt.IsTrue(delta < 100*time.Millisecond))
	qt.Assert(t, qt.IsNil(err))
	defer img2.Release()

	qt.Assert(t, qt.IsTrue(img2.cached))

	qt.Assert(t, qt.Equals(img2.Directory, img1.Directory))
}

func TestFetchAndExtractImage(t *testing.T) {
	tmp := t.TempDir()
	cli := mustNewDockerClient(t)

	id, err := fetchImage(context.Background(), cli, "busybox")
	qt.Assert(t, qt.IsNil(err))

	t.Log("id is", id)

	err = extractImage(context.Background(), cli, id, tmp)
	qt.Assert(t, qt.IsNil(err))

	_, err = os.Stat(filepath.Join(tmp, "bin", "sh"))
	qt.Assert(t, qt.IsNil(err))
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

func mustNewDockerClient(tb testing.TB) *docker.Client {
	tb.Helper()

	cli, err := docker.NewClientWithOpts(docker.FromEnv, docker.WithAPIVersionNegotiation())
	qt.Assert(tb, qt.IsNil(err))
	tb.Cleanup(func() { cli.Close() })
	return cli
}
