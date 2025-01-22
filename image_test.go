package main

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/go-quicktest/qt"
)

func TestCacheAcquire(t *testing.T) {
	cache := imageCache{t.TempDir()}

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

	err := fetchImage(context.Background(), "busybox", tmp, io.Discard)
	qt.Assert(t, qt.IsNil(err))

	_, err = os.Stat(filepath.Join(tmp, "bin", "sh"))
	qt.Assert(t, qt.IsNil(err))
}

func TestPopulateDirectoryOnce(t *testing.T) {
	tmp := t.TempDir()

	waiting := make(chan struct{})
	quit := make(chan struct{})
	errs := make(chan error, 2)
	go func() {
		f, _, err := populateDirectoryOnce(tmp, func(s string) error {
			close(waiting)
			<-quit
			return nil
		})
		if err == nil {
			f.Close()
		}
		errs <- err
	}()

	select {
	case <-waiting:
	case err := <-errs:
		t.Fatal("Got error from first invoke:", err)
	}

	go func() {
		f, _, err := populateDirectoryOnce(tmp, func(s string) error {
			return errors.New("invoked second fn")
		})
		if err == nil {
			f.Close()
		}
		errs <- err
	}()

	runtime.Gosched()
	close(quit)

	qt.Assert(t, qt.IsNil(<-errs))
	qt.Assert(t, qt.IsNil(<-errs))
}
