package main

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"time"

	"github.com/docker/docker/pkg/archive"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/schollz/progressbar/v3"
	"golang.org/x/sys/unix"
)

// imageCache ensures that multiple invocations of vimto don't download the
// same images over and over again.
//
// The main concern is startup speed of vimto.
type imageCache struct {
	baseDir string
}

func newImageCache() (*imageCache, error) {
	allCache := filepath.Join(os.TempDir(), "vimto")
	if err := os.MkdirAll(allCache, 0777); err != nil {
		return nil, err
	}

	uid := os.Getuid()
	userCache := filepath.Join(allCache, fmt.Sprint(uid))
	if err := os.Mkdir(userCache, 0755); err != nil && !errors.Is(err, os.ErrExist) {
		return nil, fmt.Errorf("create cache directory: %w", err)
	}

	return &imageCache{userCache}, nil
}

// Acquire an image from the cache.
//
// The image remains valid even after closing the cache.
func (ic *imageCache) Acquire(ctx context.Context, refStr string, status io.Writer) (_ *image, err error) {
	ref, err := name.ParseReference(refStr)
	if err != nil {
		return nil, fmt.Errorf("parsing reference %q: %w", refStr, err)
	}

	// Use the sha256 of the canonical reference as the cache key. This means
	// that images / tags pointing at the blob will have separate cache entries.
	dir := fmt.Sprintf("%x", sha256.Sum256([]byte(ref.Name())))

	lock, path, err := populateDirectoryOnce(filepath.Join(ic.baseDir, dir), func(path string) error {
		err := fetchImage(ctx, refStr, path, status)
		if err != nil {
			return fmt.Errorf("fetch image: %w", err)
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	return &image{refStr, path, lock}, nil
}

func populateDirectoryOnce(path string, fn func(string) error) (lock *os.File, _ string, err error) {
	closeOnError := func(c io.Closer) {
		if err != nil {
			c.Close()
		}
	}

	if err := os.Mkdir(path, 0755); err != nil && !errors.Is(err, os.ErrExist) {
		return nil, "", fmt.Errorf("create cache directory: %w", err)
	}

	dir, err := os.Open(path)
	if err != nil {
		return nil, "", err
	}
	defer closeOnError(dir)

	if err := flock(dir, unix.LOCK_SH); err != nil {
		return nil, "", fmt.Errorf("lock %q: %w", dir.Name(), err)
	}

	contents := filepath.Join(dir.Name(), "contents")
	if _, err := os.Stat(contents); err == nil {
		// We have a cached copy of the image.
		return dir, contents, nil
	}

	// Need to extract the image, acquire exclusive lock.
	if err := flock(dir, unix.LOCK_EX); err != nil {
		return nil, "", fmt.Errorf("lock %q: %w", dir.Name(), err)
	}

	// Changing lock mode is not atomic, revalidate.
	if _, err := os.Stat(contents); err == nil {
		if err := flock(dir, unix.LOCK_SH); err != nil {
			return nil, "", fmt.Errorf("lock %q: %w", dir.Name(), err)
		}
		return dir, contents, nil
	}

	tmpdir, err := os.MkdirTemp(path, "")
	if err != nil {
		return nil, "", err
	}
	defer os.RemoveAll(tmpdir)

	if err := fn(tmpdir); err != nil {
		return nil, "", fmt.Errorf("populate %s: %w", contents, err)
	}

	if err := os.Rename(tmpdir, contents); err != nil {
		return nil, "", err
	}

	// Drop the exclusive lock.
	if err := flock(dir, unix.LOCK_SH); err != nil {
		return nil, "", fmt.Errorf("drop exclusive lock: %w", err)
	}

	return dir, contents, nil
}

type image struct {
	// The image name in OCIspeak, for example "example.com/foo:latest".
	Name string

	// Path to directory containing the contents of the image.
	Directory string

	// The directory file descriptor holding a cache lock.
	lock *os.File
}

func (img *image) Close() error {
	if img != nil {
		return img.lock.Close()
	}
	return nil
}

type bootFiles struct {
	// Path to the kernel to boot.
	Kernel string

	// Path to a directory to be overlaid over the root filesystem. Optional.
	Overlay string

	// Source OCI image. Optional.
	Image *image
}

func newBootFiles(path string) (*bootFiles, error) {
	for _, kernel := range []string{
		"boot/vmlinux",
		"boot/vmlinuz",
	} {
		kernelPath := filepath.Join(path, kernel)
		if _, err := os.Stat(kernelPath); errors.Is(err, os.ErrNotExist) {
			continue
		} else if err != nil {
			return nil, err
		}

		return &bootFiles{
			Kernel:  kernelPath,
			Overlay: path,
		}, nil
	}

	return nil, fmt.Errorf("no kernel found in %s", path)
}

func newBootFilesFromImage(img *image) (*bootFiles, error) {
	bf, err := newBootFiles(img.Directory)
	if err != nil {
		return nil, fmt.Errorf("image %s: %w", img.Name, err)
	}

	bf.Image = img
	return bf, nil
}

var remoteOptions = []remote.Option{
	remote.WithUserAgent("vimto"),
	remote.WithPlatform(v1.Platform{
		OS:           "linux",
		Architecture: runtime.GOARCH,
	}),
}

func fetchImage(ctx context.Context, refStr, dst string, status io.Writer) error {
	ref, err := name.ParseReference(refStr)
	if err != nil {
		return fmt.Errorf("parsing reference %q: %w", refStr, err)
	}

	bar := progressbar.NewOptions64(
		-1,
		progressbar.OptionSetDescription(fmt.Sprintf("Caching %s", ref.Name())),
		progressbar.OptionSetWriter(status),
		progressbar.OptionShowBytes(true),
		progressbar.OptionShowTotalBytes(false),
		progressbar.OptionThrottle(65*time.Millisecond),
		progressbar.OptionShowCount(),
		progressbar.OptionSpinnerType(14),
		progressbar.OptionFullWidth(),
		progressbar.OptionSetRenderBlankState(true),
		progressbar.OptionClearOnFinish(),
	)
	defer bar.Finish()

	options := append(slices.Clone(remoteOptions),
		remote.WithContext(ctx),
	)

	rmt, err := remote.Get(ref, options...)
	if err != nil {
		return fmt.Errorf("get from remote: %w", err)
	}

	image, err := rmt.Image()
	if err != nil {
		return err
	}

	if err := os.MkdirAll(dst, 0755); err != nil {
		return fmt.Errorf("create destination directory: %w", err)
	}

	rc := mutate.Extract(image)
	defer rc.Close()

	reader := readProxy{rc, bar}

	return archive.UntarUncompressed(reader, dst, &archive.TarOptions{NoLchown: true})
}

type readProxy struct {
	io.Reader
	*progressbar.ProgressBar
}

func (rp readProxy) Read(p []byte) (int, error) {
	n, err := rp.Reader.Read(p)
	rp.ProgressBar.Add(n)
	return n, err
}
