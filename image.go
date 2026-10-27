package main

import (
	"context"
	"crypto/sha256"
	"debug/elf"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/adrg/xdg"
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

var userCacheDir = filepath.Join(xdg.CacheHome, "vimto")

func newImageCache() (*imageCache, error) {
	if err := os.MkdirAll(userCacheDir, 0700); err != nil && !errors.Is(err, os.ErrExist) {
		return nil, fmt.Errorf("create cache directory: %w", err)
	}

	return &imageCache{userCacheDir}, nil
}

// Acquire an image from the cache.
//
// fixup is applied to the contents after extraction. variant distinguishes
// cache entries whose contents differ due to fixup.
//
// The image remains valid even after closing the cache.
func (ic *imageCache) Acquire(ctx context.Context, refStr, arch, variant string, status io.Writer, fixup func(dir string) error) (_ *image, err error) {
	ref, err := name.ParseReference(refStr)
	if err != nil {
		return nil, fmt.Errorf("parsing reference %q: %w", refStr, err)
	}

	// Use the sha256 of the canonical reference, the architecture and the
	// variant as the cache key. This means that images / tags pointing at the
	// blob will have separate cache entries.
	dir := fmt.Sprintf("%x", sha256.Sum256([]byte(ref.Name()+arch+variant)))

	lock, path, err := populateDirectoryOnce(filepath.Join(ic.baseDir, dir), func(path string) error {
		if err := fetchImage(ctx, refStr, arch, path, status); err != nil {
			return fmt.Errorf("fetch image: %w", err)
		}

		if fixup != nil {
			if err := fixup(path); err != nil {
				return fmt.Errorf("fix up image: %w", err)
			}
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

	// Path to an ELF binary with symbols matching Kernel. Optional.
	Symbols string

	// Path to a directory to be overlaid over the root filesystem. Optional.
	Overlay string

	// Source OCI image. Optional.
	Image *image
}

func newBootFiles(path, arch string) (*bootFiles, error) {
	const (
		vmlinux = "boot/vmlinux"
		vmlinuz = "boot/vmlinuz"
	)
	kernels := []string{vmlinux, vmlinuz}
	if arch == "arm64" {
		// vmlinux is an ELF with symbols, vmlinuz the arch-specific boot
		// format. QEMU boots ELF kernels on most architectures: riscv loads
		// them directly, amd64 uses the PVH entry point. arm64 is different:
		// vmlinux is linked at virtual addresses (p_paddr == p_vaddr, the
		// kernel's linker script doesn't use AT()) and QEMU's generic ELF
		// loader doesn't implement the arm64 boot protocol. The kernel executes
		// from head.S regardless, but faults as soon as it enables the MMU.
		kernels = []string{vmlinuz}
	}

	for _, kernel := range kernels {
		// Pick the first-found kernel image in the list. Debug images have a
		// vmlinux with symbols, so prioritize it to make gdb attaches work.
		kernelPath := filepath.Join(path, kernel)
		if _, err := os.Stat(kernelPath); errors.Is(err, os.ErrNotExist) {
			continue
		} else if err != nil {
			return nil, err
		}

		// Debug images contain a vmlinux with debug symbols. Keep a reference
		// to it even when it isn't bootable, e.g. for use by a debugger.
		var symbols string
		if _, err := os.Stat(filepath.Join(path, vmlinux)); err == nil {
			symbols = vmlinux
		}

		bf := &bootFiles{
			Kernel:  kernelPath,
			Overlay: path,
			Symbols: symbols,
		}

		return bf, nil
	}

	return nil, fmt.Errorf("no kernel found in %s", path)
}

func newBootFilesFromImage(img *image, arch string) (*bootFiles, error) {
	bf, err := newBootFiles(img.Directory, arch)
	if err != nil {
		return nil, fmt.Errorf("image %s: %w", img.Name, err)
	}

	bf.Image = img
	return bf, nil
}

func remoteOptions(arch string) []remote.Option {
	return []remote.Option{
		remote.WithUserAgent("vimto"),
		remote.WithPlatform(v1.Platform{
			OS:           "linux",
			Architecture: arch,
		}),
	}
}

func fetchImage(ctx context.Context, refStr, arch, dst string, status io.Writer) error {
	ref, err := name.ParseReference(refStr)
	if err != nil {
		return fmt.Errorf("parsing reference %q: %w", refStr, err)
	}

	bar := progressbar.NewOptions64(
		-1,
		progressbar.OptionSetDescription(fmt.Sprintf("Caching %s (linux/%s)", ref.Name(), arch)),
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

	options := append(remoteOptions(arch),
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

	// WithPlatform only takes effect for multi-platform images. A
	// single-platform image is returned as is, verify what we got.
	conf, err := image.ConfigFile()
	if err != nil {
		return fmt.Errorf("image config: %w", err)
	}

	if conf.OS != "linux" || conf.Architecture != arch {
		return fmt.Errorf("image %s is %s/%s, not linux/%s", ref.Name(), conf.OS, conf.Architecture, arch)
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

// validateKernel rejects kernels which QEMU can't boot on the given
// architecture, typically hanging the VM without any console output.
func validateKernel(path, arch string) error {
	ef, err := elf.Open(path)
	if _, ok := errors.AsType[*elf.FormatError](err); ok {
		// Not an ELF, assume a native boot format.
		return nil
	}
	if err != nil {
		return err
	}
	defer ef.Close()

	if arch == "arm64" {
		// QEMU expects bare-metal Images for arm64.
		return fmt.Errorf("kernel %s: QEMU can't boot an ELF kernel on %s, use the flat Image format", path, arch)
	}

	return nil
}
