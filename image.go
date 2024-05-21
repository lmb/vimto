package main

import (
	"archive/tar"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/docker/docker/api/types"
	docker "github.com/docker/docker/client"
	"github.com/docker/docker/pkg/jsonmessage"
	"golang.org/x/sys/unix"
)

const imageKernelPath = "boot/vmlinuz"

// imageCache ensures that multiple invocations of vimto don't download the
// same images over and over again.
//
// The main concern is startup speed of vimto.
type imageCache struct {
	cli     *docker.Client
	baseDir string
}

func newImageCache(cli *docker.Client) (*imageCache, error) {
	allCache := filepath.Join(os.TempDir(), "vimto")
	if err := os.MkdirAll(allCache, 0777); err != nil {
		return nil, err
	}

	uid := os.Getuid()
	userCache := filepath.Join(allCache, fmt.Sprint(uid))
	if err := os.Mkdir(userCache, 0755); err != nil && !errors.Is(err, os.ErrExist) {
		return nil, fmt.Errorf("create cache directory: %w", err)
	}

	return &imageCache{cli, userCache}, nil
}

// Acquire an image from the cache.
//
// The image remains valid even after closing the cache.
func (ic *imageCache) Acquire(ctx context.Context, img string, status io.Writer) (_ *image, err error) {
	refStr, digest, err := fetchImage(ctx, ic.cli, img, status)
	if err != nil {
		return nil, fmt.Errorf("fetch image: %w", err)
	}

	dir, err := populateDirectoryOnce(filepath.Join(ic.baseDir, digest), func(path string) error {
		return extractImage(ctx, ic.cli, refStr, path)
	})
	if err != nil {
		return nil, err
	}

	return newImage(img, dir)
}

// populateDirectoryOnce creates path by executing fn once across multiple
// processes.
//
// Returns a file descriptor for path.
func populateDirectoryOnce(path string, fn func(tmpDir string) error) (*os.File, error) {
	tmpPath := path + "-tmp"
	for {
		// (1) Happy path: the directory exists. Pairs with (4).
		dir, err := os.Open(path)
		if err == nil {
			return dir, nil
		} else if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}

		// Unhappy path, the directory doesn't exist.
		dir, err = createLockedDirectory(tmpPath, 0755)
		if errors.Is(err, os.ErrExist) {
			// (2) Something else managed to grab the lock, wait for it to finish.
			// Also removes any corrupt temporary state. Pairs with (3), (5).
			if err := removeAllLocked(tmpPath); err != nil {
				return nil, err
			}

			// Check whether the directory exists now.
			continue
		} else if err != nil {
			return nil, err
		}
		// (3) Always close on error to release the exclusive lock. Pairs with (2).
		defer dir.Close()

		if err := fn(tmpPath); err != nil {
			return nil, fmt.Errorf("populate directory: %w", err)
		}

		// (4) Commit the directory. Pairs with (1).
		if err := unix.Renameat2(unix.AT_FDCWD, tmpPath, unix.AT_FDCWD, path, unix.RENAME_NOREPLACE); err != nil {
			return nil, fmt.Errorf("commit directory: %w", err)
		}

		// (5) Release the exclusive lock, pairs with (2).
		if err := dir.Close(); err != nil {
			return nil, err
		}

		// Use the created directory.
		return os.Open(path)
	}
}

type image struct {
	Name      string
	Directory string
	dir       *os.File
}

func newImage(name string, dir *os.File) (*image, error) {
	// Lock the directory for good measure (not required for cache consistency).
	if err := flock(dir, unix.LOCK_SH); err != nil {
		return nil, err
	}
	return &image{Name: name, Directory: dir.Name(), dir: dir}, nil
}

func (img *image) Close() error {
	return img.dir.Close()
}

func (img *image) Kernel() string {
	return filepath.Join(img.Directory, imageKernelPath)
}

func fetchImage(ctx context.Context, cli *docker.Client, refStr string, status io.Writer) (string, string, error) {
	if refStr, digest, err := imageID(ctx, cli, refStr); err == nil {
		// Found a cached image, use that.
		// TODO: We don't notice if the tag changes since we don't pull
		// again if we can resolve refStr to id locally.
		return refStr, digest, nil
	}

	remotePullReader, err := cli.ImagePull(ctx, refStr, types.ImagePullOptions{})
	if err != nil {
		return "", "", fmt.Errorf("cannot pull image %s: %w", refStr, err)
	}
	defer remotePullReader.Close()

	isTTY := false
	if f, ok := status.(*os.File); ok {
		isTTY, err = fileIsTTY(f)
		if err != nil {
			return "", "", fmt.Errorf("check whether output is tty: %w", err)
		}
	}

	decoder := json.NewDecoder(remotePullReader)
	for {
		var pullResponse jsonmessage.JSONMessage
		if err := decoder.Decode(&pullResponse); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return "", "", err
		}

		if err := pullResponse.Display(status, isTTY); err != nil {
			return "", "", fmt.Errorf("docker response: %w", pullResponse.Error)
		}
	}

	return imageID(ctx, cli, refStr)
}

func imageID(ctx context.Context, cli *docker.Client, refStr string) (string, string, error) {
	image, _, err := cli.ImageInspectWithRaw(ctx, refStr)
	if err != nil {
		return "", "", fmt.Errorf("inspect image: %w", err)
	}

	if len(image.RepoDigests) < 1 {
		return "", "", fmt.Errorf("no digest for %q", refStr)
	}

	return image.RepoDigests[0], image.ID, nil
}

func extractImage(ctx context.Context, cli *docker.Client, image, dst string) error {
	cmd := exec.CommandContext(ctx, "docker", "buildx", "build", "--quiet", "--output", dst, "-")
	cmd.Stdin = strings.NewReader(fmt.Sprintf("FROM %s\n", image))
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, string(out))
	}
	return nil
}

func extractTar(r io.Reader, path string) error {
	tr := tar.NewReader(r)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("read tar header: %w", err)
		}

		dstPath, err := secureJoin(path, path, hdr.Name)
		if err != nil {
			return err
		}

		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(dstPath, 0755); err != nil {
				return err
			}

		case tar.TypeReg:
			dst, err := os.Create(dstPath)
			if err != nil {
				return err
			}
			defer dst.Close()

			_, err = io.Copy(dst, tr)
			if err != nil {
				return err
			}

		case tar.TypeLink:
			srcPath, err := secureJoin(path, path, hdr.Linkname)
			if err != nil {
				return fmt.Errorf("hard link: %w", err)
			}

			if err := os.Link(srcPath, dstPath); err != nil {
				return err
			}

		case tar.TypeSymlink:
			// Relative symlinks start from the location of the symlink.
			srcPath, err := secureJoin(path, filepath.Dir(dstPath), hdr.Linkname)
			if err != nil {
				return fmt.Errorf("sym link: %w (dst: %s)", err, dstPath)
			}

			if err := os.Symlink(srcPath, dstPath); err != nil {
				return err
			}

		default:
			return fmt.Errorf("unexpected tar header type %d", hdr.Typeflag)
		}
	}
}

func secureJoin(base string, parts ...string) (string, error) {
	base, err := filepath.Abs(base)
	if err != nil {
		return "", err
	}

	path := filepath.Join(parts...)
	if !filepath.IsAbs(path) {
		path = filepath.Join(base, path)
	}

	if !strings.HasPrefix(path, base) {
		return "", fmt.Errorf("invalid path %q (escapes %s)", path, base)
	}

	return path, nil
}
