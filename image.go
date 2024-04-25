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

	lock, path, err := populateDirectoryOnce(filepath.Join(ic.baseDir, digest), func(path string) error {
		return extractImage(ctx, ic.cli, refStr, path)
	})
	if err != nil {
		return nil, err
	}

	return &image{img, path, lock}, nil
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
	Name      string
	Directory string
	dir       *os.File
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
