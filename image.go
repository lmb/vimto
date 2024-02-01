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

func newImageCache(cli *docker.Client) *imageCache {
	return &imageCache{cli, os.TempDir()}
}

func (ic *imageCache) Acquire(ctx context.Context, img string) (_ *image, err error) {
	closeOnError := func(c io.Closer) {
		if err != nil {
			c.Close()
		}
	}

	refStr, digest, err := fetchImage(ctx, ic.cli, img)
	if err != nil {
		return nil, fmt.Errorf("fetch image: %w", err)
	}

	cacheDir, err := ic.openCacheDir(digest)
	if err != nil {
		return nil, err
	}
	defer closeOnError(cacheDir)

	if err := flock(cacheDir, unix.LOCK_SH); err != nil {
		return nil, fmt.Errorf("lock %q: %w", cacheDir.Name(), err)
	}

	contents := filepath.Join(cacheDir.Name(), "contents")
	if _, err := os.Stat(contents); err == nil {
		// We have a cached copy of the image.
		return &image{contents, cacheDir, true}, nil
	}

	// Need to extract the image, acquire exclusive lock.
	if err := flock(cacheDir, unix.LOCK_EX); err != nil {
		return nil, fmt.Errorf("lock %q: %w", cacheDir.Name(), err)
	}

	tmpdir, err := os.MkdirTemp(ic.baseDir, "")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmpdir)

	if err := extractImage(ctx, ic.cli, refStr, tmpdir); err != nil {
		return nil, fmt.Errorf("extract image: %w", err)
	}

	if err := os.Rename(tmpdir, contents); err != nil {
		return nil, fmt.Errorf("rename temporary directory: %w", err)
	}

	// Drop the exclusive lock.
	if err := flock(cacheDir, unix.LOCK_SH); err != nil {
		return nil, fmt.Errorf("drop exclusive lock: %w", err)
	}

	return &image{contents, cacheDir, false}, nil
}

func (ic *imageCache) openCacheDir(id string) (*os.File, error) {
	base := filepath.Join(ic.baseDir, "vimto")
	if err := os.MkdirAll(base, 0o777); err != nil {
		return nil, err
	}

	uid := os.Getuid()
	cacheDir := filepath.Join(base, fmt.Sprint(uid), id)
	if err := os.MkdirAll(cacheDir, 0755); err != nil {
		return nil, fmt.Errorf("create cache directory: %w", err)
	}

	return os.Open(cacheDir)
}

type image struct {
	Directory string
	dir       *os.File
	cached    bool
}

func (img *image) Release() error {
	return img.dir.Close()
}

func fetchImage(ctx context.Context, cli *docker.Client, refStr string) (string, string, error) {
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

	decoder := json.NewDecoder(remotePullReader)
	for {
		var pullResponse jsonmessage.JSONMessage
		if err := decoder.Decode(&pullResponse); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return "", "", err
		}

		if pullResponse.Error != nil {
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
