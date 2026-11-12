package main

import (
	"crypto/sha256"
	_ "embed"
	"fmt"
	"os"
	"path/filepath"
)

// Statically linked init binaries, one per supported guest architecture. The
// guest can't execute vimto itself, which may be dynamically linked or built
// for a different architecture.
//
// Must be regenerated when the guest package changes.
//
// Use GOTOOLCHAIN to pin the exact Go binary used to build vminit for
// reproducibility since the binary is checked into git. This is not the same as
// as `toolchain` directive in go.mod, which only sets a minimum version and
// negatively affects the `go install`ability of the repository.

//go:generate env GOTOOLCHAIN=go1.27.3 CGO_ENABLED=0 GOARCH=amd64 go build -trimpath -buildvcs=false -ldflags "-s -w" -o vminit/amd64 ./cmd/vminit
//go:generate env GOTOOLCHAIN=go1.27.3 CGO_ENABLED=0 GOARCH=arm64 go build -trimpath -buildvcs=false -ldflags "-s -w" -o vminit/arm64 ./cmd/vminit

//go:embed vminit/amd64
var vminitAmd64 []byte

//go:embed vminit/arm64
var vminitArm64 []byte

// extractVMInit writes the embedded init binary for arch to the cache directory
// and returns its path.
func extractVMInit(arch string) (string, error) {
	var vminit []byte
	switch arch {
	case "amd64":
		vminit = vminitAmd64
	case "arm64":
		vminit = vminitArm64
	default:
		return "", fmt.Errorf("no embedded init for architecture %q", arch)
	}

	if len(vminit) == 0 {
		return "", fmt.Errorf("embedded init for %s is empty (did go generate run?)", arch)
	}

	if err := os.MkdirAll(userCacheDir, 0700); err != nil {
		return "", fmt.Errorf("create cache directory: %w", err)
	}

	sum := sha256.Sum256(vminit)
	path := filepath.Join(userCacheDir, fmt.Sprintf("init-%s-%x", arch, sum[:8]))

	// Return path if init binary already installed.
	if _, err := os.Stat(path); err == nil {
		return path, nil
	}

	tmp, err := os.CreateTemp(userCacheDir, "init-*")
	if err != nil {
		return "", err
	}
	defer os.Remove(tmp.Name())
	defer tmp.Close()

	if _, err := tmp.Write(vminit); err != nil {
		return "", err
	}

	if err := tmp.Chmod(0755); err != nil {
		return "", err
	}

	if err := os.Rename(tmp.Name(), path); err != nil {
		return "", err
	}

	return path, nil
}
