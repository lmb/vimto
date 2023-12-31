package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

type syscaller interface {
	mount(*mountPoint) error
	sync()
	reboot(int) error
	dup2(int, int) error
}

type realSyscaller struct{}

func (rs realSyscaller) mount(mp *mountPoint) error {
	return unix.Mount(mp.source, mp.target, mp.fstype, mp.flags, "")
}

func (rs realSyscaller) sync() {
	unix.Sync()
}

func (rs realSyscaller) reboot(cmd int) error {
	return unix.Reboot(cmd)
}

func (rs realSyscaller) dup2(old, new int) error {
	return unix.Dup2(old, new)
}

type mountPoint struct {
	source, target string
	fstype         string
	flags          uintptr
}

func (mp *mountPoint) String() string {
	return fmt.Sprintf("type %s on %s", mp.fstype, mp.target)
}

var earlyMounts = []*mountPoint{
	{"sys", "/sys/", "sysfs", unix.MS_NOSUID | unix.MS_NOEXEC | unix.MS_NODEV},
	{"proc", "/proc/", "proc", unix.MS_NOSUID | unix.MS_NOEXEC | unix.MS_NODEV},
}

func mount(sys syscaller, mounts []*mountPoint) error {
	for _, mp := range mounts {
		err := sys.mount(mp)
		if err != nil {
			return fmt.Errorf("failed to mount %s: %w", mp, err)
		}
	}
	return nil
}

const (
	stdoutPort = "stdout"
	stderrPort = "stderr"
)

type pid1 struct {
	sys   syscaller
	Ports map[string]string
}

func minimalInit(sys syscaller) (*pid1, error) {
	if err := mount(sys, earlyMounts); err != nil {
		return nil, fmt.Errorf("early mount: %w", err)
	}

	ports, err := readVirtioPorts()
	if err != nil {
		return nil, fmt.Errorf("read virtio-ports names: %w", err)
	}

	if err := replaceStdioWith(sys, 2, ports[stderrPort]); err != nil {
		return nil, fmt.Errorf("replace stderr: %w", err)
	}
	delete(ports, stderrPort)

	if err := replaceStdioWith(sys, 1, ports[stdoutPort]); err != nil {
		return nil, fmt.Errorf("replace stdout: %w", err)
	}
	delete(ports, stdoutPort)

	return &pid1{sys, ports}, nil
}

func (p *pid1) Shutdown() error {
	p.sys.sync()
	return p.sys.reboot(unix.LINUX_REBOOT_CMD_POWER_OFF)
}

func replaceStdioWith(sys syscaller, fd int, path string) error {
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	defer f.Close()

	// dup2 overwrites fd with the newly opened file.
	return sys.dup2(int(f.Fd()), fd)
}

// Read the names of virtio ports from /sys.
//
// Based on https://gitlab.com/qemu-project/qemu/-/issues/506
func readVirtioPorts() (map[string]string, error) {
	const base = "/sys/class/virtio-ports"

	files, err := os.ReadDir(base)
	if err != nil {
		return nil, err
	}

	ports := make(map[string]string)
	for _, file := range files {
		// NB: file.IsDir() returns false even though it behaves like a directory.
		// Oh well!
		name, err := os.ReadFile(filepath.Join(base, file.Name(), "name"))
		if err != nil {
			return nil, err
		}

		ports[strings.TrimSpace(string(name))] = filepath.Join("/dev/", file.Name())
	}

	return ports, nil
}
