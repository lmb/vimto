package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

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
	return unix.Mount(mp.source, mp.target, mp.fstype, mp.flags, mp.options)
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
	options        string
	flags          uintptr
}

func (mp *mountPoint) String() string {
	return fmt.Sprintf("type %s on %s", mp.fstype, mp.target)
}

type mountTable []*mountPoint

// Reference is https://github.com/systemd/systemd/blob/307b6a4dab21c854b141b53d9bdd05c8af0abc78/src/shared/mount-setup.c#L79
var earlyMounts = mountTable{
	{"sys", "/sys/", "sysfs", "", unix.MS_NOSUID | unix.MS_NOEXEC | unix.MS_NODEV},
	{"proc", "/proc/", "proc", "", unix.MS_NOSUID | unix.MS_NOEXEC | unix.MS_NODEV},
	{"tmpfs", "/tmp/", "tmpfs", "mode=0755", unix.MS_NOSUID | unix.MS_NOEXEC | unix.MS_NODEV | unix.MS_STRICTATIME},
	{"tmpfs", "/run/", "tmpfs", "mode=0755", unix.MS_NOSUID | unix.MS_NODEV | unix.MS_STRICTATIME},
}

func (mt mountTable) mountAll(sys syscaller) error {
	for _, mp := range mt {
		err := sys.mount(mp)
		if err != nil {
			return fmt.Errorf("failed to mount %s: %w", mp, err)
		}
	}
	return nil
}

func (mt mountTable) pathIsBelowMount(path string) (string, bool) {
	for _, mp := range mt {
		if strings.HasPrefix(path, mp.target) {
			return mp.fstype, true
		}
	}
	return "", false
}

type env struct {
	Args  []string
	Ports map[string]string
}

func minimalInit(sys syscaller, args []string, fn func(*env) error) error {
	err := func() error {
		if err := earlyMounts.mountAll(sys); err != nil {
			return fmt.Errorf("early mount: %w", err)
		}

		if len(args) != 2 {
			return fmt.Errorf("expected two arguments, got %q", args)
		}

		stdioPort := args[0]
		controlPort := args[1]

		ports, err := readVirtioPorts()
		if err != nil {
			return err
		}

		stdio, err := os.OpenFile(ports[stdioPort], os.O_RDWR, 0)
		if err != nil {
			return fmt.Errorf("open stdio: %w", err)
		}
		defer stdio.Close()
		delete(ports, stdioPort)

		control, err := os.OpenFile(ports[controlPort], os.O_RDWR, 0)
		if err != nil {
			return err
		}
		defer control.Close()
		delete(ports, controlPort)

		if err := control.SetDeadline(time.Now().Add(time.Second)); err != nil {
			return fmt.Errorf("control port: %w", err)
		}

		var cmd execCommand
		if err := json.NewDecoder(control).Decode(&cmd); err != nil {
			return fmt.Errorf("read command: %w", err)
		}

		tags, err := read9PMountTags()
		if err != nil {
			return fmt.Errorf("read 9p mount tags: %w", err)
		}

		for _, tag := range tags {
			if tag == p9RootTag {
				continue
			}

			path, ok := cmd.MountTags[tag]
			if !ok {
				return fmt.Errorf("missing path for 9p mount tag %q", tag)
			}

			fmt.Println("Mounting", path)

			if fs, ok := earlyMounts.pathIsBelowMount(path); ok && fs == "tmpfs" {
				if err := os.MkdirAll(path, 0644); err != nil {
					return fmt.Errorf("mount %q: %w", path, err)
				}
			}

			err = sys.mount(&mountPoint{
				tag, path,
				"9p",
				"version=9p2000.L,trans=virtio,access=any",
				0,
			})
			if err != nil {
				return fmt.Errorf("mount %q: %w", path, err)
			}
		}

		if err := replaceFdWithFile(sys, 2, stdio); err != nil {
			return fmt.Errorf("replace stderr: %w", err)
		}

		if err := replaceFdWithFile(sys, 1, stdio); err != nil {
			return fmt.Errorf("replace stdout: %w", err)
		}

		if err := replaceFdWithFile(sys, 0, stdio); err != nil {
			return fmt.Errorf("replace stdin: %w", err)
		}

		var result execResult
		if err = fn(&env{cmd.Args, ports}); err != nil {
			result.Error = err.Error()
			if result.Error == "" {
				result.Error = fmt.Sprintf("nil error of type %T", err)
			}
		}

		if err := control.SetDeadline(time.Now().Add(time.Second)); err != nil {
			return fmt.Errorf("control port: %w", err)
		}

		return json.NewEncoder(control).Encode(&result)
	}()

	if err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
	}

	sys.sync()
	return sys.reboot(unix.LINUX_REBOOT_CMD_POWER_OFF)
}

func replaceFdWithFile(sys syscaller, fd int, file *os.File) error {
	raw, err := file.SyscallConn()
	if err != nil {
		return err
	}

	var dupErr error
	err = raw.Control(func(replacement uintptr) {
		// dup2 overwrites fd with the newly opened file.
		dupErr = sys.dup2(int(replacement), fd)
	})
	if err != nil {
		return err
	}
	return dupErr
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

func read9PMountTags() ([]string, error) {
	files, err := filepath.Glob("/sys/bus/virtio/drivers/9pnet_virtio/virtio*/mount_tag")
	if err != nil {
		return nil, err
	}

	var tags []string
	for _, file := range files {
		rawTag, err := os.ReadFile(file)
		if err != nil {
			return nil, err
		}

		tags = append(tags, unix.ByteSliceToString(rawTag))
	}

	return tags, nil
}
