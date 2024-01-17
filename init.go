package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
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
	required       bool
}

func (mp *mountPoint) String() string {
	return fmt.Sprintf("type %s on %s", mp.fstype, mp.target)
}

type mountTable []*mountPoint

// Reference is https://github.com/systemd/systemd/blob/307b6a4dab21c854b141b53d9bdd05c8af0abc78/src/shared/mount-setup.c#L79
var earlyMounts = mountTable{
	{"sys", "/sys", "sysfs", "", unix.MS_NOSUID | unix.MS_NOEXEC | unix.MS_NODEV, true},
	{"proc", "/proc", "proc", "", unix.MS_NOSUID | unix.MS_NOEXEC | unix.MS_NODEV, true},
	{"devtmpfs", "/dev", "devtmpfs", "mode=0755", unix.MS_NOSUID | unix.MS_STRICTATIME, true},
	{"securityfs", "/sys/kernel/security", "securityfs", "", unix.MS_NOSUID | unix.MS_NOEXEC | unix.MS_NODEV, false},
	{"tmpfs", "/dev/shm", "tmpfs", "mode=01777", unix.MS_NOSUID | unix.MS_NODEV | unix.MS_STRICTATIME, true},
	{"tmpfs", "/tmp", "tmpfs", "mode=01777", unix.MS_NOSUID | unix.MS_NOEXEC | unix.MS_NODEV | unix.MS_STRICTATIME, true},
	{"tmpfs", "/run", "tmpfs", "mode=01777", unix.MS_NOSUID | unix.MS_NODEV | unix.MS_STRICTATIME, true},
	{"cgroup2", "/sys/fs/cgroup", "cgroup2", "nsdelegate,memory_recursiveprot", unix.MS_NOSUID | unix.MS_NOEXEC | unix.MS_NODEV, false},
	{"bpf", "/sys/fs/bpf", "bpf", "mode=0700", unix.MS_NOSUID | unix.MS_NOEXEC | unix.MS_NODEV, false},
	{"debugfs", "/sys/kernel/debug", "debugfs", "", unix.MS_NOSUID | unix.MS_NOEXEC | unix.MS_NODEV | unix.MS_RELATIME, false},
	{"tracefs", "/sys/kernel/tracing", "tracefs", "", unix.MS_NOSUID | unix.MS_NOEXEC | unix.MS_NODEV | unix.MS_RELATIME, false},
}

// From man 2 statfs.
var fsMagic = map[string]int64{
	"bpf":        unix.BPF_FS_MAGIC,
	"cgroup2":    unix.CGROUP2_SUPER_MAGIC,
	"devtmpfs":   unix.TMPFS_MAGIC,
	"proc":       unix.PROC_SUPER_MAGIC,
	"securityfs": unix.SECURITYFS_MAGIC,
	"sysfs":      unix.SYSFS_MAGIC,
	"tmpfs":      unix.TMPFS_MAGIC,
}

// Mount all mount points contained in the table.
//
// Returns a list of optional mount points which failed to mount.
func (mt mountTable) mountAll(sys syscaller) ([]*mountPoint, error) {
	var ignored []*mountPoint
	for _, mp := range mt {
		if _, err := os.Stat(mp.target); errors.Is(err, unix.ENOENT) {
			if err := os.MkdirAll(mp.target, 0755); err != nil {
				return nil, fmt.Errorf("mount %s: %w", mp, err)
			}
		} else if err != nil {
			return nil, fmt.Errorf("mount %s: %w", mp, err)
		}

		// TODO: Check /proc/self/mountinfo or similar whether the mountpoint
		// already exists. statfs doesn't work since 9pfs will happily forward
		// the statfs call to the host mount.

		err := sys.mount(mp)
		if errors.Is(err, unix.ENODEV) && !mp.required {
			ignored = append(ignored, mp)
			continue
		} else if errors.Is(err, unix.EBUSY) {
			// Already mounted. From man 2 mount:
			//    An attempt was made to stack a new mount directly on top of an
			//    existing mount point that was created in this mount namespace
			//    with the same source and target.
			continue
		} else if err != nil {
			return nil, fmt.Errorf("mount %s: %w", mp, err)
		}
	}
	return ignored, nil
}

func (mt mountTable) pathIsBelowMount(path string) (string, bool) {
	for _, mp := range mt {
		target := mp.target
		if len(target) > 0 && target[len(target)-1] != filepath.Separator {
			target += string(filepath.Separator)
		}

		// TODO: This ignores case insensitivity of the filesystem.
		if strings.HasPrefix(path, mp.target) {
			return mp.fstype, true
		}
	}
	return "", false
}

func minimalInit(sys syscaller, args []string) error {
	err := func() error {
		ignored, err := earlyMounts.mountAll(sys)
		if err != nil {
			return fmt.Errorf("mount: %w", err)
		}

		for _, mp := range ignored {
			fmt.Fprintf(os.Stderr, "Mounting %s failed, ignoring\n", mp)
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
				if err := os.MkdirAll(path, 0755); err != nil {
					return fmt.Errorf("mount %q: %w", path, err)
				}
			}

			// TODO: Investigate dfltuid, dfltgid, noxattr options.
			err = sys.mount(&mountPoint{
				tag, path,
				"9p",
				"version=9p2000.L,trans=virtio,access=any",
				0,
				false, // ignored
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

		proc := exec.Cmd{
			Path:   cmd.Path,
			Args:   cmd.Args,
			Dir:    cmd.Dir,
			Env:    cmd.Env,
			Stdin:  os.Stdin,
			Stdout: os.Stdout,
			Stderr: os.Stderr,
			SysProcAttr: &syscall.SysProcAttr{
				Credential: &syscall.Credential{
					Uid:         uint32(cmd.Uid),
					Gid:         uint32(cmd.Gid),
					NoSetGroups: true,
				},
			},
		}

		var result execResult
		if err = proc.Run(); err != nil {
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
