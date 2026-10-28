// Package guest implements the init process of the virtual machine.
//
// It is built into a separate, statically linked binary which vimto embeds
// and boots the guest from. The host only imports the types shared with the
// init over the control port.
package guest

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/jsimonetti/rtnetlink/v2/rtnl"
	"golang.org/x/sys/unix"
)

// Default options used to mount a 9pfs.
//
// - cache=mmap: required to avoid mmap returning EINVAL.
const Default9POptions = "version=9p2000.L,trans=virtio,access=any,msize=1048576,cache=mmap"

// Tag of the 9p share containing the guest's base file system.
const P9BaseTag = "base"

// Tag of the 9p share containing the kernel image's overlay.
const P9KernelTag = "kernel"

type Syscaller interface {
	mount(*mountPoint) error
	sync()
	reboot(int) error
}

type RealSyscaller struct{}

func (rs RealSyscaller) mount(mp *mountPoint) error {
	err := unix.Mount(mp.source, mp.target, mp.fstype, mp.flags, mp.options)
	if err != nil {
		return fmt.Errorf("mount %s: %w", mp.target, err)
	}
	return nil
}

func (rs RealSyscaller) sync() {
	unix.Sync()
}

func (rs RealSyscaller) reboot(cmd int) error {
	return unix.Reboot(cmd)
}

func mount(source, target, fstype string, flags uintptr, data string) error {
	err := unix.Mount(source, target, fstype, flags, data)
	if err != nil {
		return fmt.Errorf("mount %s on %s (%s): %w", source, target, fstype, err)
	}
	return nil
}

func mountOverlay(target, upperdir, workdir string, lowerdirs []string) error {
	slices.Reverse(lowerdirs)
	var options strings.Builder
	fmt.Fprintf(&options, "upperdir=%s,workdir=%s,", upperdir, workdir)
	options.WriteString("lowerdir=")
	for i, dir := range lowerdirs {
		if i > 0 {
			options.WriteRune(':')
		}
		options.WriteString(strings.ReplaceAll(dir, `:`, `\:`))
	}

	// 9p passes the host's file ownership through unchanged. Images extracted
	// by an unprivileged user retain their setuid bits but not their owner, so
	// executing e.g. mount would switch from root to that user. Ignore the bits
	// like container runtimes do. The flag has to be set on the mount a file is
	// executed through, which is the overlay rather than its layers.
	return unix.Mount("overlay", target, "overlay", unix.MS_NOSUID, options.String())
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
var EarlyMounts = mountTable{
	{"sys", "/sys", "sysfs", "", unix.MS_NOSUID | unix.MS_NOEXEC | unix.MS_NODEV, true},
	{"proc", "/proc", "proc", "", unix.MS_NOSUID | unix.MS_NOEXEC | unix.MS_NODEV, true},
	{"devtmpfs", "/dev", "devtmpfs", "mode=0755", unix.MS_NOSUID | unix.MS_STRICTATIME, true},
	{"devpts", "/dev/pts", "devpts", "gid=5,mode=620", unix.MS_NOSUID | unix.MS_NOEXEC, true},
	{"securityfs", "/sys/kernel/security", "securityfs", "", unix.MS_NOSUID | unix.MS_NOEXEC | unix.MS_NODEV, false},
	// We don't need tmpfs mounts since the root filesystem is already ephemeral.
	// See prepareRoot().
	// {"tmpfs", "/dev/shm", "tmpfs", "mode=01777", unix.MS_NOSUID | unix.MS_NODEV | unix.MS_STRICTATIME, true},
	// {"tmpfs", "/tmp", "tmpfs", "mode=01777", unix.MS_NOSUID | unix.MS_NOEXEC | unix.MS_NODEV | unix.MS_STRICTATIME, true},
	// {"tmpfs", "/run", "tmpfs", "mode=01777", unix.MS_NOSUID | unix.MS_NODEV | unix.MS_STRICTATIME, true},
	// {"cgroup2", "/sys/fs/cgroup", "cgroup2", "nsdelegate,memory_recursiveprot", unix.MS_NOSUID | unix.MS_NOEXEC | unix.MS_NODEV, false},
	{"bpf", "/sys/fs/bpf", "bpf", "mode=0700", unix.MS_NOSUID | unix.MS_NOEXEC | unix.MS_NODEV, false},
	{"debugfs", "/sys/kernel/debug", "debugfs", "", unix.MS_NOSUID | unix.MS_NOEXEC | unix.MS_NODEV | unix.MS_RELATIME, false},
	{"tracefs", "/sys/kernel/tracing", "tracefs", "", unix.MS_NOSUID | unix.MS_NOEXEC | unix.MS_NODEV | unix.MS_RELATIME, false},
}

// Directories from the host root filesystem which should not be accessible in
// the VM. They are replaced with an empty directory.
var OpaqueDirectories = []string{
	"/dev/shm",
	"/tmp",
	"/run",
}

// From man 2 statfs.
var fsMagic = map[string]int64{
	"bpf":        unix.BPF_FS_MAGIC,
	"cgroup2":    unix.CGROUP2_SUPER_MAGIC,
	"debugfs":    unix.DEBUGFS_MAGIC,
	"devpts":     unix.DEVPTS_SUPER_MAGIC,
	"devtmpfs":   unix.TMPFS_MAGIC,
	"overlay":    unix.OVERLAYFS_SUPER_MAGIC,
	"proc":       unix.PROC_SUPER_MAGIC,
	"securityfs": unix.SECURITYFS_MAGIC,
	"sysfs":      unix.SYSFS_MAGIC,
	"tmpfs":      unix.TMPFS_MAGIC,
	"tracefs":    unix.TRACEFS_MAGIC,
}

// Mount all mount points contained in the table.
//
// Returns a list of optional mount points which failed to mount.
func (mt mountTable) mountAll(sys Syscaller) ([]*mountPoint, error) {
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

func (mt mountTable) PathIsBelowMount(path string) (string, bool) {
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

func Init(sys Syscaller, args []string) error {
	err := func() error {
		if len(args) != 2 {
			return fmt.Errorf("expected two arguments, got %q", args)
		}

		stdioPort := args[0]
		controlPort := args[1]

		if err := prepareRoot(); err != nil {
			return err
		}

		ignored, err := EarlyMounts.mountAll(sys)
		if err != nil {
			return fmt.Errorf("mount: %w", err)
		}

		for _, mp := range ignored {
			fmt.Fprintf(os.Stderr, "Mounting %s failed, ignoring\n", mp)
		}

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
		comm := NewRPC(control)
		defer comm.Close()
		delete(ports, controlPort)

		var cmd ExecCommand
		if err := comm.Read(&cmd, time.Now().Add(time.Second)); err != nil {
			return fmt.Errorf("read command: %w", err)
		}

		for tag, path := range cmd.MountTags {
			path = filepath.Clean(path)
			fmt.Println("Mounting", path)

			// The mountpoint may not exist, e.g. below an opaque directory or
			// when a userland replaced the root filesystem.
			if err := os.MkdirAll(path, 0755); err != nil {
				return fmt.Errorf("mount %q: %w", path, err)
			}

			// TODO: Investigate dfltuid, dfltgid, noxattr options.
			err = sys.mount(&mountPoint{
				tag, path,
				"9p",
				Default9POptions,
				unix.MS_NOSUID,
				false, // ignored
			})
			if err != nil {
				return fmt.Errorf("mount %q: %w", path, err)
			}
		}

		// A userland may contain binaries in directories which are not part of
		// the host's PATH, e.g. /bin on hosts where it is a symlink into /usr.
		cmd.Env = ensurePathBinDirs(cmd.Env)

		// Setup environment variables.
		for _, env := range cmd.Env {
			key, value, _ := strings.Cut(env, "=")
			if key == "PATH" {
				err := os.Setenv("PATH", value)
				if err != nil {
					return err
				}
				// NB: Must check all entries since there might be duplicates.
			}
		}

		// Apply sysctls.
		for _, Sysctl := range cmd.Sysctls {
			err = writeSysctl(Sysctl.Name, Sysctl.Value)
			if err != nil {
				return fmt.Errorf("set Sysctl %s: %w", Sysctl.Name, err)
			}
		}

		if err := setupLoopback(); err != nil {
			fmt.Fprintln(os.Stderr, "Set up lo:", err)
		}

		if err := executeSimpleCommands(cmd.Setup, cmd.Dir, cmd.Env); err != nil {
			return fmt.Errorf("setup: %w", err)
		}

		// Set resource limits
		for resource, limit := range cmd.Rlimits {
			err = unix.Setrlimit(resource, &limit)
			if err != nil {
				return fmt.Errorf("raise resource limit 0x%x: %w", resource, err)
			}
		}

		proc := exec.Command(cmd.Path)
		proc.Args = cmd.Args
		proc.Dir = cmd.Dir
		proc.Env = cmd.Env
		proc.Stdin = stdio
		proc.Stdout = stdio
		proc.Stderr = stdio
		proc.SysProcAttr = &syscall.SysProcAttr{
			Credential: &syscall.Credential{
				Uid:         uint32(cmd.Uid),
				Gid:         uint32(cmd.Gid),
				NoSetGroups: true,
			},
		}

		if err := unix.Access(proc.Path, unix.R_OK); err == unix.EACCES {
			// QEMU limitation: the 9p implementation needs to be able to read the
			// executable to be able to execute it in the VM.
			// TODO: Might be able to avoid this using CAP_DAC_OVERRIDE or similar.
			fmt.Fprintf(stdio, "%s is not readable, execution might fail with %q\n", cmd.Path, err)
		}

		result := proc.Start()
		if result == nil {
			// Work around a bug in virtio-console which doesn't deal well with concurrent
			// access to a single serial port.
			//
			// It is crucial that we don't hold on to stdio, otherwise the runtime will
			// opportunistically poll it, which causes writes to hang.
			//
			// See https://github.com/lmb/vimto/issues/29.
			_ = stdio.Close()

			result = proc.Wait()
		}

		if err := executeSimpleCommands(cmd.Teardown, cmd.Dir, cmd.Env); err != nil {
			return fmt.Errorf("teardown: %w", err)
		}

		var exitError *exec.ExitError
		if errors.As(result, &exitError) && exitError.Exited() {
			result = &ExitError{exitError.ExitCode()}
		} else if result != nil {
			result = &GenericError{result.Error()}
		}

		return comm.Write(&result, time.Now().Add(time.Second))
	}()

	if err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
	}

	sys.sync()
	return sys.reboot(unix.LINUX_REBOOT_CMD_POWER_OFF)
}

// Standard locations for binaries according to the FHS.
var binDirs = []string{
	"/usr/local/sbin",
	"/usr/local/bin",
	"/usr/sbin",
	"/usr/bin",
	"/sbin",
	"/bin",
}

// ensurePathBinDirs appends standard binary directories to PATH entries in env if
// they are missing.
func ensurePathBinDirs(env []string) []string {
	for i, kv := range env {
		key, value, _ := strings.Cut(kv, "=")
		if key != "PATH" {
			continue
		}

		var dirs []string
		if value != "" {
			dirs = strings.Split(value, string(filepath.ListSeparator))
		}
		for _, dir := range binDirs {
			if !slices.Contains(dirs, dir) {
				dirs = append(dirs, dir)
			}
		}

		env[i] = "PATH=" + strings.Join(dirs, string(filepath.ListSeparator))
	}
	return env
}

// setupLoopback brings up the loopback interface.
func setupLoopback() error {
	conn, err := rtnl.Dial(nil)
	if err != nil {
		return err
	}
	defer conn.Close()

	lo, err := net.InterfaceByName("lo")
	if err != nil {
		return err
	}

	return conn.LinkUp(lo)
}

func executeSimpleCommands(cmds []Command, dir string, env []string) error {
	for _, args := range cmds {
		if len(args) < 1 {
			return fmt.Errorf("invalid empty command")
		}

		cmd := exec.Command(args[0], args[1:]...)
		cmd.Dir = dir
		cmd.Env = env
		cmd.Stderr = os.Stderr
		cmd.Stdout = os.Stdout
		cmd.WaitDelay = time.Second
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("%s: %w", cmd.Path, err)
		}
	}
	return nil
}

func prepareRoot() error {
	const (
		oldRootDir = "/oldroot"
		baseDir    = "/base"
		kernelDir  = "/kernel"
		upperDir   = "/upper"
		workDir    = "/work"
		mergedDir  = "/merged"
	)

	// The current mount table looks something like this:
	//    /    9pfs     boot directory containing the init binary
	//    /dev devtmpfs (automounted)

	// Remove unnecessary /dev, we're going to mount our own later on.
	if err := unix.Unmount("/dev", 0); err != nil && !errors.Is(err, unix.ENOENT) {
		return fmt.Errorf("unmount automounted /dev: %w", err)
	}

	// Mount a tmpfs so that we can create files, etc. Doesn't have to be on
	// /tmp, but why not?
	// Limit its size to 25% of total RAM to avoid triggering oomkills, instead
	// turning them into ENOSPC or similar.
	// TODO: flags?
	if err := mount("tmpfs", "/tmp", "tmpfs", 0, "size=25%"); err != nil {
		return err
	}

	// Create mountpoints in our own tmpfs.
	for _, dir := range []string{oldRootDir, baseDir, kernelDir, upperDir, workDir, mergedDir} {
		if err := os.Mkdir(filepath.Join("/tmp", dir), 0755); err != nil {
			return err
		}
	}

	// Switch the root to the tmpfs. The old root only serves to keep the init
	// binary alive.
	if err := unix.PivotRoot("/tmp", filepath.Join("/tmp", oldRootDir)); err != nil {
		return fmt.Errorf("pivot root: %w", err)
	}

	// The mount table is now:
	//    /         tmpfs
	//    /oldroot  9pfs

	// Remove access to some temporary directories in case host root is mounted
	// as base dir.
	//
	// See https://docs.kernel.org/filesystems/overlayfs.html#whiteouts-and-opaque-directories
	for _, opaque := range OpaqueDirectories {
		path := filepath.Join(upperDir, opaque)
		if err := os.MkdirAll(path, 0755); err != nil {
			return fmt.Errorf("make directory opaque: %w", err)
		}

		if err := unix.Setxattr(path, "trusted.overlay.opaque", []byte("y"), 0); err != nil {
			return fmt.Errorf("set opaque xattr: %w", err)
		}
	}

	// The base of the guest's file system. The host decides whether this is
	// its own root or a userland image, the guest doesn't care.
	if err := mount(P9BaseTag, baseDir, "9p", unix.MS_RDONLY|unix.MS_NOSUID, Default9POptions); err != nil {
		return fmt.Errorf("mount base: %w", err)
	}

	// Constituent parts of the merged filesystem.
	//
	// Directories with lower indices sit lower in the stack of layers.
	lowerDirs := []string{baseDir}

	// Optionally mount the kernel image and merge it over the base.
	err := mount(P9KernelTag, kernelDir, "9p", unix.MS_RDONLY|unix.MS_NOSUID, Default9POptions)
	if err != nil {
		if !errors.Is(err, unix.ENOENT) {
			return fmt.Errorf("mount kernel image: %w", err)
		}

		fmt.Fprintln(os.Stderr, "No kernel image provided:", err)
	} else {
		if err := checkLayerShadowing(baseDir, kernelDir); err != nil {
			return err
		}

		lowerDirs = append(lowerDirs, kernelDir)
	}

	// Mount the overlayfs which we'll use as the root.
	if err := mountOverlay(mergedDir, upperDir, workDir, lowerDirs); err != nil {
		return fmt.Errorf("mount root overlay: %w", err)
	}

	// Detect the kernel image's module path and bind-mount it at /lib/modules.
	// The mount operation will follow any symlinks present in the merged dir,
	// so will account for usrmerged base images automatically.
	if modules := findModules(kernelDir); modules != "" {
		// Bind the modules to the conventional location so that tools like
		// modprobe work regardless of the base's layout.
		dst := filepath.Join(mergedDir, "lib", "modules")
		if err := os.MkdirAll(dst, 0755); err != nil {
			return err
		}

		if err := mount(modules, dst, "", unix.MS_BIND, ""); err != nil {
			return err
		}
	} else {
		fmt.Fprintln(os.Stderr, "No modules in kernel image")
	}

	// The mount table is now:
	//    /        tmpfs
	//    /oldroot 9pfs
	//    /base    9pfs
	//    /kernel  9pfs (optional)
	//    /merged  overlayfs

	if err := os.Chdir(mergedDir); err != nil {
		return err
	}

	err = unix.Mount(".", "/", "", unix.MS_MOVE, "")
	if err != nil {
		return fmt.Errorf("move root mount: %w", err)
	}

	// The mount table is now:
	//    /        overlayfs
	//    /oldroot 9pfs              (shadowed by /)

	if err := unix.Chroot("."); err != nil {
		return fmt.Errorf("chroot: %w", err)
	}

	if err := unix.Chdir("/"); err != nil {
		return fmt.Errorf("chdir: %w", err)
	}

	if err := unix.Chmod("/tmp", 01777); err != nil {
		return fmt.Errorf("chmod /tmp: %w", err)
	}

	return nil
}

func findModules(root string) string {
	for _, dir := range []string{"lib/modules", "usr/lib/modules"} {
		if m, err := filepath.EvalSymlinks(filepath.Join(root, dir)); err == nil {
			return m
		}
	}
	return ""
}

var errShadowedPath = errors.New("path would be shadowed by incoming layer")

// checkLayerShadowing ensures that paths a and b don't shadow any important
// paths in each other.
//
// Overlayfs only merges directories, never a directory and a symlink. A
// directory in a kernel image shadows a symlink in a base image and vice versa.
func checkLayerShadowing(a, b string) error {
	for _, dir := range []string{"/lib", "/lib64", "/bin", "/sbin"} {
		aInfo, err := os.Lstat(filepath.Join(a, dir))
		if errors.Is(err, os.ErrNotExist) {
			continue
		} else if err != nil {
			return err
		}

		bInfo, err := os.Lstat(filepath.Join(b, dir))
		if errors.Is(err, os.ErrNotExist) {
			continue
		} else if err != nil {
			return err
		}

		if aInfo.IsDir() != bInfo.IsDir() {
			return fmt.Errorf("%s shadows %s in %s: %w", b, dir, a, errShadowedPath)
		}
	}

	return nil
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

func writeSysctl(name, value string) error {
	path := filepath.Join("/proc/sys", strings.ReplaceAll(name, ".", string(filepath.Separator)))
	// No O_CREAT, so that we don't create non-existent sysctls.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	_, err = io.WriteString(f, value)
	if err1 := f.Close(); err1 != nil && err == nil {
		err = err1
	}
	return err
}
