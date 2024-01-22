package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"time"

	"github.com/u-root/u-root/pkg/qemu"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sys/unix"
)

const p9OverlayTag = "overlay"

// command is a binary to be executed under a different kernel.
//
// Mirrors exec.Cmd.
type command struct {
	Kernel string
	// Memory to give to the VM. Passed verbatim as the QEMU -m flag.
	Memory string
	// SMP is passed verbatim as the QEMU -smp flag.
	SMP string
	// Path to the binary to execute.
	Path string
	// Arguments passed to the binary. The first element is conventionally Path.
	Args []string
	// The directory to execute the binary in. Defaults to the current working
	// directory.
	Dir string
	// User id and group id to execute the command under.
	Uid, Gid int
	// Env works like exec.Cmd.Env.
	Env    []string
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
	// A directory to overlay over the root filesystem.
	RootOverlay string

	SerialPorts       map[string]*os.File
	SharedDirectories []string

	cmd   *exec.Cmd
	tasks errgroup.Group
	// Console contains boot diagnostics may only be read once tasks.Wait() has returned.
	console bytes.Buffer
	// Results may contain the result of an execution after tasks.Wait() has returned.
	results chan *execResult
	// Write end of a pipe used to provide a blocking stdin to qemu.
	fakeStdin *os.File
}

func (cmd *command) Start(ctx context.Context) (err error) {
	closeOnError := func(c io.Closer) {
		if err != nil {
			c.Close()
		}
	}

	const controlPortName = "ctrl"
	const stdioPortName = "stdio"

	if cmd.cmd != nil {
		return errors.New("qemu: already started")
	}

	if err := unix.Access(cmd.Path, unix.R_OK); err != nil && cmd.Stderr != nil {
		// QEMU limitation: the 9p implementation needs to be able to read the
		// executable to be able to execute it in the VM.
		// TODO: Might be able to avoid this using CAP_DAC_OVERRIDE or similar.
		fmt.Fprintf(cmd.Stderr, "%s is not readable, execution might fail with %q\n", cmd.Path, unix.EACCES)
	}

	fds := &fdSets{}
	cds := &chardevs{}
	ports := &serialPorts{}
	virtioPorts := &virtioSerialPorts{make(map[chardev]string)}

	// The first serial port is always console, earlyprintk and SeaBIOS (on amd64)
	// output. SeaBIOS seems to always write to the first serial port.
	// Some platforms like the arm64 virt board only have a single console.
	consoleHost, consoleGuest, err := unixSocketpair()
	if err != nil {
		return err
	}
	defer consoleHost.Close()
	defer consoleGuest.Close()

	consolePort := ports.add(cds.addFdSet(fds.addFile(consoleGuest)))

	// The second serial port is used for communication between host and guest.
	controlHost, controlGuest, err := unixSocketpair()
	if err != nil {
		return err
	}
	defer controlHost.Close()
	defer controlGuest.Close()

	virtioPorts.Chardevs[cds.addFdSet(fds.addFile(controlGuest))] = controlPortName

	// The third serial port is always stdio. The init process executes
	// subprocesses with this port as stdin, stdout and stderr.
	virtioPorts.Chardevs[chardev("stdio")] = stdioPortName

	devices := []qemu.Device{
		qemu.ArbitraryArgs{
			"-nodefaults",
			"-display", "none",
			"-enable-kvm",
			"-cpu", "host",
			"-chardev", "stdio,id=stdio",
			"-m", cmd.Memory,
			"-smp", cmd.SMP,
		},
		qemu.VirtioRandom{},
		readOnlyRootfs{},
		exitOnPanic{},
		disablePS2Probing{},
		disableRaidAutodetect{},
		&p9Root{
			"/",
		},
		// enableGDBServer{},
		fds,
		cds,
		ports,
		virtioPorts,
		consoleOnSerialPort{consolePort},
	}

	var binary string
	switch runtime.GOARCH {
	case "amd64":
		binary = "qemu-system-x86_64"
		devices = append(devices, earlyprintkOnSerialPort{consolePort})

	case "arm64":
		binary = "qemu-system-aarch64"
		devices = append(devices,
			qemu.ArbitraryArgs{"-machine", "virt,gic-version=host"},
			earlycon{},
		)

	default:
		return fmt.Errorf("unsupported GOARCH %s", runtime.GOARCH)
	}

	for name, port := range cmd.SerialPorts {
		virtioPorts.Chardevs[cds.addFdSet(fds.addFile(port))] = name
	}

	dir := cmd.Dir
	if dir == "" {
		dir, err = os.Getwd()
		if err != nil {
			return err
		}
	}

	// Ensure that the binary and the working directory are always available
	// in the guest.
	sharedDirectories := slices.Clone(cmd.SharedDirectories)
	for _, dir := range []string{filepath.Dir(cmd.Path), dir} {
		fstype, found := earlyMounts.pathIsBelowMount(dir)
		if !found {
			continue
		}

		if fstype != "tmpfs" {
			return fmt.Errorf("directory %s is shadowed by %s mount in the guest", dir, fstype)
		}

		sharedDirectories = append(sharedDirectories, dir)
	}
	slices.Sort(sharedDirectories)
	slices.Compact(sharedDirectories)

	mountTags := make(map[string]string)
	for i, path := range sharedDirectories {
		id := fmt.Sprintf("sd-9p-%d", i)
		mountTags[id] = path
		devices = append(devices, &p9SharedDirectory{
			ID:   fsdev(id),
			Tag:  id,
			Path: path,
		})
	}

	var rootOverlay string
	if cmd.RootOverlay != "" {
		rootOverlay, err = filepath.Abs(cmd.RootOverlay)
		if err != nil {
			return err
		}

		devices = append(devices, &p9SharedDirectory{
			fsdev(p9OverlayTag),
			p9OverlayTag,
			rootOverlay,
			true,
		})
	}

	execCmd := execCommand{
		cmd.Path,
		cmd.Args,
		dir,
		cmd.Uid, cmd.Gid,
		cmd.Env,
		mountTags,
	}

	if execCmd.Env == nil {
		// TODO: Might have to do some filtering here.
		execCmd.Env = os.Environ()
	}

	init, err := findExecutable()
	if err != nil {
		return err
	}

	// init has to go last since we stop processing of KArgs after.
	devices = append(devices, initWithArgs{
		init,
		[]string{stdioPortName, controlPortName},
	})

	qemuPath, err := exec.LookPath(binary)
	if err != nil {
		return err
	}

	qemuOpts := qemu.Options{
		QEMUPath: qemuPath,
		Kernel:   cmd.Kernel,
		Devices:  devices,
	}

	qemuArgs, err := qemuOpts.Cmdline()
	if err != nil {
		return err
	}

	stdinIsDevZero := false
	if f, ok := cmd.Stdin.(*os.File); ok {
		stdinIsDevZero, err = fileIsDevZero(f)
		if err != nil {
			return fmt.Errorf("stdin: %w", err)
		}
	}

	stdin := cmd.Stdin
	if stdin == nil || stdinIsDevZero {
		// Writing to stdio in the guest hangs when stdin is /dev/zero.
		// Use an empty pipe instead.
		fakeStdinGuest, fakeStdinHost, err := os.Pipe()
		if err != nil {
			return fmt.Errorf("create fake stdin: %w", err)
		}
		defer fakeStdinGuest.Close()
		defer closeOnError(fakeStdinHost)

		stdin = fakeStdinGuest
		cmd.fakeStdin = fakeStdinHost
	}

	proc := exec.CommandContext(ctx, qemuArgs[0], qemuArgs[1:]...)
	proc.Stdin = stdin
	proc.Stdout = cmd.Stdout
	proc.Stderr = cmd.Stderr
	proc.WaitDelay = time.Second
	proc.ExtraFiles = fds.Files

	console, err := net.FileConn(consoleHost)
	if err != nil {
		return err
	}
	defer closeOnError(console)

	control, err := net.FileConn(controlHost)
	if err != nil {
		return err
	}
	defer closeOnError(control)

	if err := proc.Start(); err != nil {
		return err
	}

	cmd.tasks.Go(func() error {
		defer console.Close()

		_, err = io.Copy(&cmd.console, console)
		return err
	})

	results := make(chan *execResult, 1)
	cmd.tasks.Go(func() error {
		defer control.Close()

		enc := json.NewEncoder(control)
		if err := enc.Encode(&execCmd); err != nil {
			return err
		}

		var result execResult
		dec := json.NewDecoder(control)
		if err := dec.Decode(&result); err != nil {
			return fmt.Errorf("decode execution result: %w", err)
		}

		results <- &result
		return nil
	})

	cmd.cmd = proc
	cmd.results = results
	return nil
}

func (cmd *command) Wait() error {
	defer cmd.fakeStdin.Close()

	if err := cmd.cmd.Wait(); err != nil {
		return fmt.Errorf("qemu: %w", err)
	}

	if err := cmd.tasks.Wait(); err != nil {
		if cmd.Stderr != nil {
			_, _ = io.Copy(cmd.Stderr, &cmd.console)
		}
		return err
	}

	result := <-cmd.results
	if result.Error != "" {
		return fmt.Errorf("guest: %s", result.Error)
	}

	return nil
}

type execCommand struct {
	Path      string
	Args      []string
	Dir       string
	Uid, Gid  int
	Env       []string
	MountTags map[string]string // map[tag]path
}

type execResult struct {
	Error string
}

type initWithArgs struct {
	path string
	args []string
}

func (i initWithArgs) Cmdline() []string {
	return nil
}

func (i initWithArgs) KArgs() []string {
	kargs := []string{"init=" + i.path, "--"}
	for _, arg := range i.args {
		if arg == "" {
			kargs = append(kargs, `""`)
		} else {
			kargs = append(kargs, arg)
		}
	}
	return kargs
}

type fdSet string

// fdSets manages fdsets.
//
// Assumes that files is passed in exec.Cmd.ExtraFiles.
type fdSets struct {
	Files []*os.File
}

// addFile a fd backed chardev.
//
// Returns the chardev id allocated for the file.
func (cds *fdSets) addFile(f *os.File) fdSet {
	const idFmt = "/dev/fdset/%d"

	for i, file := range cds.Files {
		if f == file {
			return fdSet(fmt.Sprintf(idFmt, i))
		}
	}

	id := fdSet(fmt.Sprintf(idFmt, len(cds.Files)))
	cds.Files = append(cds.Files, f)
	return id
}

func (cds *fdSets) Cmdline() []string {
	const execFirstExtraFd = 3

	var args []string
	for i := range cds.Files {
		fd := execFirstExtraFd + i
		args = append(args,
			"-add-fd", fmt.Sprintf("fd=%d,set=%d", fd, i),
		)
	}
	return args
}

func (*fdSets) KArgs() []string { return nil }

type chardev string

// chardevs manages character devices.
type chardevs struct {
	Pipes []fdSet
}

func (cds *chardevs) addFdSet(fds fdSet) chardev {
	id := chardev(fmt.Sprintf("cd-%d", len(cds.Pipes)))
	cds.Pipes = append(cds.Pipes, fds)
	return id
}

func (cds *chardevs) Cmdline() []string {
	mux := make(map[fdSet]int)
	for _, fds := range cds.Pipes {
		mux[fds]++
	}

	var args []string
	for i, fds := range cds.Pipes {
		id := chardev(fmt.Sprintf("cd-%d", i))

		arg := fmt.Sprintf("pipe,id=%s,path=%s", id, fds)
		if mux[fds] > 1 {
			arg += ",mux=on"
		}

		args = append(args, "-chardev", arg)
	}
	return args
}

func (*chardevs) KArgs() []string { return nil }

// A "simple" serial port using a character device.
//
// Probably more portable than virtio-serial, but doesn't allow naming.
type serialPorts struct {
	Chardevs []chardev
}

func (ports *serialPorts) add(cd chardev) string {
	pattern := "ttyS%d"
	if runtime.GOARCH == "arm64" {
		pattern = "ttyAMA%d"
	}

	port := fmt.Sprintf(pattern, len(ports.Chardevs))
	ports.Chardevs = append(ports.Chardevs, cd)
	return port
}

func (ports *serialPorts) Cmdline() []string {
	var args []string
	for _, chardev := range ports.Chardevs {
		args = append(args, "-serial", fmt.Sprintf("chardev:%s", chardev))
	}
	return args
}

func (*serialPorts) KArgs() []string { return nil }

type virtioSerialPorts struct {
	// A map of character devices to serial port names.
	//
	// Inside the VM, port names can be accessed via /sys/class/virtio-ports.
	Chardevs map[chardev]string
}

func (vios *virtioSerialPorts) Cmdline() []string {
	if len(vios.Chardevs) == 0 {
		return nil
	}

	args := []string{
		// There seems to be an off by one error with max_ports.
		"-device", fmt.Sprintf("virtio-serial,max_ports=%d", len(vios.Chardevs)+1),
	}
	for dev, name := range vios.Chardevs {
		args = append(args,
			"-device", fmt.Sprintf("virtserialport,chardev=%s,name=%s", dev, name),
		)
	}
	return args
}

func (*virtioSerialPorts) KArgs() []string { return nil }

// Force the root fs to be read-only.
type readOnlyRootfs struct{}

func (readOnlyRootfs) Cmdline() []string {
	return nil
}

func (readOnlyRootfs) KArgs() []string {
	return []string{"ro"}
}

// Make qemu exit on panic instead of pausing.
type exitOnPanic struct{}

func (exitOnPanic) Cmdline() []string {
	return []string{"-no-reboot"}
}

func (exitOnPanic) KArgs() []string {
	return []string{"panic=-1"}
}

type consoleOnSerialPort struct {
	// Linux name of the serial port, e.g. ttyS0.
	Port string
}

func (consoleOnSerialPort) Cmdline() []string { return nil }

func (cs consoleOnSerialPort) KArgs() []string {
	return []string{
		fmt.Sprintf("console=%s,115200", cs.Port),
	}
}

type earlyprintkOnSerialPort struct {
	Port string
}

func (earlyprintkOnSerialPort) Cmdline() []string { return nil }

func (epk earlyprintkOnSerialPort) KArgs() []string {
	return []string{
		fmt.Sprintf("earlyprintk=serial,%s,115200", epk.Port),
	}
}

type earlycon struct {
}

func (earlycon) Cmdline() []string { return nil }

func (epk earlycon) KArgs() []string {
	return []string{
		"earlycon=pl011,0x9000000",
	}
}

// Disable PS/2 protocol probing to speed up booting.
type disablePS2Probing struct{}

func (disablePS2Probing) Cmdline() []string {
	return nil
}

func (disablePS2Probing) KArgs() []string {
	return []string{"psmouse.proto=exps"}
}

// Disable RAID autodetection to speed up booting.
type disableRaidAutodetect struct{}

func (disableRaidAutodetect) Cmdline() []string {
	return nil
}

func (disableRaidAutodetect) KArgs() []string {
	return []string{"raid=noautodetect"}
}

type enableGDBServer struct{}

func (enableGDBServer) Cmdline() []string {
	return []string{"-s", "-S"}
}

func (enableGDBServer) KArgs() []string {
	return nil
}

type fsdev string

type p9Root struct {
	Path string
}

func (p9r *p9Root) Cmdline() []string {
	return []string{
		// Need security_model=none due to https://gitlab.com/qemu-project/qemu/-/issues/173
		"-fsdev", fmt.Sprintf("local,id=rootdrv,path=%s,readonly=on,security_model=none,multidevs=remap", p9r.Path),
		"-device", "virtio-9p-pci,fsdev=rootdrv,mount_tag=/dev/root",
	}
}

func (*p9Root) KArgs() []string {
	return []string{
		"root=/dev/root",
		"rootfstype=9p",
		"rootflags=trans=virtio,version=9p2000.L",
	}
}

type p9SharedDirectory struct {
	ID       fsdev
	Tag      string
	Path     string
	ReadOnly bool
}

func (p9sd *p9SharedDirectory) Cmdline() []string {
	return []string{
		// Need security_model=none due to https://gitlab.com/qemu-project/qemu/-/issues/173
		"-fsdev", fmt.Sprintf("local,id=%s,path=%s,readonly=%t,security_model=none,multidevs=remap", p9sd.ID, p9sd.Path, p9sd.ReadOnly),
		"-device", fmt.Sprintf("virtio-9p-pci,fsdev=%s,mount_tag=%s", p9sd.ID, p9sd.Tag),
	}
}

func (*p9SharedDirectory) KArgs() []string {
	return nil
}
