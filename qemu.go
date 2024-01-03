package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"time"

	"github.com/u-root/u-root/pkg/qemu"
	"golang.org/x/sys/unix"
)

// command is a binary to be executed under a different kernel.
//
// Mirrors exec.Cmd.
type command struct {
	Kernel string
	// Arguments spassed to the init process. Contrary to exec.Cmd doesn't
	// contain Init in Args[0].
	Args        []string
	Stdin       io.Reader
	Stdout      io.Writer
	Stderr      io.Writer
	SerialPorts map[string]*os.File

	cmd     *exec.Cmd
	control net.Conn
}

func (cmd *command) execInVM(ctx context.Context) (err error) {
	if cmd.cmd != nil {
		return errors.New("qemu: already started")
	}

	// TODO: Cache the call.
	qemuPath, err := exec.LookPath("qemu-system-x86_64")
	if err != nil {
		return err
	}

	args := qemu.ArbitraryArgs{
		"-enable-kvm",
		"-cpu", "host",
		"-parallel", "none", // TODO: Needed?
		"-net", "none",
		"-vga", "none",
		"-display", "none",
		"-serial", "none",
		"-monitor", "none",
		"-no-reboot",
		"-m", "768", // TODO: Configurable
		"-chardev", "stdio,id=stdio",
	}
	cds := &chardevs{}
	ports := &serialPorts{}
	virtioPorts := &virtioSerialPorts{make(map[chardev]string)}

	// The first serial port is always console, earlyprintk and SeaBIOS (on amd64)
	// output. SeaBIOS seems to always write to the first serial port.
	consoleHost, consoleGuest, err := unixSocketpair()
	if err != nil {
		return err
	}
	defer consoleHost.Close()
	defer consoleGuest.Close()

	consolePort := ports.add(cds.addFile(consoleGuest))

	// The second serial port is used for communication between host and guest.
	controlHost, controlGuest, err := unixSocketpair()
	if err != nil {
		return err
	}
	defer controlHost.Close()
	defer controlGuest.Close()

	controlPort := ports.add(cds.addFile(controlGuest))

	// The third serial port is always stdio. The init process executes
	// subprocesses with this port as stdin, stdout and stderr.
	stdioPort := ports.add(chardev("stdio"))

	devices := []qemu.Device{
		args,
		qemu.VirtioRandom{},
		readOnlyRootfs{},
		exitOnPanic{},
		disablePS2Probing{},
		disableRaidAutodetect{},
		qemu.P9Directory{
			Dir:  "/",
			Boot: true,
		},
		// enableGDBServer{},
		cds,
		ports,
		virtioPorts,
		consoleOnSerialPort{consolePort},
	}

	for name, port := range cmd.SerialPorts {
		virtioPorts.Chardevs[cds.addFile(port)] = name
	}

	init, err := findExecutable()
	if err != nil {
		return err
	}

	// init has to go last since we stop processing of KArgs after.
	devices = append(devices, initWithArgs{
		init,
		append([]string{"/dev/" + stdioPort, "/dev/" + controlPort}, cmd.Args...),
	})

	qemuOpts := qemu.Options{
		QEMUPath: qemuPath,
		Kernel:   cmd.Kernel,
		Devices:  devices,
	}

	qemuArgs, err := qemuOpts.Cmdline()
	if err != nil {
		return err
	}

	proc := exec.CommandContext(ctx, qemuArgs[0], qemuArgs[1:]...)
	proc.Stdin = cmd.Stdin
	proc.Stdout = cmd.Stdout
	// TODO: qemu writes to stderr, which is not what we want.
	proc.Stderr = cmd.Stderr
	fmt.Printf("%q\n", proc.Args[1:])
	proc.ExtraFiles = cds.Files

	if err := proc.Start(); err != nil {
		return err
	}

	control, err := net.FileConn(controlHost)
	if err != nil {
		return err
	}

	cmd.cmd = proc
	cmd.control = control
	return err
}

func (cmd *command) Wait() error {
	defer cmd.control.Close()

	if err := cmd.cmd.Wait(); err != nil {
		// TODO: Include stderr output if any.
		return fmt.Errorf("qemu: %w", err)
	}

	ctrl := cmd.control
	if err := ctrl.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		return err
	}

	dec := json.NewDecoder(ctrl)
	var result execResult
	if err := dec.Decode(&result); err != nil {
		// TODO: Handle timeout specifically?
		return fmt.Errorf("decode execution result: %w", err)
	}

	if result.ExitCode != 0 {
		if result.ExitCode == -1 && result.Error != "" {
			return fmt.Errorf("guest process: %s", result.Error)
		}
		return fmt.Errorf("guest process exited with %d", result.ExitCode)
	}

	return nil
}

type execResult struct {
	ExitCode int
	Error    string
}

func executeTest(args []string) error {
	if len(args) < 3 {
		return fmt.Errorf("missing arguments")
	}

	pid1, err := minimalInit(realSyscaller{}, args[0])
	if err != nil {
		return err
	}

	control, err := os.OpenFile(args[1], os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	defer control.Close()

	cmd := exec.Command(args[2], args[3:]...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	var result execResult
	err = cmd.Run()
	if err != nil {
		result.ExitCode = -1
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			result.ExitCode = exitErr.ExitCode()
		} else {
			result.Error = err.Error()
		}
	}

	enc := json.NewEncoder(control)
	if err := enc.Encode(&result); err != nil {
		return err
	}

	return pid1.Shutdown()
}

type initWithArgs struct {
	path string
	args []string
}

func (i initWithArgs) Cmdline() []string {
	return nil
}

func (i initWithArgs) KArgs() []string {
	return append([]string{"init=" + i.path, "--"}, i.args...)
}

type chardev string

// chardevs adds files as a character device.
//
// Assumes that files is passed in exec.Cmd.ExtraFiles.
type chardevs struct {
	Files []*os.File
	mux   map[*os.File]bool
}

// addFile a fd backed chardev.
//
// Returns the chardev id allocated for the file.
func (cds *chardevs) addFile(f *os.File) chardev {
	for i, file := range cds.Files {
		if f == file {
			if cds.mux == nil {
				cds.mux = make(map[*os.File]bool)
			}

			cds.mux[f] = true
			return chardev(fmt.Sprintf("cd-%d", i))
		}
	}

	id := fmt.Sprintf("cd-%d", len(cds.Files))
	cds.Files = append(cds.Files, f)
	return chardev(id)
}

func (cds *chardevs) Cmdline() []string {
	const execFirstExtraFd = 3

	var args []string
	for i, file := range cds.Files {
		fd := execFirstExtraFd + i
		id := fmt.Sprintf("cd-%d", i)

		var extraOpts string
		if cds.mux[file] {
			extraOpts += ",mux=on"
		}

		args = append(args,
			"-add-fd", fmt.Sprintf("fd=%d,set=%d", fd, fd),
			"-chardev", fmt.Sprintf("pipe,id=%s,path=/dev/fdset/%d%s", id, fd, extraOpts),
		)
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
	port := fmt.Sprintf("ttyS%d", len(ports.Chardevs))
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
		fmt.Sprintf("earlyprintk=serial,%s,115200", cs.Port),
		"console=" + cs.Port,
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

func unixSocketpair() (*os.File, *os.File, error) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("create unix socket pair: %w", err)
	}

	return os.NewFile(uintptr(fds[0]), ""), os.NewFile(uintptr(fds[1]), ""), nil
}
