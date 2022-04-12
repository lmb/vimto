package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"

	"github.com/u-root/u-root/pkg/qemu"
)

// command is a binary to be executed under a different kernel.
//
// Mirrors exec.Cmd.
type command struct {
	Kernel string
	Path   string
	// Arguments passed to the binary at Path. Contrary to exec.Cmd doesn't
	// contain Path in Args[0].
	Args        []string
	Console     *os.File
	SerialPorts map[string]*os.File
}

func execInVM(ctx context.Context, cmd *command) (*exec.Cmd, error) {
	// TODO: Cache the call.
	qemuPath, err := exec.LookPath("qemu-system-x86_64")
	if err != nil {
		return nil, err
	}

	chardevs := &fdChardevs{}
	ports := &virtioSerialPorts{make(map[string]string)}
	devices := []qemu.Device{
		qemu.ArbitraryArgs{
			"-enable-kvm",
			"-cpu", "host",
			"-parallel", "none", // TODO: Needed?
			"-net", "none",
			"-vga", "none",
			"-display", "none",
			"-serial", "none",
			"-monitor", "none",
			"-m", "768", // TODO: Configurable
		},
		qemu.VirtioRandom{},
		readOnlyRootfs{},
		exitOnPanic{},
		disablePS2Probing{},
		disableRaidAutodetect{},
		qemu.P9Directory{
			// TODO: Should be read only?
			Dir:  "/",
			Boot: true,
		},
		chardevs,
		ports,
	}

	if cmd.Console != nil {
		devices = append(devices,
			&serialPort{chardevs.add(cmd.Console)},
			consoleOnFirstSerialPort{},
		)
	}

	for name, port := range cmd.SerialPorts {
		ports.Chardevs[chardevs.add(port)] = name
	}

	// init has to go last since we stop processing of KArgs after.
	devices = append(devices, initWithArgs{
		cmd.Path,
		cmd.Args,
	})

	qemuOpts := qemu.Options{
		QEMUPath: qemuPath,
		Kernel:   cmd.Kernel,
		Devices:  devices,
	}

	qemuArgs, err := qemuOpts.Cmdline()
	if err != nil {
		return nil, err
	}

	fmt.Println(qemuArgs)

	proc := &exec.Cmd{
		Path:       qemuArgs[0],
		Args:       qemuArgs,
		Stderr:     os.Stderr,
		ExtraFiles: chardevs.Files,
	}

	if err := proc.Start(); err != nil {
		return nil, err
	}

	go func() {
		<-ctx.Done()
		proc.Process.Kill()
	}()

	return proc, nil
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

// fdChardevs adds files as a character device.
//
// Assumes that files is passed in exec.Cmd.ExtraFiles.
type fdChardevs struct {
	Files []*os.File
	mux   map[*os.File]bool
}

// add a fd backed chardev.
//
// Returns the chardev id allocated for the file.
func (fds *fdChardevs) add(f *os.File) string {
	for i, file := range fds.Files {
		if f == file {
			if fds.mux == nil {
				fds.mux = make(map[*os.File]bool)
			}

			fds.mux[f] = true
			return fmt.Sprintf("cd-%d", i)
		}
	}

	id := fmt.Sprintf("cd-%d", len(fds.Files))
	fds.Files = append(fds.Files, f)
	return id
}

func (fds *fdChardevs) Cmdline() []string {
	const execFirstExtraFd = 3

	var args []string
	for i, file := range fds.Files {
		fd := execFirstExtraFd + i
		id := fmt.Sprintf("cd-%d", i)

		var extraOpts string
		if fds.mux[file] {
			extraOpts += ",mux=on"
		}

		args = append(args,
			"-add-fd", fmt.Sprintf("fd=%d,set=%d", fd, fd),
			"-chardev", fmt.Sprintf("pipe,id=%s,path=/dev/fdset/%d%s", id, fd, extraOpts),
		)
	}
	return args
}

func (fds *fdChardevs) KArgs() []string { return nil }

// A "simple" serial port using a character device.
//
// Probably more portable than virtio-serial, but doesn't allow naming.
type serialPort struct {
	Chardev string
}

func (fdser *serialPort) Cmdline() []string {
	return []string{
		"-serial", "chardev:" + fdser.Chardev,
	}
}

func (*serialPort) KArgs() []string { return nil }

type virtioSerialPorts struct {
	// A map of character devices to serial port names.
	//
	// Inside the VM, port names can be accessed via /sys/class/virtio-ports.
	Chardevs map[string]string
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

type consoleOnFirstSerialPort struct{}

func (consoleOnFirstSerialPort) Cmdline() []string { return nil }

func (consoleOnFirstSerialPort) KArgs() []string {
	return []string{
		"earlyprintk=serial,ttyS0,115200",
		"console=ttyS0",
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
