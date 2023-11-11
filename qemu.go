package main

import (
	"io"
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
	Args   []string
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
}

func execInVM(cmd *command) (*exec.Cmd, error) {
	// TODO: Cache the call.
	qemuPath, err := exec.LookPath("qemu-system-x86_64")
	if err != nil {
		return nil, err
	}

	qemuOpts := qemu.Options{
		QEMUPath: qemuPath,
		Kernel:   cmd.Kernel,
		Devices: []qemu.Device{
			qemu.ArbitraryArgs{
				"-enable-kvm",
				"-cpu", "host",
				"-parallel", "none", // TODO: Needed?
				"-net", "none",
				"-vga", "none",
				"-display", "none",
				// "-serial", "none",
				"-monitor", "none",
				"-m", "768", // TODO: Configurable
			},
			qemu.VirtioRandom{},
			readOnlyRootfs{},
			exitOnPanic{},
			// useStdioAsFirstSerial{},
			disablePS2Probing{},
			disableRaidAutodetect{},
			qemu.P9Directory{
				// TODO: Should be read only?
				Dir:  "/",
				Boot: true,
			},
			initWithArgs{
				cmd.Path,
				cmd.Args,
			},
		},
		KernelArgs: "earlyprintk=serial,ttyS0,115200 console=ttyS0",
	}

	qemuArgs, err := qemuOpts.Cmdline()
	if err != nil {
		return nil, err
	}

	proc := &exec.Cmd{
		Path:  qemuArgs[0],
		Args:  qemuArgs,
		Stdin: cmd.Stdin,
		// TODO: Stdout, Stderr should go via separate (?) serial ports
		Stdout: cmd.Stdout,
		Stderr: cmd.Stderr,
	}

	if err := proc.Start(); err != nil {
		return nil, err
	}

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

type useStdioAsFirstSerial struct{}

func (useStdioAsFirstSerial) Cmdline() []string {
	return []string{
		"-echr", "1",
		"-serial", "none",
		"-chardev", "stdio,id=console,signal=off,mux=on",
		"-serial", "chardev:console",
	}
}

func (useStdioAsFirstSerial) KArgs() []string {
	return nil
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
