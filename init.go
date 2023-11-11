package main

import (
	"errors"
	"flag"
	"fmt"

	"golang.org/x/sys/unix"
)

type syscaller interface {
	mount(*mountPoint) error
	sync()
	reboot(int) error
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

func minimalInit(sys syscaller, args []string) error {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	if err := fs.Parse(args); errors.Is(err, flag.ErrHelp) {
		return nil
	} else if err != nil {
		return err
	}

	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected argument(s): %q", fs.Args())
	}

	if err := mount(sys, earlyMounts); err != nil {
		return fmt.Errorf("early mount: %w", err)
	}

	sys.sync()
	return sys.reboot(unix.LINUX_REBOOT_CMD_POWER_OFF)
}
