package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/c35s/hype/kvm"
	"github.com/c35s/hype/os/linux"
	"github.com/c35s/hype/virtio"
	"github.com/c35s/hype/vmm"
	"github.com/docker/go-units"
	"golang.org/x/sync/errgroup"
)

type hype struct {
	cmd   *command
	vm    *vmm.VM
	ncpus int
	group *errgroup.Group
}

func newHypeVMM(cmd *command) (*hype, error) {
	ncpus, err := strconv.ParseInt(cmd.SMP, 10, 32)
	if err != nil {
		return nil, fmt.Errorf("parse smp: %w", err)
	}

	memory, err := units.FromHumanSize(cmd.Memory)
	if err != nil {
		return nil, fmt.Errorf("parse memory: %w", err)
	}

	pageSize := int64(os.Getpagesize())
	memory = (memory + pageSize - 1) / pageSize * pageSize

	init, err := findExecutable()
	if err != nil {
		return nil, err
	}

	params := extractKArgs(
		readOnlyRootfs{},
		exitOnPanic{},
		disablePS2Probing{},
		disableRaidAutodetect{},
		&p9Root{"/"},
		consoleOnSerialPort{"hvc0"},
		earlyprintkXen{},
		initWithArgs{
			init,
			[]string{},
		},
	)
	// params += "dyndbg=\"file drivers/virtio/* +p; file net/9p/* +p; file drivers/pci/* +p\""

	kernel, err := os.ReadFile(cmd.Kernel)
	if err != nil {
		return nil, err
	}

	cfg := vmm.Config{
		MemSize: int(memory),

		Devices: []virtio.DeviceConfig{
			&virtio.ConsoleDevice{
				In:  os.Stdin,
				Out: os.Stdout,
			},
			&P9FSDevice{
				Tag:  "/dev/root",
				Root: "/",
			},
		},

		Loader: &linux.Loader{
			Kernel:  kernel,
			Cmdline: params,
		},
	}

	fmt.Println("params", params)

	vm, err := vmm.New(cfg)
	if err != nil {
		panic(err)
	}

	return &hype{cmd, vm, int(ncpus), nil}, nil
}

func (vmm *hype) Start(ctx context.Context) error {
	if vmm.group != nil {
		return errors.New("already started")
	}

	vmm.group, ctx = errgroup.WithContext(ctx)

	// vmm.group.Go(func() error {
	// 	// TODO: Serial should take a context.
	// 	go closeWhenCancelled(ctx, os.Stdin)

	// 	serial := vmm.vm.GetSerial()
	// 	return serial.Start(*bufio.NewReader(os.Stdin), func() {}, vmm.machine.InjectSerialIRQ)
	// })

	// vmm.group.Go(func() error {
	// 	return vmm.p9.Process(ctx)
	// })

	if vmm.cmd.GDB != "" {
		if vmm.ncpus != 1 {
			return fmt.Errorf("gdb stub only supports a single cpu")
		}

		ln, err := (&net.ListenConfig{}).Listen(ctx, "tcp", vmm.cmd.GDB)
		if err != nil {
			return fmt.Errorf("listen gdb stub: %w", err)
		}

		vmm.group.Go(func() error {
			stub := newGDBStub(ctx, &hypeGdbTarget{vmm.vm})
			return stub.Serve(ln)
		})
	} else {
		vmm.group.Go(func() error {
			return vmm.vm.Run(ctx)
		})
	}

	return nil
}

func (vmm *hype) Wait() error {
	return vmm.group.Wait()
}

type hypeGdbTarget struct {
	*vmm.VM
}

func (t *hypeGdbTarget) Run(ctx context.Context) error {
	err := t.VM.Run(ctx)
	if errors.Is(err, vmm.ErrDebug) {
		return nil
	}
	return err
}

func (t *hypeGdbTarget) SingleStep(singleStep bool) error {
	return t.VM.VCPUs()[0].SingleStep(singleStep)
}

func (t *hypeGdbTarget) AddBreakpoint(vaddr uint64) error {
	return t.VM.VCPUs()[0].AddBreakpoint(vaddr)
}

func (t *hypeGdbTarget) RemoveBreakpoint(vaddr uint64) error {
	return t.VM.VCPUs()[0].RemoveBreakpoint(vaddr)
}

func (t *hypeGdbTarget) ReadRegisters() (*gdbAMD64Registers, error) {
	var kregs kvm.Regs
	err := t.VM.VCPUs()[0].Do(func(vcpu *kvm.VCPU, state *kvm.VCPUState) error {
		return kvm.GetRegs(vcpu, &kregs)
	})
	if err != nil {
		return nil, fmt.Errorf("get registers: %w", err)
	}

	regs := &gdbAMD64Registers{
		// General purpose registers
		RAX: kregs.RAX,
		RBX: kregs.RBX,
		RCX: kregs.RCX,
		RDX: kregs.RDX,
		RSI: kregs.RSI,
		RDI: kregs.RDI,
		RBP: kregs.RBP,
		RSP: kregs.RSP,

		// Extended registers
		R8:  kregs.R8,
		R9:  kregs.R9,
		R10: kregs.R10,
		R11: kregs.R11,
		R12: kregs.R12,
		R13: kregs.R13,
		R14: kregs.R14,
		R15: kregs.R15,

		// Program counter and flags
		RIP:    kregs.RIP,
		EFLAGS: uint32(kregs.RFlags),
	}

	return regs, nil
}

func (t *hypeGdbTarget) WriteRegisters(regs *gdbAMD64Registers) error {
	return t.VM.VCPUs()[0].Do(func(vcpu *kvm.VCPU, state *kvm.VCPUState) error {
		var kregs kvm.Regs
		if err := kvm.GetRegs(vcpu, &kregs); err != nil {
			return fmt.Errorf("get registers: %w", err)
		}

		// Update registers while preserving any KVM-specific fields
		kregs.RAX = regs.RAX
		kregs.RBX = regs.RBX
		kregs.RCX = regs.RCX
		kregs.RDX = regs.RDX
		kregs.RSI = regs.RSI
		kregs.RDI = regs.RDI
		kregs.RBP = regs.RBP
		kregs.RSP = regs.RSP
		kregs.R8 = regs.R8
		kregs.R9 = regs.R9
		kregs.R10 = regs.R10
		kregs.R11 = regs.R11
		kregs.R12 = regs.R12
		kregs.R13 = regs.R13
		kregs.R14 = regs.R14
		kregs.R15 = regs.R15
		kregs.RIP = regs.RIP
		kregs.RFlags = uint64(regs.EFLAGS)

		if err := kvm.SetRegs(vcpu, &kregs); err != nil {
			return fmt.Errorf("set registers: %w", err)
		}

		return nil
	})

}

func (t *hypeGdbTarget) ReadMemory(vaddr uint64, buf []byte) error {
	paddr, err := t.VM.VCPUs()[0].Translate(vaddr)
	if err != nil {
		return err
	}
	return t.VM.ReadMemory(buf, paddr)
}

func (t *hypeGdbTarget) WriteMemory(vaddr uint64, buf []byte) error {
	paddr, err := t.VM.VCPUs()[0].Translate(vaddr)
	if err != nil {
		return err
	}
	return t.VM.WriteMemory(buf, paddr)
}

func extractKArgs(devices ...device) string {
	var args []string
	for _, dev := range devices {
		args = append(args, dev.KArgs()...)
	}
	// TODO: Shell quoting?
	return strings.Join(args, " ")
}
