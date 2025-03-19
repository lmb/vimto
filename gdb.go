package main

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync/atomic"

	"golang.org/x/sync/errgroup"
)

type gdbTarget interface {
	SingleStep(toggle bool) error
	AddBreakpoint(addr uint64) error
	RemoveBreakpoint(addr uint64) error
	Run(context.Context) error
	ReadRegisters() (*gdbAMD64Registers, error)
	WriteRegisters(*gdbAMD64Registers) error
	ReadMemory(uint64, []byte) error
	WriteMemory(uint64, []byte) error
}

var errKillCommand = errors.New("killed by client")

type gdbErrorNumber struct {
	error
	number int
}

type gdbStub struct {
	group         *errgroup.Group
	ctx           context.Context
	target        gdbTarget
	wantInterrupt *atomic.Bool
	interrupted   chan struct{}
}

func newGDBStub(ctx context.Context, target gdbTarget) *gdbStub {
	group, ctx := errgroup.WithContext(ctx)
	return &gdbStub{
		group,
		ctx,
		target,
		new(atomic.Bool),
		make(chan struct{}, 1),
	}
}

func (g *gdbStub) Serve(ln net.Listener) error {
	go closeWhenCancelled(g.ctx, ln)

	g.group.Go(func() error {
		defer ln.Close()

		var prevConn net.Conn
		for {
			conn, err := ln.Accept()
			if errors.Is(err, net.ErrClosed) {
				return nil
			} else if err != nil {
				return err
			}
			go closeWhenCancelled(g.ctx, conn)

			if prevConn != nil {
				// Only allow a single client at a time.
				prevConn.Close()
			}
			prevConn = conn

			g.group.Go(func() error {
				defer conn.Close()

				err := g.Handle(conn, conn)
				if errors.Is(err, net.ErrClosed) {
					return nil
				}
				return err
			})
		}
	})

	return g.group.Wait()
}

func (g *gdbStub) Handle(in io.Reader, out io.Writer) error {
	r := bufio.NewReader(in)
	w := bufio.NewWriter(out)
	defer w.Flush()

	cmds := make(chan string, 1)

	g.group.Go(func() error {
		defer close(cmds)

		for {
			cmd, err := gdbReadPacket(r)
			if err != nil {
				return fmt.Errorf("read command: %w", err)
			}

			select {
			case cmds <- cmd:
			case <-g.ctx.Done():
				return g.ctx.Err()
			}
		}
	})

	for {
		var cmd string
		var ok bool
		select {
		case cmd, ok = <-cmds:
			if !ok {
				return nil
			}
		case <-g.ctx.Done():
			return g.ctx.Err()
		}

		if err := w.WriteByte('+'); err != nil {
			return fmt.Errorf("failed to ack: %w", err)
		}

		if err := w.Flush(); err != nil {
			return fmt.Errorf("flush ack: %w", err)
		}

		response, err := g.handleCommand(cmd, cmds)
		if err != nil {
			if errors.Is(err, errKillCommand) {
				return nil
			}
			fmt.Println("error", err.Error())

			response = "E." + err.Error()
			var errNo *gdbErrorNumber
			if errors.As(err, &errNo) {
				response = fmt.Sprintf("E%02x", errNo.number)
			}
		}

		if err := gdbWritePacket(w, response); err != nil {
			return err
		}
	}
}

func (g *gdbStub) handleCommand(cmd string, cmds <-chan string) (string, error) {
	const gdbRegisterSize = (16*8 + 8 + 4 + 6*4) + (8*10 + 8*4) + (16*16 + 4) + 8

	// Interruption messages
	// See https://chromium.googlesource.com/native_client/nacl-gdb/+/refs/heads/main/include/gdb/signals.def
	const (
		sigInt  = "S02"
		sigTrap = "S05"
	)

	switch {
	case cmd == "":
		return "", fmt.Errorf("empty command")

	case cmd == "?":
		return sigTrap, nil

	case cmd == "k":
		return "", errKillCommand

	case cmd == "s":
		if err := g.target.SingleStep(true); err != nil {
			return "", fmt.Errorf("single step: %w", err)
		}
		err := g.target.Run(g.ctx)
		if err != nil {
			return "", fmt.Errorf("single step: %w", err)
		}
		return sigTrap, nil

	case cmd == "c":
		if err := g.target.SingleStep(false); err != nil {
			return "", fmt.Errorf("single step: %w", err)
		}

		ctx, cancel := context.WithCancel(g.ctx)
		defer cancel()

		status := make(chan error, 1)
		go func() {
			status <- g.target.Run(ctx)
		}()

	wait:
		select {
		case cmd, ok := <-cmds:
			if !ok {
				return "", nil // TODO
			}

			if cmd != string(rune(gdbInterruptChar)) {
				return "", fmt.Errorf("invalid interrupt char: %q", cmd)
			}

			cancel()

			goto wait

		case err := <-status:
			if errors.Is(err, context.Canceled) {
				return sigInt, nil
			} else if err == nil {
				return sigTrap, nil
			}
			return "", err

		case <-g.ctx.Done():
			return "", g.ctx.Err()
		}

	case cmd[0] == 'm':
		var vaddr uint64
		var length int
		if n, err := fmt.Sscanf(cmd[1:], "%x,%x", &vaddr, &length); err != nil {
			return "", fmt.Errorf("parse memory read params: %w", err)
		} else if n != 2 {
			return "", fmt.Errorf("truncated params: %q", cmd[1:])
		}

		buf := make([]byte, length)
		if err := g.target.ReadMemory(vaddr, buf); err != nil {
			return "", &gdbErrorNumber{fmt.Errorf("read memory: %w", err), 0x14}
		}

		return hex.EncodeToString(buf), nil

	case cmd[0] == 'M':
		dest, data, ok := strings.Cut(cmd[1:], ":")
		if !ok {
			return "", fmt.Errorf("memory write without data")
		}

		var vaddr uint64
		var length int
		if _, err := fmt.Sscanf(dest, "%x,%x", &vaddr, &length); err != nil {
			return "", fmt.Errorf("parse memory write address: %w", err)
		}

		buf, err := hex.DecodeString(data)
		if err != nil {
			return "", fmt.Errorf("decode memory write data: %w", err)
		}

		if len(buf) != length {
			return "", fmt.Errorf("got %d bytes of data but length is %d", len(buf), length)
		}

		if err := g.target.WriteMemory(vaddr, buf); err != nil {
			return "", fmt.Errorf("write memory: %w", err)
		}

		return "OK", nil

	case cmd[0] == 'g':
		regs, err := g.target.ReadRegisters()
		if err != nil {
			return "", fmt.Errorf("read registers: %w", err)
		}

		buf, err := binary.Append(make([]byte, 0, gdbRegisterSize), binary.NativeEndian, regs)
		if err != nil {
			return "", fmt.Errorf("encode registers: %w", err)
		}

		padding := cap(buf) - len(buf)
		for range padding {
			buf = append(buf, 'x')
		}

		return hex.EncodeToString(buf), nil

	case cmd[0] == 'G':
		regData, err := hex.DecodeString(cmd[1:])
		if err != nil {
			return "", fmt.Errorf("decode register data: %w", err)
		}

		regs := &gdbAMD64Registers{}
		regSize := binary.Size(regs)
		if len(regData) < regSize {
			return "", fmt.Errorf("register data too short: got %d, want %d", len(regData), regSize)
		}

		if len(regData) > gdbRegisterSize {
			return "", fmt.Errorf("register data too long: got %d, want %d", len(regData), gdbRegisterSize)
		}

		for i := regSize; i < len(regData); i++ {
			if regData[i] != 'x' {
				return "", fmt.Errorf("modification of unsupported register at offset %d", i)
			}
		}

		_, err = binary.Decode(regData[:regSize], binary.NativeEndian, regs)
		if err != nil {
			return "", fmt.Errorf("parse register data: %w", err)
		}

		if err := g.target.WriteRegisters(regs); err != nil {
			return "", fmt.Errorf("write registers: %w", err)
		}

		return "OK", nil

	case cmd[0] == 'Z' || cmd[0] == 'z':
		// Format is Z/z<type>,<addr>,<kind>
		// type: 0 = software breakpoint, 1 = hardware breakpoint, 2 = write watchpoint, 3 = read watchpoint, 4 = access watchpoint
		const (
			typeSW = 0
			typeHW = 1
		)

		var bpType int
		var addr uint64
		var kind int
		if n, err := fmt.Sscanf(cmd[1:], "%d,%x,%x", &bpType, &addr, &kind); err != nil {
			return "", fmt.Errorf("parse breakpoint params: %w", err)
		} else if n != 3 {
			return "", fmt.Errorf("invalid breakpoint command format")
		}

		if bpType != typeSW && bpType != typeHW {
			return "", nil
		}

		if kind != 1 {
			return "", fmt.Errorf("unsupported kind %d", kind)
		}

		// TODO: We map software to hardware breakpoints for simplicity.
		if cmd[0] == 'Z' {
			if err := g.target.AddBreakpoint(addr); err != nil {
				return "", fmt.Errorf("add breakpoint: %w", err)
			}
		} else {
			if err := g.target.RemoveBreakpoint(addr); err != nil {
				return "", fmt.Errorf("remove breakpoint: %w", err)
			}
		}

		return "OK", nil

	default:
		return "", nil
	}
}

// https://chromium.googlesource.com/native_client/nacl-gdb/+/8c22b25422585fdfddb0fe35489c6259319416cd/gdb/features/i386/amd64-linux.c
type gdbAMD64Registers struct {
	// General Purpose Registers
	RAX uint64 // Accumulator, commonly used for function return values
	RBX uint64 // Base register, callee-saved
	RCX uint64 // Counter register, used for loops and string operations
	RDX uint64 // Data register, used for I/O operations
	RSI uint64 // Source Index, used for string operations
	RDI uint64 // Destination Index, used for string operations
	RBP uint64 // Base Pointer, maintains stack frame
	RSP uint64 // Stack Pointer, points to current stack position

	// Extended General Purpose Registers (added in x86_64)
	R8  uint64 // General purpose
	R9  uint64 // General purpose, used for passing parameters in System V ABI
	R10 uint64 // General purpose, used as static chain pointer in System V ABI
	R11 uint64 // General purpose, used as scratch register
	R12 uint64 // General purpose, callee-saved
	R13 uint64 // General purpose, callee-saved
	R14 uint64 // General purpose, callee-saved
	R15 uint64 // General purpose, callee-saved

	// Program Counter and Flags
	RIP    uint64 // Instruction Pointer, points to next instruction
	EFLAGS uint32 // CPU status flags (32-bit register even in 64-bit mode)
}

const gdbInterruptChar = 0x03

func gdbReadPacket(r *bufio.Reader) (string, error) {
	const (
		ack      byte = '+'
		start         = '$'
		end           = '#'
		checksum      = iota
	)

	var packet, csumBytes []byte
	next := ack
read:
	for {
		c, err := r.ReadByte()
		if err != nil {
			return "", err
		}

		switch {
		case next == ack && c == gdbInterruptChar:
			return string(gdbInterruptChar), nil

		case next == ack && c == ack:
			next = start
			continue

		case next == start && c == start:
			next = end
			continue

		case next == end && c == end:
			next = checksum
			continue

		case next == end:
			packet = append(packet, c)
			continue

		case next == checksum:
			csumBytes = append(csumBytes, c)
			if len(csumBytes) == 2 {
				break read
			}
			continue
		}

		return "", fmt.Errorf("expected %v got %v", rune(next), rune(c))
	}

	tmp := make([]byte, 1)
	if _, err := hex.Decode(tmp, csumBytes); err != nil {
		return "", fmt.Errorf("decode checksum: %w", err)
	}

	haveCsum := tmp[0]
	wantCsum := gdbChecksum(packet)
	if wantCsum != haveCsum {
		return "", fmt.Errorf("invalid checksum 0x%x for %q (want 0x%2x)", haveCsum, string(packet), wantCsum)
	}

	return string(packet), nil
}

func gdbWritePacket(w *bufio.Writer, cmd string) error {
	escapedCmd := gdbEscapeCommand(cmd)

	if err := w.WriteByte('$'); err != nil {
		return fmt.Errorf("write start marker: %w", err)
	}

	if _, err := w.WriteString(escapedCmd); err != nil {
		return fmt.Errorf("write command: %w", err)
	}

	if err := w.WriteByte('#'); err != nil {
		return fmt.Errorf("write end marker: %w", err)
	}

	if _, err := fmt.Fprintf(w, "%02x", gdbChecksum(escapedCmd)); err != nil {
		return fmt.Errorf("write checksum: %w", err)
	}

	if err := w.Flush(); err != nil {
		return fmt.Errorf("flush: %w", err)
	}

	return nil
}

func gdbEscapeCommand(cmd string) string {
	buf := make([]byte, 0, len(cmd)*2)

	for i := 0; i < len(cmd); i++ {
		c := cmd[i]
		needsEscape := c == '$' || c == '#' || c == '*' || c == '}' || c > 0x7F

		if needsEscape {
			buf = append(buf, '}')
			buf = append(buf, c^0x20)
		} else {
			buf = append(buf, c)
		}
	}

	return string(buf)
}

func gdbUnescapeCommand(escaped string) (string, error) {
	buf := make([]byte, 0, len(escaped))

	haveEscape := false
	for _, c := range []byte(escaped) {
		if c == '}' {
			haveEscape = true
			continue
		}

		if haveEscape {
			buf = append(buf, c^0x20)
			haveEscape = false
		} else if c == '*' {
			return "", fmt.Errorf("run length encoding is not supported")
		} else {
			buf = append(buf, c)
		}
	}

	if haveEscape {
		return "", fmt.Errorf("truncated escape sequence at end")
	}

	return string(buf), nil
}

func gdbReadResponse(r *bufio.Reader) (string, error) {
	response, err := gdbReadPacket(r)
	if err != nil {
		return "", fmt.Errorf("read response: %w", err)
	}

	// https://sourceware.org/gdb/current/onlinedocs/gdb.html/Standard-Replies.html#Standard-Replies
	switch {
	case strings.HasPrefix("E ", response):
		return "", fmt.Errorf("error code: 0x%s", strings.TrimPrefix("E ", response))
	case strings.HasPrefix("E.", response):
		return "", errors.New(strings.TrimPrefix("E.", response))
	default:
		return response, nil
	}
}

func gdbChecksum[T interface{ ~[]byte | ~string }](data T) (sum byte) {
	for _, d := range []byte(data) {
		sum += d
	}
	return
}

func closeWhenCancelled(ctx context.Context, c io.Closer) {
	<-ctx.Done()
	c.Close()
}
