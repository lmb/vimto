package main

import (
	"encoding/gob"
	"fmt"
	"io"
	"time"

	"github.com/kballard/go-shellquote"
	"golang.org/x/sys/unix"
)

func init() {
	gob.Register((*guestExitError)(nil))
	gob.Register((*genericGuestError)(nil))
}

// Types exchanged between the host and the guest init.

type execCommand struct {
	Path            string
	Args            []string
	Dir             string
	Uid, Gid        int
	Env             []string
	Sysctls         []sysctl
	Rlimits         map[int]unix.Rlimit
	Setup, Teardown []configCommand
	MountTags       map[string]string // map[tag]path
}

type sysctl struct {
	Name  string
	Value string
}

type configCommand []string

func (cc *configCommand) UnmarshalText(text []byte) error {
	words, err := shellquote.Split(string(text))
	if err != nil {
		return err
	}

	*cc = configCommand(words)
	return nil
}

func (cc *configCommand) MarshalText() ([]byte, error) {
	return []byte(shellquote.Join(*cc...)), nil
}

type guestExitError struct {
	ExitCode int
}

func (gee *guestExitError) Error() string {
	return fmt.Sprintf("guest: exit %d", gee.ExitCode)
}

type genericGuestError struct {
	Message string
}

func (gge *genericGuestError) Error() string {
	return fmt.Sprintf("guest: %s", gge.Message)
}

type conn interface {
	io.Reader
	io.Writer
	io.Closer
	SetReadDeadline(time.Time) error
	SetWriteDeadline(time.Time) error
}

type rpc struct {
	conn conn
	enc  *gob.Encoder
	dec  *gob.Decoder
}

func newRPC(conn conn) *rpc {
	return &rpc{
		conn,
		gob.NewEncoder(conn),
		gob.NewDecoder(conn),
	}
}

func (r *rpc) Close() error {
	return r.conn.Close()
}

func (r *rpc) Read(v any, deadline time.Time) error {
	if err := r.conn.SetReadDeadline(deadline); err != nil {
		return err
	}

	return r.dec.Decode(v)
}

func (r *rpc) Write(v any, deadline time.Time) error {
	if err := r.conn.SetWriteDeadline(deadline); err != nil {
		return err
	}

	return r.enc.Encode(v)
}
