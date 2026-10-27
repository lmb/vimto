package guest

import (
	"encoding/gob"
	"fmt"
	"io"
	"time"

	"github.com/kballard/go-shellquote"
	"golang.org/x/sys/unix"
)

func init() {
	gob.Register((*ExitError)(nil))
	gob.Register((*GenericError)(nil))
}

// Types exchanged between the host and the guest init over the control port.

type ExecCommand struct {
	Path            string
	Args            []string
	Dir             string
	Uid, Gid        int
	Env             []string
	Sysctls         []Sysctl
	Rlimits         map[int]unix.Rlimit
	Setup, Teardown []Command
	MountTags       map[string]string // map[tag]path
}

type Sysctl struct {
	Name  string
	Value string
}

type Command []string

func (cc *Command) UnmarshalText(text []byte) error {
	words, err := shellquote.Split(string(text))
	if err != nil {
		return err
	}

	*cc = Command(words)
	return nil
}

func (cc *Command) MarshalText() ([]byte, error) {
	return []byte(shellquote.Join(*cc...)), nil
}

type ExitError struct {
	ExitCode int
}

func (gee *ExitError) Error() string {
	return fmt.Sprintf("guest: exit %d", gee.ExitCode)
}

type GenericError struct {
	Message string
}

func (gge *GenericError) Error() string {
	return fmt.Sprintf("guest: %s", gge.Message)
}

type conn interface {
	io.Reader
	io.Writer
	io.Closer
	SetReadDeadline(time.Time) error
	SetWriteDeadline(time.Time) error
}

type RPC struct {
	conn conn
	enc  *gob.Encoder
	dec  *gob.Decoder
}

func NewRPC(conn conn) *RPC {
	return &RPC{
		conn,
		gob.NewEncoder(conn),
		gob.NewDecoder(conn),
	}
}

func (r *RPC) Close() error {
	return r.conn.Close()
}

func (r *RPC) Read(v any, deadline time.Time) error {
	if err := r.conn.SetReadDeadline(deadline); err != nil {
		return err
	}

	return r.dec.Decode(v)
}

func (r *RPC) Write(v any, deadline time.Time) error {
	if err := r.conn.SetWriteDeadline(deadline); err != nil {
		return err
	}

	return r.enc.Encode(v)
}
