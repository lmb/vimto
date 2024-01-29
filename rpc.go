package main

import (
	"encoding/gob"
	"io"
	"time"
)

func init() {
	gob.Register((*guestExitError)(nil))
	gob.Register((*genericGuestError)(nil))
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
