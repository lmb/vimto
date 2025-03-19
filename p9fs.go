package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"unsafe"

	"github.com/c35s/hype/virtio"
	"github.com/c35s/hype/virtio/virtq"
	"github.com/hugelgupf/p9/fsimpl/templatefs"
	"github.com/hugelgupf/p9/p9"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sys/unix"
)

var _ virtio.DeviceConfig = (*P9FSDevice)(nil)

// P9FSDevice configures a virtio 9P filesystem device.
type P9FSDevice struct {
	// Tag is the name of the share that will be visible to the guest
	Tag string
	// Root is the path to share from the host
	Root string
}

func (cfg P9FSDevice) NewHandler() (virtio.DeviceHandler, error) {
	if len(cfg.Tag) > math.MaxUint16 {
		return nil, errors.New("9P tag is too long")
	}

	root, err := os.OpenRoot(cfg.Root)
	if err != nil {
		return nil, err
	}

	return &p9fsHandler{
		cfg:    cfg,
		server: p9.NewServer(&p9Attacher{root}),
		quit:   make(chan struct{}),
	}, nil
}

var _ virtio.DeviceHandler = (*p9fsHandler)(nil)

type p9fsHandler struct {
	cfg      P9FSDevice
	server   *p9.Server
	quit     chan struct{}
	quitOnce sync.Once
	group    errgroup.Group
}

func (h *p9fsHandler) GetType() virtio.DeviceID {
	return virtio.DeviceID(9)
}

const (
	_VIRTIO_9P_MOUNT_TAG = 1 << iota
)

func (*p9fsHandler) GetFeatures() uint64 {
	return _VIRTIO_9P_MOUNT_TAG
}

func (*p9fsHandler) Ready(negotiatedFeatures uint64) error {
	if negotiatedFeatures&_VIRTIO_9P_MOUNT_TAG == 0 {
		return fmt.Errorf("_VIRTIO_9P_MOUNT_TAG not negotiated")
	}
	return nil
}

func (h *p9fsHandler) QueueReady(num int, q *virtq.Queue, notify <-chan struct{}) error {
	if num != 0 {
		return fmt.Errorf("unknown queue: %d", num)
	}

	h.group.Go(func() error {
		conn := newP9VirtioConn(q, notify, h.quit)
		return h.server.Handle(conn, conn)
	})

	return nil
}

func (h *p9fsHandler) ReadConfig(p []byte, off int) error {
	// Equivalent of struct virtio_9p_config.
	cfg := binary.LittleEndian.AppendUint16(make([]byte, 0, 256), uint16(len(h.cfg.Tag)))
	cfg = append(cfg, []byte(h.cfg.Tag)...)

	if off > len(cfg) {
		return fmt.Errorf("out of bounds read at offset %d", off)
	}

	n := copy(p, cfg[off:])
	if n != len(p) {
		return fmt.Errorf("truncated read")
	}

	return nil
}

func (h *p9fsHandler) Close() error {
	h.quitOnce.Do(func() { close(h.quit) })
	return h.group.Wait()
}

type p9VirtioConn struct {
	queue  *virtq.Queue
	notify <-chan struct{}
	quit   <-chan struct{}

	readBuf        []byte
	writeChain     *virtq.Chain
	writeDesc      int
	writeOff       int
	responseLength int
	bytesWritten   int

	mu       sync.Mutex
	requests map[uint16]*virtq.Chain
}

func newP9VirtioConn(queue *virtq.Queue, notify <-chan struct{}, quit <-chan struct{}) *p9VirtioConn {
	return &p9VirtioConn{
		queue:    queue,
		notify:   notify,
		quit:     quit,
		requests: make(map[uint16]*virtq.Chain),
	}
}

func (c *p9VirtioConn) Close() error {
	return nil
}

func (c *p9VirtioConn) Read(p []byte) (n int, err error) {
	// Read is never called concurrently.
	if len(c.readBuf) == 0 {
		// Wait for the next request.
		select {
		case <-c.quit:
			return 0, io.EOF
		case _, ok := <-c.notify:
			if !ok {
				return 0, io.EOF
			}
		}

		chain, err := c.queue.Next()
		if err != nil {
			return 0, err
		}
		if chain == nil {
			return 0, io.EOF
		}

		desc := chain.Desc[0]
		if !desc.IsRO() {
			return 0, fmt.Errorf("first descriptor is not read only")
		}

		buf, err := chain.Buf(0)
		if err != nil {
			return 0, err
		}

		_, tag, err := decodeP9Header(buf)
		if err != nil {
			return 0, err
		}

		c.mu.Lock()
		c.requests[tag] = chain
		c.mu.Unlock()

		c.readBuf = buf
	}

	// Allow consuming the buffer in multiple calls, because the 9p implementation
	// doesn't read the it in one go.
	n = copy(p, c.readBuf)
	c.readBuf = c.readBuf[n:]
	return n, nil
}

func (c *p9VirtioConn) Write(p []byte) (int, error) {
	// Write is never called concurrently.
	if c.writeChain == nil {
		length, tag, err := decodeP9Header(p)
		if err != nil {
			return 0, err
		}

		c.mu.Lock()
		chain, ok := c.requests[tag]
		delete(c.requests, tag)
		c.mu.Unlock()

		if !ok {
			return 0, fmt.Errorf("no pending request for tag %d", tag)
		}

		c.writeChain = chain
		c.writeDesc = 1
		c.writeOff = 0
		c.responseLength = int(length)
		c.bytesWritten = 0
	}

	var total int
	for len(p) > 0 {
		if c.writeDesc > len(c.writeChain.Desc) {
			return 0, fmt.Errorf("write desc out of bounds")
		}

		if !c.writeChain.Desc[c.writeDesc].IsWO() {
			return 0, fmt.Errorf("descriptor %d is not write only", c.writeDesc)
		}

		buf, err := c.writeChain.Buf(c.writeDesc)
		if err != nil {
			return 0, err
		}

		buf = buf[c.writeOff:]
		n := copy(buf, p)

		p = p[n:]
		total += n
		c.writeOff += n

		if n == len(buf) {
			c.writeDesc++
			c.writeOff = 0
		}
	}

	c.bytesWritten += total
	if c.bytesWritten == c.responseLength {
		err := c.writeChain.Release(c.bytesWritten)
		c.writeChain = nil
		return total, err
	}

	return total, nil
}

func decodeP9Header(message []byte) (length uint32, tag uint16, _ error) {
	if len(message) < 4+1+2 {
		return 0, 0, errors.New("message too short for a tag")
	}

	length = binary.LittleEndian.Uint32(message[0:])
	tag = binary.LittleEndian.Uint16(message[4+1:])

	return length, tag, nil
}

type p9Attacher struct {
	root *os.Root
}

func (a *p9Attacher) Close() error {
	return a.root.Close()
}

// Attach implements p9.Attacher interface
func (a *p9Attacher) Attach() (p9.File, error) {
	return &p9File{root: a.root, path: "."}, nil
}

type p9Statfs struct{}

// StatFS implements p9.File.StatFS.
func (p9Statfs) StatFS() (p9.FSStat, error) {
	return p9.FSStat{
		Type:      0x01021997, /* V9FS_MAGIC */
		BlockSize: 4096,       /* whatever */
	}, nil
}

type p9File struct {
	root *os.Root
	path string

	file *os.File

	templatefs.ReadOnlyFile
	p9Statfs
}

// Open implements p9.File.Open
func (f *p9File) Open(mode p9.OpenFlags) (p9.QID, uint32, error) {
	if f.file != nil {
		return p9.QID{}, 0, os.ErrExist
	}

	if mode.Mode() != p9.ReadOnly {
		return p9.QID{}, 0, unix.EROFS
	}

	file, err := f.root.OpenFile(f.path, mode.OSFlags(), 0666)
	if err != nil {
		return p9.QID{}, 0, err
	}

	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return p9.QID{}, 0, err
	}

	f.file = file
	return qidFromFileInfo(info), 0, nil
}

// Close implements p9.File.Close
func (f *p9File) Close() error {
	if f.file != nil {
		file := f.file
		f.file = nil
		return file.Close()
	}
	return nil
}

// Walk implements p9.File.Walk.
func (f *p9File) WalkGetAttr(names []string) ([]p9.QID, p9.File, p9.AttrMask, p9.Attr, error) {
	if len(names) > 1 {
		return nil, nil, p9.AttrMaskAll, p9.Attr{}, errors.New("not supported")
	}

	path := f.path
	if len(names) > 0 {
		path = filepath.Join(path, names[0])
	}

	switch path {
	case "dev", "sys", "proc":
		// TODO: This doesn't account for symlinks.
		return nil, nil, p9.AttrMaskAll, p9.Attr{}, os.ErrNotExist
	}

	info, err := f.root.Lstat(path)
	if err != nil {
		return nil, nil, p9.AttrMaskAll, p9.Attr{}, err
	}

	qid := qidFromFileInfo(info)
	attr, mask := infoToAttr(info, p9.AttrMaskAll)
	file := &p9File{root: f.root, path: path}

	return []p9.QID{qid}, file, mask, attr, nil
}

// WalkGetAttr implements p9.File.WalkGetAttr.
func (f *p9File) Walk(names []string) ([]p9.QID, p9.File, error) {
	if len(names) == 0 {
		return nil, &p9File{root: f.root, path: f.path}, nil
	}

	qids, file, _, _, err := f.WalkGetAttr(names)
	return qids, file, err
}

// GetAttr implements p9.File.GetAttr.
func (f *p9File) GetAttr(req p9.AttrMask) (p9.QID, p9.AttrMask, p9.Attr, error) {
	info, err := f.root.Lstat(f.path)
	if err != nil {
		return p9.QID{}, p9.AttrMask{}, p9.Attr{}, err
	}

	qid := qidFromFileInfo(info)
	attr, mask := infoToAttr(info, req)
	return qid, mask, attr, nil
}

// Readdir implements p9.File.Readdir.
func (f *p9File) Readdir(offset uint64, count uint32) (p9.Dirents, error) {
	if f.file == nil {
		return nil, os.ErrClosed
	}

	_, err := f.file.Seek(int64(offset), io.SeekStart)
	if err != nil {
		return nil, err
	}

	// TODO: count is actually the number of bytes requested by the client.
	// WTF.
	entries, err := f.file.Readdir(int(count))
	if err != nil && err != io.EOF {
		return nil, err
	}

	dents := make(p9.Dirents, 0, len(entries))
	for _, info := range entries {
		qid := qidFromFileInfo(info)

		dents = append(dents, p9.Dirent{
			QID:    qid,
			Offset: offset + uint64(len(dents)) + 1,
			Type:   qid.Type,
			Name:   info.Name(),
		})
	}

	return dents, nil
}

// ReadAt implements p9.File.ReadAt
func (f *p9File) ReadAt(p []byte, offset int64) (int, error) {
	if f.file == nil {
		return 0, os.ErrClosed
	}

	return f.file.ReadAt(p, offset)
}

func qidFromFileInfo(info os.FileInfo) p9.QID {
	return qidFromStat(info.Sys().(*syscall.Stat_t))
}

func qidFromStat(s *syscall.Stat_t) p9.QID {
	qtype := p9.ModeFromOS(os.FileMode(s.Mode)).QIDType()
	return p9.QID{
		Type: qtype,
		// TODO: Are inodes reused?
		Path: uint64(s.Ino),
	}
}

// adapted from p9 because their version uses unix.Stat_t instead of syscall.Stat_t

// infoToAttr converts an [os.FileInfo] to an [p9.Attr].
func infoToAttr(info os.FileInfo, req p9.AttrMask) (p9.Attr, p9.AttrMask) {
	s := info.Sys().(*syscall.Stat_t)
	return statToAttr(s, req)
}

// statToAttr converts an [os.FileInfo] to an [p9.Attr].
func statToAttr(s *syscall.Stat_t, req p9.AttrMask) (p9.Attr, p9.AttrMask) {
	attr := p9.Attr{
		UID: p9.NoUID,
		GID: p9.NoGID,
	}
	if req.Mode {
		// p9.FileMode corresponds to Linux mode_t.
		attr.Mode = p9.FileMode(s.Mode)
	}
	if req.NLink {
		attr.NLink = p9.NLink(s.Nlink)
	}
	if req.UID {
		attr.UID = p9.UID(s.Uid)
	}
	if req.GID {
		attr.GID = p9.GID(s.Gid)
	}
	if req.RDev {
		attr.RDev = p9.Dev(s.Dev)
	}
	if req.ATime {
		attr.ATimeSeconds = uint64(s.Atim.Sec)
		attr.ATimeNanoSeconds = uint64(s.Atim.Nsec)
	}
	if req.MTime {
		attr.MTimeSeconds = uint64(s.Mtim.Sec)
		attr.MTimeNanoSeconds = uint64(s.Mtim.Nsec)
	}
	if req.CTime {
		attr.CTimeSeconds = uint64(s.Ctim.Sec)
		attr.CTimeNanoSeconds = uint64(s.Ctim.Nsec)
	}
	if req.Size {
		attr.Size = uint64(s.Size)
	}
	if req.Blocks {
		attr.BlockSize = uint64(s.Blksize)
		attr.Blocks = uint64(s.Blocks)
	}

	// Use the req field because we already have it.
	req.BTime = false
	req.Gen = false
	req.DataVersion = false

	return attr, req
}

func fstatat(dir *os.File, path string) (*syscall.Stat_t, error) {
	conn, err := dir.SyscallConn()
	if err != nil {
		return nil, err
	}

	var stat syscall.Stat_t
	var statErr error

	err = conn.Control(func(fd uintptr) {
		statErr = unix.Fstatat(int(fd), path, (*unix.Stat_t)(unsafe.Pointer(&stat)), unix.AT_SYMLINK_NOFOLLOW)
	})
	if err != nil {
		return nil, err
	}
	return &stat, statErr
}
