package main

import (
	"compress/gzip"
	"io"
	"os"

	"github.com/u-root/u-root/pkg/cpio"
)

const initBin = "/init"

func writeInitrd(w io.Writer, initExe *os.File) error {
	info, err := initExe.Stat()
	if err != nil {
		return err
	}

	gz, err := gzip.NewWriterLevel(w, gzip.BestSpeed)
	if err != nil {
		return err
	}

	cpw := cpio.NewDedupWriter(cpio.Newc.Writer(gz))
	err = cpio.WriteRecordsAndDirs(cpw, []cpio.Record{
		{
			ReaderAt: initExe,
			Info: cpio.Info{
				Name:     initBin,
				Mode:     cpio.S_IFREG | cpio.S_IEXEC,
				FileSize: uint64(info.Size()),
			},
		},
	})

	if err != nil {
		return err
	}

	return gz.Close()
}
