package main

import (
	"archive/zip"
	"bytes"
	"errors"
	"io"
)

func zipNewReader(r io.ReaderAt, size int64) (*zip.Reader, error) {
	const BUFSIZE = 4096
	var buf [BUFSIZE + 4]byte
	for i := int64(0); (i-1)*BUFSIZE < size; i++ {
		len, err := r.ReadAt(buf[:], i*BUFSIZE)
		if err != nil && err != io.EOF {
			break
		}

		n := 0
		for {
			m := bytes.Index(buf[n:len], []byte("PK\x03\x04"))
			if m == -1 {
				break
			}
			off := i*BUFSIZE + int64(n+m)
			ssize := size - int64(off)
			sr := io.NewSectionReader(r, int64(off), ssize)
			if zr, ze := zip.NewReader(sr, ssize+1); ze == nil {
				return zr, nil
			}
			n += m + 1
		}
		if err == io.EOF {
			break
		}
	}
	return nil, errors.New("No zip file signature found")
}
