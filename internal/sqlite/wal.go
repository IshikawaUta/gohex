package sqlite

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
)

// Write-ahead log constants from the file format, section 4.
const (
	walMagicLE = 0x377f0682 // checksum words are little-endian
	walMagicBE = 0x377f0683 // checksum words are big-endian
	walFormat  = 3007000

	walHeaderSize     = 32
	walFrameHeaderLen = 24

	// A page image in a WAL can be large; the index only records offsets, so
	// this bound limits how many frames are walked, not how much is cached.
	maxWALFrames = 1 << 22
)

// walOverlay maps page numbers to the byte offset of their newest committed
// image inside the -wal file. Offsets rather than copies keep a profile with
// a multi-megabyte log from doubling in memory: only the pages a caller
// actually reads are fetched.
type walOverlay struct {
	f        *os.File
	pageSize uint32
	pages    map[int64]int64 // page number -> offset of frame data
	frames   int
	maxPage  int64
	commit   int64 // database size in pages after the last commit frame
}

func (w *walOverlay) page(n int64) []byte {
	off, ok := w.pages[n]
	if !ok {
		return nil
	}
	buf := make([]byte, w.pageSize)
	if _, err := w.f.ReadAt(buf, off); err != nil {
		return nil
	}
	return buf
}

func (w *walOverlay) close() {
	if w != nil && w.f != nil {
		w.f.Close()
		w.f = nil
	}
}

// applyWAL loads <db>-wal if present. Every failure is a warning, never a
// hard error: a database without a usable log is still readable, and a
// profile copied from a failing disk is exactly where a torn log shows up.
func (db *DB) applyWAL() error {
	f, err := os.Open(db.path + "-wal")
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		db.warnf("write-ahead log is unreadable: %v", err)
		return nil
	}
	w, warn := readWAL(f, db.pageSize)
	if warn != "" {
		f.Close()
		db.warnf("%s", warn)
		return nil
	}
	db.wal = w
	if w.maxPage > db.pages {
		db.pages = w.maxPage
	}
	if w.commit > db.pages {
		db.pages = w.commit
	}
	return nil
}

// readWAL walks the log from the start and keeps only frames that belong to
// a committed transaction. Frames after the last commit are a transaction
// SQLite never made durable, so the reader algorithm (file format 4.5) says
// to ignore them.
func readWAL(f *os.File, dbPageSize uint32) (*walOverlay, string) {
	var hdr [walHeaderSize]byte
	if _, err := io.ReadFull(f, hdr[:]); err != nil {
		return nil, fmt.Sprintf("write-ahead log header is truncated: %v", err)
	}
	magic := binary.BigEndian.Uint32(hdr[0:4])
	var bigWords bool
	switch magic {
	case walMagicLE:
		bigWords = false
	case walMagicBE:
		bigWords = true
	default:
		return nil, fmt.Sprintf("write-ahead log has magic 0x%08x, want 0x%08x or 0x%08x", magic, walMagicLE, walMagicBE)
	}
	if v := binary.BigEndian.Uint32(hdr[4:8]); v != walFormat {
		return nil, fmt.Sprintf("write-ahead log format version %d is not %d", v, walFormat)
	}
	pageSize := binary.BigEndian.Uint32(hdr[8:12])
	if pageSize != dbPageSize {
		return nil, fmt.Sprintf("write-ahead log page size %d does not match the database page size %d", pageSize, dbPageSize)
	}
	// The header checksum covers the first 24 bytes starting from zero.
	s0, s1 := walChecksum(hdr[:24], 0, 0, bigWords)
	if s0 != binary.BigEndian.Uint32(hdr[24:28]) || s1 != binary.BigEndian.Uint32(hdr[28:32]) {
		return nil, "write-ahead log header checksum does not match; the log is ignored"
	}
	salt1 := binary.BigEndian.Uint32(hdr[16:20])
	salt2 := binary.BigEndian.Uint32(hdr[20:24])

	w := &walOverlay{f: f, pageSize: pageSize, pages: map[int64]int64{}}
	pending := map[int64]int64{}
	frame := make([]byte, int(walFrameHeaderLen)+int(pageSize))
	for i := 0; i < maxWALFrames; i++ {
		if _, err := io.ReadFull(f, frame); err != nil {
			if errors.Is(err, io.EOF) || err == io.ErrUnexpectedEOF {
				break
			}
			break
		}
		if binary.BigEndian.Uint32(frame[8:12]) != salt1 ||
			binary.BigEndian.Uint32(frame[12:16]) != salt2 {
			break // left over from an earlier checkpoint cycle
		}
		s0, s1 = walChecksum(frame[:8], s0, s1, bigWords)
		s0, s1 = walChecksum(frame[walFrameHeaderLen:], s0, s1, bigWords)
		if s0 != binary.BigEndian.Uint32(frame[16:20]) || s1 != binary.BigEndian.Uint32(frame[20:24]) {
			break // end of the frames that are actually durable
		}
		pgno := int64(binary.BigEndian.Uint32(frame[0:4]))
		// Skip this frame's own 24-byte header: the offset must point at
		// the page image that follows it.
		dataOff := int64(walHeaderSize) + int64(w.frames)*(int64(walFrameHeaderLen)+int64(pageSize)) + int64(walFrameHeaderLen)
		if pgno >= 1 {
			pending[pgno] = dataOff
			if pgno > w.maxPage {
				w.maxPage = pgno
			}
		}
		w.frames++
		if size := int64(binary.BigEndian.Uint32(frame[4:8])); size > 0 {
			for p, off := range pending {
				w.pages[p] = off
			}
			pending = map[int64]int64{}
			w.commit = size
			if size > w.maxPage {
				w.maxPage = size
			}
		}
	}
	return w, ""
}

// walChecksum folds data into the running pair. The input is read as 32-bit
// words whose byte order follows the log's magic number, and the result is
// always stored big-endian by the writer.
func walChecksum(data []byte, s0, s1 uint32, bigWords bool) (uint32, uint32) {
	for i := 0; i+8 <= len(data); i += 8 {
		var x0, x1 uint32
		if bigWords {
			x0 = binary.BigEndian.Uint32(data[i:])
			x1 = binary.BigEndian.Uint32(data[i+4:])
		} else {
			x0 = binary.LittleEndian.Uint32(data[i:])
			x1 = binary.LittleEndian.Uint32(data[i+4:])
		}
		s0 += x0 + s1
		s1 += x1 + s0
	}
	return s0, s1
}
