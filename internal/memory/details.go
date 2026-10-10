package memory

import (
	"encoding/binary"
	"errors"
	"fmt"
	"sort"
)

// Module is one loaded binary recorded in a dump: a minidump ModuleList
// entry, an ELF NT_FILE mapping, or a Windows kernel-dump module list
// entry. Base/Size bound the image in the dumped address space.
type Module struct {
	Name    string `json:"name"`
	Path    string `json:"path,omitempty"`
	Base    uint64 `json:"base"`
	Size    uint64 `json:"size"`
	Version string `json:"version,omitempty"`
}

// Thread is one thread (minidump ThreadList / ELF NT_PRSTATUS) with its
// stack bounds and, when the dump carries a CONTEXT/PRSTATUS register set
// for a supported architecture, the general-purpose registers.
type Thread struct {
	ID         uint32            `json:"id"`
	Teb        uint64            `json:"teb,omitempty"`
	StackStart uint64            `json:"stackStart,omitempty"`
	StackEnd   uint64            `json:"stackEnd,omitempty"`
	Registers  map[string]uint64 `json:"registers,omitempty"`
}

// Exception is the primary fault recorded in a dump (minidump
// ExceptionStream). Code is an NTSTATUS for Windows dumps.
type Exception struct {
	ThreadID uint32    `json:"threadId"`
	Code     uint32    `json:"code"`
	Address  uint64    `json:"address"`
	Params   [4]uint64 `json:"params"`
	Desc     string    `json:"desc,omitempty"`
}

// BugCheck is the bugcheck code and parameters from a Windows 64-bit
// kernel crash dump header (DUMP_HEADER64).
type BugCheck struct {
	Code   uint32    `json:"code"`
	Params [4]uint64 `json:"params"`
	Desc   string    `json:"desc,omitempty"`
}

// HiberInfo summarises a Windows hibernation file (hiberfil.sys). The
// pages are XPRESS-Huffman compressed; only the page inventory is parsed.
type HiberInfo struct {
	PageSize int      `json:"pageSize"`
	Pages    int      `json:"pages"`
	Versions []string `json:"versions,omitempty"`
}

// Details is the triage summary of a dump: OS/arch, process name, loaded
// modules, threads with registers, and the primary exception when one is
// recorded. All fields are best-effort; whatever the format guarantees is
// filled, the rest stays empty.
type Details struct {
	OS        string     `json:"os,omitempty"`
	Arch      string     `json:"arch,omitempty"`
	Process   string     `json:"process,omitempty"`
	Modules   []Module   `json:"modules"`
	Threads   []Thread   `json:"threads"`
	Exception *Exception `json:"exception,omitempty"`
}

// StackFrame is one frame from a best-effort frame-pointer stack walk.
// When the address falls inside a known module the frame is resolved to
// that module plus the offset from its base; otherwise Module is empty.
type StackFrame struct {
	Addr   uint64 `json:"addr"`
	Module string `json:"module,omitempty"`
	Offset uint64 `json:"offset,omitempty"`
}

// ModuleDiff summarises the loaded-module difference between two dumps.
type ModuleDiff struct {
	OnlyA  []Module `json:"onlyA"`
	OnlyB  []Module `json:"onlyB"`
	Common int      `json:"common"`
}

// parseDetails is the best-effort details pass run for every Open. It
// never fails the open: an unparsable details section simply yields nil.
func parseDetails(f readerAtSize, size int64, format string, head []byte) (*Details, *BugCheck, *HiberInfo) {
	switch format {
	case FormatMinidump:
		d, _ := parseMdmpDetails(f, size)
		return d, nil, nil
	case FormatELFCore:
		d, _ := parseELFDetails(f, head[4])
		return d, nil, nil
	case FormatWinDump:
		bc := parseWinDumpBugCheck(f)
		d := &Details{OS: "windows", Arch: "x86-64"}
		return d, bc, nil
	case FormatHiber:
		h := probeHiber(f)
		d := &Details{OS: "windows"}
		return d, nil, h
	}
	return nil, nil, nil
}

// readerAtSize is the minimal file view details parsers need.
type readerAtSize interface {
	ReadAt(p []byte, off int64) (int, error)
}

// walkMaxFrames bounds a stack walk; a corrupted chain stops well before.
const walkMaxFrames = 64

// WalkStack performs a best-effort frame-pointer walk of the given
// thread's stack inside the capture. path reopens the capture so the
// walk can read stack bytes (compressed captures are decompressed by
// Reader on demand). Without frame pointers in the compiled frames the
// walk returns fewer frames or none; it never guesses.
func (c *Capture) WalkStack(path string, threadID uint32) ([]StackFrame, error) {
	if c.Details == nil {
		return nil, errors.New("memory: capture carries no thread details")
	}
	var th *Thread
	for i := range c.Details.Threads {
		if c.Details.Threads[i].ID == threadID {
			th = &c.Details.Threads[i]
			break
		}
	}
	if th == nil {
		return nil, fmt.Errorf("memory: thread %d not present in capture", threadID)
	}
	var rbpKey, rspKey, ripKey string
	switch {
	case th.Registers["rip"] != 0 || hasRegister(th.Registers, "rip"):
		rbpKey, rspKey, ripKey = "rbp", "rsp", "rip"
	case hasRegister(th.Registers, "eip"):
		rbpKey, rspKey, ripKey = "ebp", "esp", "eip"
	default:
		return nil, errors.New("memory: thread has no supported register set")
	}
	rbp, rsp := th.Registers[rbpKey], th.Registers[rspKey]
	if rbp == 0 || rsp == 0 {
		return nil, errors.New("memory: thread has no frame/stack pointer")
	}

	r, err := OpenReader(path)
	if err != nil {
		return nil, err
	}
	defer r.Close()

	stackEnd := th.StackEnd
	if stackEnd == 0 || stackEnd <= rbp {
		// No usable bound: give the chain a generous window above RBP.
		stackEnd = rbp + 0x40000
	}

	frames := []StackFrame{{Addr: th.Registers[ripKey]}}
	var word [16]byte
	for len(frames) < walkMaxFrames {
		if rbp < rsp || rbp >= stackEnd || rbp%8 != 0 {
			break
		}
		// Reader speaks dense (virtual-view) offsets, not addresses.
		dense, ok := c.denseOffset(rbp)
		if !ok {
			break
		}
		if _, err := r.ReadAt(word[:], dense); err != nil {
			break
		}
		next := binary.LittleEndian.Uint64(word[0:8])
		ret := binary.LittleEndian.Uint64(word[8:16])
		if ret == 0 {
			break
		}
		frames = append(frames, StackFrame{Addr: ret})
		if next <= rbp || next >= stackEnd { // chain must strictly grow towards higher addresses
			break
		}
		rbp = next
	}
	c.Details.resolveFrames(frames)
	return frames, nil
}

func hasRegister(m map[string]uint64, key string) bool {
	if m == nil {
		return false
	}
	_, ok := m[key]
	return ok
}

// denseOffset maps a virtual address onto the Reader's dense virtual-view
// offset (the concatenation point of the covering segment plus the
// offset inside it). It reports false for uncovered addresses.
func (c *Capture) denseOffset(addr uint64) (int64, bool) {
	var dense int64
	for i := range c.Segments {
		s := &c.Segments[i]
		if addr >= s.AddrStart && addr < s.AddrEnd {
			return dense + int64(addr-s.AddrStart), true
		}
		dense += s.Length
	}
	return 0, false
}

// resolveFrames annotates frames with the module that contains them.
func (d *Details) resolveFrames(frames []StackFrame) {
	for i := range frames {
		f := &frames[i]
		for _, m := range d.Modules {
			if m.Size > 0 && f.Addr >= m.Base && f.Addr < m.Base+m.Size {
				f.Module = m.Name
				f.Offset = f.Addr - m.Base
				break
			}
		}
	}
}

// DiffModules compares the loaded-module sets of two dumps by base+size
// identity; names differing for the same base are reported in OnlyA.
func DiffModules(a, b *Details) ModuleDiff {
	var diff ModuleDiff
	if a == nil || b == nil {
		return diff
	}
	inB := make(map[[2]uint64]bool, len(b.Modules))
	for _, m := range b.Modules {
		inB[[2]uint64{m.Base, m.Size}] = true
	}
	inA := make(map[[2]uint64]bool, len(a.Modules))
	for _, m := range a.Modules {
		inA[[2]uint64{m.Base, m.Size}] = true
	}
	for _, m := range a.Modules {
		if !inB[[2]uint64{m.Base, m.Size}] {
			diff.OnlyA = append(diff.OnlyA, m)
		} else {
			diff.Common++
		}
	}
	for _, m := range b.Modules {
		if !inA[[2]uint64{m.Base, m.Size}] {
			diff.OnlyB = append(diff.OnlyB, m)
		}
	}
	sort.Slice(diff.OnlyA, func(i, j int) bool { return diff.OnlyA[i].Base < diff.OnlyA[j].Base })
	sort.Slice(diff.OnlyB, func(i, j int) bool { return diff.OnlyB[i].Base < diff.OnlyB[j].Base })
	return diff
}

// --- Windows exception / bugcheck descriptions -----------------------------

// commonExceptions maps the NTSTATUS codes seen most often in user-mode
// minidumps to a short description.
var commonExceptions = map[uint32]string{
	0xC0000005: "ACCESS_VIOLATION",
	0xC0000017: "NO_MEMORY",
	0xC000001D: "ILLEGAL_INSTRUCTION",
	0xC0000025: "NONCONTINUABLE_EXCEPTION",
	0xC0000094: "INTEGER_DIVIDE_BY_ZERO",
	0xC0000095: "INTEGER_OVERFLOW",
	0xC00000FD: "STACK_OVERFLOW",
	0xC0000135: "DLL_NOT_FOUND",
	0xC0000138: "ORDINAL_NOT_FOUND",
	0xC0000139: "ENTRYPOINT_NOT_FOUND",
	0xC0000142: "DLL_INIT_FAILED",
	0xC0000374: "HEAP_CORRUPTION",
	0xC0000409: "STACK_BUFFER_OVERRUN (GS cookie)",
	0xC0000417: "INVALID_CRUNTIME_PARAMETER",
	0x80000003: "BREAKPOINT",
	0x80000004: "SINGLE_STEP",
}

// commonBugChecks maps bugcheck codes to their short names (a subset of
// the well-known Windows bugchecks; unknown codes render as code only).
var commonBugChecks = map[uint32]string{
	0x1E:  "KMODE_EXCEPTION_NOT_HANDLED",
	0x24:  "NTFS_FILE_SYSTEM",
	0x2E:  "DATA_BUS_ERROR",
	0x3B:  "SYSTEM_SERVICE_EXCEPTION",
	0x4E:  "PFN_LIST_CORRUPT",
	0x50:  "PAGE_FAULT_IN_NONPAGED_AREA",
	0x7B:  "INACCESSIBLE_BOOT_DEVICE",
	0x7E:  "SYSTEM_THREAD_EXCEPTION_NOT_HANDLED",
	0x7F:  "UNEXPECTED_KERNEL_MODE_TRAP",
	0x9F:  "DRIVER_POWER_STATE_FAILURE",
	0xA0:  "INTERNAL_POWER_ERROR",
	0xBE:  "ATTEMPTED_WRITE_TO_READONLY_MEMORY",
	0xC2:  "BAD_POOL_CALLER",
	0xC4:  "DRIVER_VERIFIER_DETECTED_VIOLATION",
	0xD1:  "IRQL_NOT_LESS_OR_EQUAL",
	0xD5:  "DRIVER_PAGE_FAULT_IN_FREED_SPECIAL_POOL",
	0xEF:  "CRITICAL_PROCESS_DIED",
	0x109: "CRITICAL_STRUCTURE_CORRUPTION",
	0x116: "VIDEO_TDR_FAILURE",
	0x119: "VIDEO_SCHEDULER_INTERNAL_ERROR",
	0x124: "WHEA_UNCORRECTABLE_ERROR",
	0x133: "DPC_WATCHDOG_VIOLATION",
	0x139: "KERNEL_SECURITY_CHECK_FAILURE",
	0x154: "UNEXPECTED_STORE_EXCEPTION",
	0x1A:  "MEMORY_MANAGEMENT",
	0x4A:  "IRQL_GT_ZERO_AT_SYSTEM_SERVICE",
}

// DescribeException returns a short name for an NTSTATUS exception code.
func DescribeException(code uint32) string { return commonExceptions[code] }

// DescribeBugCheck returns a short name for a bugcheck code.
func DescribeBugCheck(code uint32) string { return commonBugChecks[code] }

// parseWinDumpBugCheck extracts BugCheckCode and its four parameters from
// a DUMP_HEADER64 (offsets per ntddk.h: BugCheckCode at 0x38, the four
// ULONG64 parameters at 0x40).
func parseWinDumpBugCheck(f readerAtSize) *BugCheck {
	var hdr [0x60]byte
	if _, err := f.ReadAt(hdr[:], 0); err != nil {
		return nil
	}
	code := binary.LittleEndian.Uint32(hdr[0x38:0x3C])
	bc := &BugCheck{Code: code, Desc: DescribeBugCheck(code)}
	for i := 0; i < 4; i++ {
		off := 0x40 + i*8
		bc.Params[i] = binary.LittleEndian.Uint64(hdr[off : off+8])
	}
	return bc
}
