package halfBanana

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strconv"
	"unsafe"
)

type StringTable []byte

type Export struct {
	Ordinal        uint32
	Name           string
	VirtualAddress uint32
}

type ExportDirectory struct {
	ExportFlags       uint32 // reserved, must be zero
	TimeDateStamp     uint32
	MajorVersion      uint16
	MinorVersion      uint16
	NameRVA           uint32 // pointer to the name of the DLL
	OrdinalBase       uint32
	NumberOfFunctions uint32
	NumberOfNames     uint32 // also Ordinal Table Len
	AddressTableAddr  uint32 // RVA of EAT, relative to image base
	NameTableAddr     uint32 // RVA of export name pointer table, relative to image base
	OrdinalTableAddr  uint32 // address of the ordinal table, relative to iamge base

	DllName string
}

type DosHeader struct {
	MZSignature              uint16
	UsedBytesInTheLastPage   uint16
	FileSizeInPages          uint16
	NumberOfRelocationItems  uint16
	HeaderSizeInParagraphs   uint16
	MinimumExtraParagraphs   uint16
	MaximumExtraParagraphs   uint16
	InitialRelativeSS        uint16
	InitialSP                uint16
	CheckSum                 uint16
	InitialIP                uint16
	InitialRelativeCS        uint16
	AddressOfRelocationTable uint16
	OverlayNumber            uint16
	Reserved                 [4]uint16
	OEMid                    uint16
	OEMinfo                  uint16
	Reserved2                [10]uint16
	AddressOfNewExeHeader    uint32
}

type FileHeader struct {
	Machine              uint16
	NumberOfSections     uint16
	TimeDateStamp        uint32
	PointerToSymbolTable uint32
	NumberOfSymbols      uint32
	SizeOfOptionalHeader uint16
	Characteristics      uint16
}

type Reloc struct {
	VirtualAddress   uint32
	SymbolTableIndex uint32
	Type             uint16
}

type Section struct {
	SectionHeader
	Relocs []Reloc

	// Embed ReaderAt for ReadAt method.
	// Do not embed SectionReader directly
	// to avoid having Read and Seek.
	// If a client wants Read and Seek it must use
	// Open() to avoid fighting over the seek offset
	// with other clients.
	io.ReaderAt
	sr *io.SectionReader
}

type SectionHeader struct {
	Name                 string
	OriginalName         [8]uint8
	VirtualSize          uint32
	VirtualAddress       uint32
	Size                 uint32
	Offset               uint32
	PointerToRelocations uint32
	PointerToLineNumbers uint32
	NumberOfRelocations  uint16
	NumberOfLineNumbers  uint16
	Characteristics      uint32
}

type Symbol struct {
	Name          string
	Value         uint32
	SectionNumber int16
	Type          uint16
	StorageClass  uint8
}

type COFFSymbol struct {
	Name               [8]uint8
	Value              uint32
	SectionNumber      int16
	Type               uint16
	StorageClass       uint8
	NumberOfAuxSymbols uint8
}

type MayBeHookedError struct {
	Foundbytes []byte
}

type File struct {
	DosHeader
	DosExists  bool
	DosStub    [64]byte // TODO(capnspacehook) make slice and correctly parse any DOS stub
	RichHeader []byte
	FileHeader
	OptionalHeader   interface{} // of type *OptionalHeader32 or *OptionalHeader64
	Sections         []*Section
	Symbols          []*Symbol    // COFF symbols with auxiliary symbol records removed
	COFFSymbols      []COFFSymbol // all COFF symbols (including auxiliary symbol records)
	StringTable      StringTable
	CertificateTable []byte

	InsertionAddr  uint32
	InsertionBytes []byte

	closer io.Closer
}

type baseStruct struct {
	filePe *File //Used to be banana
	mode   injectionMode
	memloc uintptr
}

type Image struct {
	BaseAddr uint64
	Size     uint64
}

type stupidstring struct {
	Length    uint16
	MaxLength uint16
	PWstr     *uint16
}

type Slice struct {
	Data unsafe.Pointer
	Len  int
	Cap  int
}

// String is the runtime representation of a string.
// It cannot be used safely or portably and its representation may change in a later release.
type String struct {
	Data unsafe.Pointer
	Len  int
}

type LdrDataTableEntry struct {
	InLoadOrderLinks           ListEntry
	InMemoryOrderLinks         ListEntry
	InInitializationOrderLinks ListEntry
	DllBase                    *uintptr
	EntryPoint                 *uintptr
	SizeOfImage                *uintptr
	FullDllName                stupidstring
	BaseDllName                stupidstring
	Flags                      uint32
	LoadCount                  uint16
	TlsIndex                   uint16
	HashLinks                  ListEntry
	TimeDateStamp              uint64
}

type ListEntry struct {
	Flink *ListEntry
	Blink *ListEntry
	//Awful struct I hate it
}

func isSymNameOffset(name [8]byte) (bool, uint32) {
	if name[0] == 0 && name[1] == 0 && name[2] == 0 && name[3] == 0 {
		return true, binary.LittleEndian.Uint32(name[4:])
	}
	return false, 0
}

func (sym *COFFSymbol) FullName(st StringTable) (string, error) {
	if ok, offset := isSymNameOffset(sym.Name); ok {
		return st.String(offset)
	}
	return cstring(sym.Name[:]), nil
}

func (st StringTable) String(start uint32) (string, error) {
	// start includes 4 bytes of string table length
	if start < 4 {
		return "", fmt.Errorf("offset %d is before the start of string table", start)
	}
	start -= 4
	if int(start) > len(st) {
		return "", fmt.Errorf("offset %d is beyond the end of string table", start)
	}
	return cstring(st[start:]), nil
}

func cstring(b []byte) string {
	i := bytes.IndexByte(b, 0)
	if i == -1 {
		i = len(b)
	}
	return string(b[:i])
}

type OptionalHeader32 struct {
	Magic                       uint16
	MajorLinkerVersion          uint8
	MinorLinkerVersion          uint8
	SizeOfCode                  uint32
	SizeOfInitializedData       uint32
	SizeOfUninitializedData     uint32
	AddressOfEntryPoint         uint32
	BaseOfCode                  uint32
	BaseOfData                  uint32
	ImageBase                   uint32
	SectionAlignment            uint32
	FileAlignment               uint32
	MajorOperatingSystemVersion uint16
	MinorOperatingSystemVersion uint16
	MajorImageVersion           uint16
	MinorImageVersion           uint16
	MajorSubsystemVersion       uint16
	MinorSubsystemVersion       uint16
	Win32VersionValue           uint32
	SizeOfImage                 uint32
	SizeOfHeaders               uint32
	CheckSum                    uint32
	Subsystem                   uint16
	DllCharacteristics          uint16
	SizeOfStackReserve          uint32
	SizeOfStackCommit           uint32
	SizeOfHeapReserve           uint32
	SizeOfHeapCommit            uint32
	LoaderFlags                 uint32
	NumberOfRvaAndSizes         uint32
	DataDirectory               [16]DataDirectory
}

type DataDirectory struct {
	VirtualAddress uint32
	Size           uint32
}

type SectionHeader32 struct {
	Name                 [8]uint8
	VirtualSize          uint32
	VirtualAddress       uint32
	SizeOfRawData        uint32
	PointerToRawData     uint32
	PointerToRelocations uint32
	PointerToLineNumbers uint32
	NumberOfRelocations  uint16
	NumberOfLineNumbers  uint16
	Characteristics      uint32
}

const CERTIFICATE_TABLE = 4

func readCertTable(f *File, r io.ReadSeeker) ([]byte, error) {
	var certTableOffset, certTableSize uint32

	switch f.FileHeader.Machine {
	case IMAGE_FILE_MACHINE_I386:
		certTableOffset = f.OptionalHeader.(*OptionalHeader32).DataDirectory[CERTIFICATE_TABLE].VirtualAddress
		certTableSize = f.OptionalHeader.(*OptionalHeader32).DataDirectory[CERTIFICATE_TABLE].Size
	case IMAGE_FILE_MACHINE_AMD64:
		certTableOffset = f.OptionalHeader.(*OptionalHeader64).DataDirectory[CERTIFICATE_TABLE].VirtualAddress
		certTableSize = f.OptionalHeader.(*OptionalHeader64).DataDirectory[CERTIFICATE_TABLE].Size
	default:
		return nil, errors.New("architecture not supported")
	}

	// check if certificate table exists
	if certTableOffset == 0 || certTableSize == 0 {
		return nil, nil
	}

	var err error
	_, err = r.Seek(int64(certTableOffset), 0)
	if err != nil {
		return nil, fmt.Errorf("fail to seek to certificate table: %v", err)
	}

	// grab the cert
	cert := make([]byte, certTableSize)
	_, err = io.ReadFull(r, cert)
	if err != nil {
		return nil, fmt.Errorf("fail to read certificate table: %v", err)
	}

	return cert, nil
}

func (sh *SectionHeader32) fullName(st StringTable) (string, error) {
	if sh.Name[0] != '/' {
		return cstring(sh.Name[:]), nil
	}
	i, err := strconv.Atoi(cstring(sh.Name[1:]))
	if err != nil {
		return "", err
	}
	return st.String(uint32(i))
}

type zeroReaderAt struct{}

func (w zeroReaderAt) ReadAt(p []byte, off int64) (n int, err error) {
	for i := range p {
		p[i] = 0
	}
	return len(p), nil
}

func readRelocs(sh *SectionHeader, r io.ReadSeeker) ([]Reloc, error) {
	if sh.NumberOfRelocations <= 0 {
		return nil, nil
	}
	_, err := r.Seek(int64(sh.PointerToRelocations), 0)
	if err != nil {
		return nil, fmt.Errorf("fail to seek to %q section relocations: %v", sh.Name, err)
	}
	relocs := make([]Reloc, sh.NumberOfRelocations)
	err = binary.Read(r, binary.LittleEndian, relocs)
	if err != nil {
		return nil, fmt.Errorf("fail to read section relocations: %v", err)
	}
	return relocs, nil
}

type OptionalHeader64 struct {
	Magic                       uint16
	MajorLinkerVersion          uint8
	MinorLinkerVersion          uint8
	SizeOfCode                  uint32
	SizeOfInitializedData       uint32
	SizeOfUninitializedData     uint32
	AddressOfEntryPoint         uint32
	BaseOfCode                  uint32
	ImageBase                   uint64
	SectionAlignment            uint32
	FileAlignment               uint32
	MajorOperatingSystemVersion uint16
	MinorOperatingSystemVersion uint16
	MajorImageVersion           uint16
	MinorImageVersion           uint16
	MajorSubsystemVersion       uint16
	MinorSubsystemVersion       uint16
	Win32VersionValue           uint32
	SizeOfImage                 uint32
	SizeOfHeaders               uint32
	CheckSum                    uint32
	Subsystem                   uint16
	DllCharacteristics          uint16
	SizeOfStackReserve          uint64
	SizeOfStackCommit           uint64
	SizeOfHeapReserve           uint64
	SizeOfHeapCommit            uint64
	LoaderFlags                 uint32
	NumberOfRvaAndSizes         uint32
	DataDirectory               [16]DataDirectory
}

const (
	IMAGE_FILE_MACHINE_UNKNOWN   = 0x0
	IMAGE_FILE_MACHINE_AM33      = 0x1d3
	IMAGE_FILE_MACHINE_AMD64     = 0x8664
	IMAGE_FILE_MACHINE_ARM       = 0x1c0
	IMAGE_FILE_MACHINE_ARMNT     = 0x1c4
	IMAGE_FILE_MACHINE_ARM64     = 0xaa64
	IMAGE_FILE_MACHINE_EBC       = 0xebc
	IMAGE_FILE_MACHINE_I386      = 0x14c
	IMAGE_FILE_MACHINE_IA64      = 0x200
	IMAGE_FILE_MACHINE_M32R      = 0x9041
	IMAGE_FILE_MACHINE_MIPS16    = 0x266
	IMAGE_FILE_MACHINE_MIPSFPU   = 0x366
	IMAGE_FILE_MACHINE_MIPSFPU16 = 0x466
	IMAGE_FILE_MACHINE_POWERPC   = 0x1f0
	IMAGE_FILE_MACHINE_POWERPCFP = 0x1f1
	IMAGE_FILE_MACHINE_R4000     = 0x166
	IMAGE_FILE_MACHINE_SH3       = 0x1a2
	IMAGE_FILE_MACHINE_SH3DSP    = 0x1a3
	IMAGE_FILE_MACHINE_SH4       = 0x1a6
	IMAGE_FILE_MACHINE_SH5       = 0x1a8
	IMAGE_FILE_MACHINE_THUMB     = 0x1c2
	IMAGE_FILE_MACHINE_WCEMIPSV2 = 0x169
)
