package main

import (
	"debug/pe"
	"unsafe"
)

/*
typedef struct _IMAGE_DOS_HEADER {      // DOS .EXE header
    WORD   e_magic;                     // Magic number
    WORD   e_cblp;                      // Bytes on last page of file
    WORD   e_cp;                        // Pages in file
    WORD   e_crlc;                      // Relocations
    WORD   e_cparhdr;                   // Size of header in paragraphs
    WORD   e_minalloc;                  // Minimum extra paragraphs needed
    WORD   e_maxalloc;                  // Maximum extra paragraphs needed
    WORD   e_ss;                        // Initial (relative) SS value
    WORD   e_sp;                        // Initial SP value
    WORD   e_csum;                      // Checksum
    WORD   e_ip;                        // Initial IP value
    WORD   e_cs;                        // Initial (relative) CS value
    WORD   e_lfarlc;                    // File address of relocation table
    WORD   e_ovno;                      // Overlay number
    WORD   e_res[4];                    // Reserved words
    WORD   e_oemid;                     // OEM identifier (for e_oeminfo)
    WORD   e_oeminfo;                   // OEM information; e_oemid specific
    WORD   e_res2[10];                  // Reserved words
    LONG   e_lfanew;                    // File address of new exe header
  } IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;
*/
type ImageDosHeader struct {
	EMagic    uint16     // Magic number
	ECblp     uint16     // Bytes on last page of file
	ECp       uint16     // Pages in file
	ECrlc     uint16     // Relocations
	ECparhdr  uint16     // Size of header in paragraphs
	EMinalloc uint16     // Minimum extra paragraphs needed
	EMaxalloc uint16     // Maximum extra paragraphs needed
	ESs       uint16     // Initial (relative) SS value
	ESp       uint16     // Initial SP value
	ECsum     uint16     // Checksum
	EIp       uint16     // Initial IP value
	ECs       uint16     // Initial (relative) CS value
	ELfarlc   uint16     // File address of relocation table
	EOvno     uint16     // Overlay number
	ERes      [4]uint16  // Reserved uint16s
	EOemid    uint16     // OEM identifier (for e_oeminfo)
	EOeminfo  uint16     // OEM information; e_oemid specific
	ERes2     [10]uint16 // Reserved uint16s
	ELfanew   uint32     // File address of new exe header
}

/*
typedef struct _IMAGE_NT_HEADERS {
    DWORD Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER32 OptionalHeader;
} IMAGE_NT_HEADERS32, *PIMAGE_NT_HEADERS32;
*/
type ImageNTHeaders struct {
	Signature  uint32
	FileHeader ImageFileHeader
}

/*
typedef struct _IMAGE_FILE_HEADER {
    WORD    Machine;
    WORD    NumberOfSections;
    DWORD   TimeDateStamp;
    DWORD   PointerToSymbolTable;
    DWORD   NumberOfSymbols;
    WORD    SizeOfOptionalHeader;
    WORD    Characteristics;
} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;
*/
type ImageFileHeader struct {
	Machine              uint16
	NumberOfSections     uint16
	TimeDateStamp        uint32
	PointerToSymbolTable uint32
	NumberOfSymbols      uint32
	SizeOfOptionalHeader uint16
	Characteristics      uint16
}

/*
typedef struct _IMAGE_DATA_DIRECTORY {
    DWORD   VirtualAddress;
    DWORD   Size;
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;
*/
type ImageDataDirectory struct {
	VirtualAddress uint32
	Size           uint32
}

/*
typedef struct _IMAGE_SECTION_HEADER {
    BYTE    Name[IMAGE_SIZEOF_SHORT_NAME];
    union {
            DWORD   PhysicalAddress;
            DWORD   VirtualSize;
    } Misc;
    DWORD   VirtualAddress;
    DWORD   SizeOfRawData;
    DWORD   PointerToRawData;
    DWORD   PointerToRelocations;
    DWORD   PointerToLinenumbers;
    WORD    NumberOfRelocations;
    WORD    NumberOfLinenumbers;
    DWORD   Characteristics;
} IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;
*/
type ImageSectionHeader struct {
	Name                         [8]byte
	PhysicalAddressOrVirtualSize uint32
	VirtualAddress               uint32
	SizeOfRawData                uint32
	PointerToRawData             uint32
	PointerToRelocations         uint32
	PointerToLinenumbers         uint32
	NumberOfRelocations          uint16
	NumberOfLinenumbers          uint16
	Characteristics              uint32
}

func GetDOSHeader(f []byte) *ImageDosHeader {
	return (*ImageDosHeader)(unsafe.Pointer(&f[0]))
}

func GetNtHeader(f []byte) *ImageNTHeaders {
	return (*ImageNTHeaders)(unsafe.Pointer(&f[GetDOSHeader(f).ELfanew]))
}

func GetFileHeader(f []byte) *ImageFileHeader {
	return &GetNtHeader(f).FileHeader
}

func GetOptHeader32(f []byte) *pe.OptionalHeader32 {
	return (*pe.OptionalHeader32)(unsafe.Pointer(&f[int64(GetDOSHeader(f).ELfanew)+int64(unsafe.Sizeof(ImageNTHeaders{}))]))
}

func GetOptHeader64(f []byte) *pe.OptionalHeader64 {
	dos := GetDOSHeader(f)
	offset := int64(dos.ELfanew) + int64(unsafe.Sizeof(ImageNTHeaders{}))
	return (*pe.OptionalHeader64)(unsafe.Pointer(&f[offset]))
}

func GetSectionHeader(f []byte) []*ImageSectionHeader {
	dosh := GetDOSHeader(f)
	fh := GetFileHeader(f)
	var sections []*ImageSectionHeader

	var opOffset int64
	size := GetNtHeader(f).FileHeader.SizeOfOptionalHeader
	if size == 0xe0 {
		opOffset = int64(unsafe.Sizeof(pe.OptionalHeader32{}))
	} else {
		opOffset = int64(unsafe.Sizeof(pe.OptionalHeader64{}))
	}

	for i := int64(0); i < int64(fh.NumberOfSections); i++ {
		offset := int64(dosh.ELfanew) + int64(unsafe.Sizeof(ImageNTHeaders{})) + opOffset + i*int64(unsafe.Sizeof(ImageSectionHeader{}))
		section := (*ImageSectionHeader)(unsafe.Pointer(&f[offset]))
		sections = append(sections, section)
	}
	return sections
}

func GetDataDirectory(f []byte) *[16]pe.DataDirectory {
	nt := GetNtHeader(f)

	switch nt.FileHeader.SizeOfOptionalHeader {

	case 0xf0:
		//x64
		op := GetOptHeader64(f)

		return &op.DataDirectory

	case 0xe0:
		//x86
		op := GetOptHeader32(f)

		return &op.DataDirectory
	}

	return nil
}

func GetExportDirectory(f []byte) *IMAGE_EXPORT_DIRECTORY {

	data := GetDataDirectory(f)
	export := data[pe.IMAGE_DIRECTORY_ENTRY_EXPORT]
	return (*IMAGE_EXPORT_DIRECTORY)(unsafe.Pointer(&f[export.VirtualAddress]))
}
