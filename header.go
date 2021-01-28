package editPE

import (
	"debug/pe"
	"unsafe"
)

const (
	SIZE_OF_OPTIONAL_HEADER_32 = 0xe0
	SIZE_OF_OPTIONAL_HEADER_64 = 0xf0
)

const (
	ENTRY_NAME_CURSOR              = 0x01
	ENTRY_NAME_BITMAP              = 0x02
	ENTRY_NAME_ICON                = 0x03
	ENTRY_NAME_MENU                = 0x04
	ENTRY_NAME_DIALOG              = 0x05
	ENTRY_NAME_STIRING             = 0x06
	ENTRY_NAME_FONT_DIRECTORY      = 0x07
	ENTRY_NAME_FONT                = 0x08
	ENTRY_NAME_ACCELERATOR         = 0x09
	ENTRY_NAME_UNFORMATTED         = 0x0a
	ENTRY_NAME_MESSAGETABLE        = 0x0b
	ENTRY_NAME_GROUP_CURSOR        = 0x0c
	ENTRY_NAME_GROUP_ICON          = 0x0e
	ENTRY_NAME_VERSION_INFORMATION = 0x10
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

/*
typedef struct _IMAGE_RESOURCE_DIRECTORY {
    DWORD   Characteristics;
    DWORD   TimeDateStamp;
    WORD    MajorVersion;
    WORD    MinorVersion;
    WORD    NumberOfNamedEntries;
    WORD    NumberOfIdEntries;
//  IMAGE_RESOURCE_DIRECTORY_ENTRY DirectoryEntries[];
} IMAGE_RESOURCE_DIRECTORY, *PIMAGE_RESOURCE_DIRECTORY;
*/
type ImageResourceDirectory struct {
	Characteristics      uint32
	TimeDateStamp        uint32
	MajorVersion         uint16
	MinorVersion         uint16
	NumberOfNamedEntries uint16
	NumberOfIdEntries    uint16
}

/*
typedef struct _IMAGE_RESOURCE_DIRECTORY_ENTRY
	DWORD  Name;
	DWORD  OffsetToData;
}_IMAGE_RESOURCE_DIRECTORY_ENTRY, *P_IMAGE_RESOURCE_DIRECTORY_ENTRY;
*/
type ImageResourceDirectoryEntry struct {
	Name         uint32
	OffsetToData uint32
}

/*
typedef struct _IMAGE_RESOURCE_DATA_ENTRY {
    DWORD   OffsetToData;
    DWORD   Size;
    DWORD   CodePage;
    DWORD   Reserved;
} IMAGE_RESOURCE_DATA_ENTRY, *PIMAGE_RESOURCE_DATA_ENTRY;
*/
type ImageResourceDataEntry struct {
	OffsetToData uint32
	Size         uint32
	CodePage     uint32
	Reserved     uint32
}

/*
typedef struct
{
    WORD idReserved; // Reserved (must be 0)
    WORD idType; // Resource Type (1 for icons)
    WORD idCount; // How many images?
    ICONDIRENTRY idEntries[1]; // An entry for each image (idCount of 'em)
} ICONDIR, *LPICONDIR;
*/
type IconDir struct {
	IdReserved uint16
	IdType     uint16
	IdCount    uint16
}

/*
typedef struct
{
    BYTE bWidth; // Width, in pixels, of the image
    BYTE bHeight; // Height, in pixels, of the image
    BYTE bColorCount; // Number of colors in image (0 if >=8bpp)
    BYTE bReserved; // Reserved ( must be 0)
    WORD wPlanes; // Color Planes
    WORD wBitCount; // Bits per pixel
    DWORD dwBytesInRes; // How many bytes in this resource?
    DWORD dwImageOffset; // Where in the file is this image?
} ICONDIRENTRY, *LPICONDIRENTRY;
*/
type IconDirEntry struct {
	BWidth      byte
	BHeight     byte
	BColorCount byte
	BReserved   byte
	WPlanes     uint16
	WBitCount   uint16
	BytesInRes  uint32
	ImageOffset uint32
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

func GetResourceDirectory(f []byte) (dir *ImageResourceDirectory, rootOffset uint32) {

	dataDir := GetDataDirectory(f)

	offset := dataDir[pe.IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress

	rootOffset = RVAToOffset(offset, f)

	firstResourceDir := (*ImageResourceDirectory)(unsafe.Pointer(&f[rootOffset]))

	return firstResourceDir, rootOffset
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

func GetExportDirectory(f []byte) *ImageExportDirectory {
	data := GetDataDirectory(f)
	export := data[pe.IMAGE_DIRECTORY_ENTRY_EXPORT]
	offset := RVAToOffset(export.VirtualAddress, f)
	return (*ImageExportDirectory)(unsafe.Pointer(&f[offset]))
}

func GetImportDirectory(f []byte) *ImageImportDirectory {
	data := GetDataDirectory(f)
	_import := data[pe.IMAGE_DIRECTORY_ENTRY_IMPORT]
	offset := RVAToOffset(_import.VirtualAddress, f)
	return (*ImageImportDirectory)(unsafe.Pointer(&f[offset]))
}

/*
size_t RVAToOffset(size_t stRVA,PVOID lpFileBuf)
{
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)lpFileBuf;
	size_t stPEHeadAddr = (size_t)lpFileBuf + pDos ->e_lfanew;
	PIMAGE_NT_HEADERS32 pNT = (PIMAGE_NT_HEADERS32)stPEHeadAddr;
	//区段数
	DWORD dwSectionCount = pNT->FileHeader.NumberOfSections;
	//内存对齐大小
	DWORD dwMemoruAil = pNT->OptionalHeader.SectionAlignment;
	PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNT);
	//距离命中节的起始虚拟地址的偏移值。
	DWORD  dwDiffer = 0;
	for (DWORD i = 0; i < dwSectionCount; i++)
	{
		//模拟内存对齐机制
		DWORD dwBlockCount	= pSection[i].SizeOfRawData/dwMemoruAil;
		dwBlockCount       += pSection[i].SizeOfRawData%dwMemoruAil? 1 : 0;

		DWORD dwBeginVA     = pSection[i].VirtualAddress;
		DWORD dwEndVA       = pSection[i].VirtualAddress + dwBlockCount * dwMemoruAil;
		//如果stRVA在某个区段中
		if (stRVA >= dwBeginVA && stRVA < dwEndVA)
		{
			dwDiffer = stRVA - dwBeginVA;
			return pSection[i].PointerToRawData + dwDiffer;
		}
		else if (stRVA < dwBeginVA)//在文件头中直接返回
		{
			return stRVA;
		}
	}
	return 0;
}
*/

func RVAToOffset(RVA uint32, f []byte) uint32 {

	file := GetFileHeader(f)
	sec := GetSectionHeader(f)

	//内存对齐大小
	var memoryAil uint32

	switch file.SizeOfOptionalHeader {
	case SIZE_OF_OPTIONAL_HEADER_32:
		memoryAil = GetOptHeader32(f).SectionAlignment
	case SIZE_OF_OPTIONAL_HEADER_64:
		memoryAil = GetOptHeader64(f).SectionAlignment
	}

	for _, v := range sec {

		blockCount := v.SizeOfRawData / memoryAil

		if v.SizeOfRawData%memoryAil > 0 {
			blockCount++
		}

		beginVA := v.VirtualAddress
		endVA := v.VirtualAddress + blockCount*memoryAil

		//如果RVA在某个区段中
		if RVA >= beginVA && RVA < endVA {
			differ := RVA - beginVA
			return v.PointerToRawData + differ
		} else if RVA < beginVA {
			return RVA
		}
	}
	return 0
}

/*
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)lpFileBuf;

	size_t stPEHeadAddr = (size_t)lpFileBuf + pDos ->e_lfanew;
	PIMAGE_NT_HEADERS32 pNT = (PIMAGE_NT_HEADERS32)stPEHeadAddr;

	DWORD dwSectionCount = pNT->FileHeader.NumberOfSections;

	DWORD dwImageBase    = pNT->OptionalHeader.ImageBase;

	PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNT);

	DWORD  dwDiffer = 0;
	for (DWORD i = 0; i <  dwSectionCount; i++)
	{
		DWORD dwBeginVA     = pSection[i].PointerToRawData;
		DWORD dwEndVA       = pSection[i].PointerToRawData + pSection[i].SizeOfRawData;

		if (stOffset >= dwBeginVA && stOffset < dwEndVA)
		{
			dwDiffer = stOffset - dwBeginVA;

			return dwImageBase + pSection[i].VirtualAddress + dwDiffer;
		}
		else if (stOffset < dwBeginVA)
		{
			return dwImageBase + stOffset;
		}
	}
	return 0;
*/
func Offset2VA(offset uint32, f []byte) uint64 {

	file := GetFileHeader(f)
	sec := GetSectionHeader(f)

	//内存对齐大小
	var imageBase uint64

	switch file.SizeOfOptionalHeader {
	case SIZE_OF_OPTIONAL_HEADER_32:
		imageBase = uint64(GetOptHeader32(f).ImageBase)
	case SIZE_OF_OPTIONAL_HEADER_64:
		imageBase = GetOptHeader64(f).ImageBase
	}

	for _, v := range sec {

		beginVA := v.PointerToRawData
		EndVA := v.PointerToRawData + v.SizeOfRawData

		if offset >= beginVA && offset < EndVA {
			differ := offset - beginVA
			return imageBase + uint64(v.VirtualAddress+differ)
		} else if offset < beginVA {
			return imageBase + uint64(offset)
		}
	}
	return 0
}
