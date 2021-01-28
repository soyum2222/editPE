package editPE

import (
	"debug/pe"
	"errors"
	"reflect"
	"unsafe"
)

type PE struct {
	Raw                   []byte
	ImageDosHeader        *ImageDosHeader
	ImageNTHeaders        *ImageNTHeaders
	ImageOptionalHeader32 *pe.OptionalHeader32
	ImageOptionalHeader64 *pe.OptionalHeader64
	ImageSectionHeaders   []*ImageSectionHeader
	ExportDirectory       *ImageExportDirectory
}

type ExportFunc struct {
	FuncName []*ENT
	EAT      []*EAT
}

type EAT struct {
	RVA uint32
}

type ENT struct {
	Name []byte
}

func (p *PE) GetExportFunc() ExportFunc {

	offset := RVAToOffset(p.ExportDirectory.AddressOfFunctions, p.Raw)
	num := p.ExportDirectory.NumberOfFunctions
	var eats []*EAT
	for i := uint32(0); i < num; i++ {
		eat := (*EAT)(unsafe.Pointer(&p.Raw[offset+(4*i)]))
		eats = append(eats, eat)
	}

	offset = RVAToOffset(p.ExportDirectory.AddressOfNames, p.Raw)
	num = p.ExportDirectory.NumberOfNames
	var ents []*ENT
	for i := uint32(0); i < num; i++ {

		nameRVA := *(*uint32)(unsafe.Pointer(&p.Raw[offset+(4*i)]))

		beginOffset := RVAToOffset(nameRVA, p.Raw)
		endOffset := beginOffset
		for {
			// 0 meat '\0'
			if p.Raw[endOffset] == 0 {
				break
			}
			endOffset++
		}

		ent := (*ENT)(unsafe.Pointer(&reflect.SliceHeader{
			Data: uintptr(unsafe.Pointer(&p.Raw[beginOffset])),
			Len:  int(endOffset - beginOffset),
		}))

		ents = append(ents, ent)
	}
	return ExportFunc{
		FuncName: ents,
		EAT:      eats,
	}
}

func (p *PE) GetIcon() ([][]byte, error) {

	var icons [][]byte
	//p.Parse(f)
	if len(p.Raw) == 0 {
		return nil, errors.New("please call Parse function first")
	}

	firstResourceDir, rootOffset := GetResourceDirectory(p.Raw)

	dirEntryNum := firstResourceDir.NumberOfIdEntries

	entrySlice := make([]*ImageResourceDirectoryEntry, dirEntryNum)

	for i := uint16(0); i < dirEntryNum; i++ {
		entryOffset := rootOffset + uint32(unsafe.Sizeof(ImageResourceDirectory{})) + (uint32(unsafe.Sizeof(ImageResourceDirectoryEntry{})) * uint32(i))
		entry := (*ImageResourceDirectoryEntry)(unsafe.Pointer(&p.Raw[entryOffset]))
		entrySlice[i] = entry
	}

	for _, v := range entrySlice {

		if v.Name&(1<<31) == 0 && v.Name == ENTRY_NAME_ICON {

			offset := v.OffsetToData & (^uint32(1 << 31))

			offset += rootOffset

			//Secondary directory
			secondResourceDir := (*ImageResourceDirectory)(unsafe.Pointer(&p.Raw[offset]))

			dirEntryNum = secondResourceDir.NumberOfIdEntries

			secEntrySlice := make([]*ImageResourceDirectoryEntry, dirEntryNum)

			for i := uint16(0); i < dirEntryNum; i++ {
				entryOffset := offset + uint32(unsafe.Sizeof(ImageResourceDirectory{})) + (uint32(unsafe.Sizeof(ImageResourceDirectoryEntry{})) * uint32(i))
				entry := (*ImageResourceDirectoryEntry)(unsafe.Pointer(&p.Raw[entryOffset]))
				secEntrySlice[i] = entry
			}

			for _, v := range secEntrySlice {

				// high bit is 1 meat point to next dir
				if v.Name&(1<<31) == 0 {

					offset := v.OffsetToData & (^uint32(1 << 31))

					offset += rootOffset

					thirdResourceDir := (*ImageResourceDirectory)(unsafe.Pointer(&p.Raw[offset]))

					dirEntryNum = thirdResourceDir.NumberOfIdEntries

					thirdEntrySlice := make([]*ImageResourceDirectoryEntry, dirEntryNum)

					for i := uint16(0); i < dirEntryNum; i++ {
						entryOffset := offset + uint32(unsafe.Sizeof(ImageResourceDirectory{})) + (uint32(unsafe.Sizeof(ImageResourceDirectoryEntry{})) * uint32(i))
						entry := (*ImageResourceDirectoryEntry)(unsafe.Pointer(&p.Raw[entryOffset]))
						thirdEntrySlice[i] = entry
					}

					for _, v := range thirdEntrySlice {

						offset := v.OffsetToData
						offset += rootOffset

						data := (*ImageResourceDataEntry)(unsafe.Pointer(&p.Raw[offset]))

						rva := data.OffsetToData
						rawaddr := RVAToOffset(rva, p.Raw)

						icons = append(icons, p.Raw[rawaddr:rawaddr+data.Size])
					}
				}
			}
		}
	}

	// add icon head
	for i := 0; i < len(icons); i++ {
		var head []byte
		icondir := &IconDir{
			IdReserved: 0,
			IdType:     1,
			IdCount:    1,
		}

		foo := &reflect.SliceHeader{
			Data: uintptr(unsafe.Pointer(icondir)),
			Len:  int(unsafe.Sizeof(IconDir{})),
		}

		h := *(*[]byte)(unsafe.Pointer(foo))

		head = append(head, h...)

		entry := &IconDirEntry{
			BWidth:      0,
			BHeight:     0,
			BColorCount: 0,
			BReserved:   0,
			WPlanes:     0,
			WBitCount:   0,
			BytesInRes:  uint32(len(icons[i])),
			ImageOffset: uint32(unsafe.Sizeof(IconDirEntry{}) + unsafe.Sizeof(IconDir{})),
		}

		foo = &reflect.SliceHeader{
			Data: uintptr(unsafe.Pointer(entry)),
			Len:  int(unsafe.Sizeof(IconDirEntry{})),
		}

		h = *(*[]byte)(unsafe.Pointer(foo))

		head = append(head, h...)

		icons[i] = append(head, icons[i]...)
	}

	return icons, nil
}

// please make sure this file is a correct PE file
// you can use pe.Open() function verification
// if this file is not correct PE file ,  may happen panic
func (p *PE) Parse(file []byte) {

	p.Raw = file

	p.ImageDosHeader = GetDOSHeader(file)

	p.ImageNTHeaders = GetNtHeader(file)

	switch p.ImageNTHeaders.FileHeader.SizeOfOptionalHeader {

	case SIZE_OF_OPTIONAL_HEADER_64:
		//x64
		p.ImageOptionalHeader64 = GetOptHeader64(file)

	case SIZE_OF_OPTIONAL_HEADER_32:
		//x86
		p.ImageOptionalHeader32 = GetOptHeader32(file)
	}

	p.ImageSectionHeaders = GetSectionHeader(file)
	p.ExportDirectory = GetExportDirectory(file)
}

func (p *PE) AddSection(name string, size uint32) {
	p.ImageNTHeaders.FileHeader.NumberOfSections++
	p.Parse(p.Raw)

	tail := len(p.ImageSectionHeaders) - 1

	if name[0] != '.' {
		name = string(append([]byte{'.'}, []byte(name)...))
	}

	if len(name) < 8 {
		name = string(append([]byte(name), make([]byte, 8-len(name))...))
	}

	p.ImageSectionHeaders[tail].Name[0] = name[0]
	p.ImageSectionHeaders[tail].Name[1] = name[1]
	p.ImageSectionHeaders[tail].Name[2] = name[2]
	p.ImageSectionHeaders[tail].Name[3] = name[3]
	p.ImageSectionHeaders[tail].Name[4] = name[4]
	p.ImageSectionHeaders[tail].Name[5] = name[5]
	p.ImageSectionHeaders[tail].Name[6] = name[6]
	p.ImageSectionHeaders[tail].Name[7] = name[7]

	var sAlignment uint32
	var fAlignment uint32
	if p.ImageOptionalHeader32 != nil {
		sAlignment = p.ImageOptionalHeader32.SectionAlignment
		fAlignment = p.ImageOptionalHeader32.FileAlignment
	} else {
		sAlignment = p.ImageOptionalHeader64.SectionAlignment
		fAlignment = p.ImageOptionalHeader64.FileAlignment
	}

	PointerToRawData := uint32(len(p.Raw))
	PointerToRawData += (fAlignment - (PointerToRawData % fAlignment))

	if tail == 0 {
		p.ImageSectionHeaders[tail].VirtualAddress = sAlignment
		p.ImageSectionHeaders[tail].PhysicalAddressOrVirtualSize = uint32(size)
		p.ImageSectionHeaders[tail].PointerToRawData = PointerToRawData
		p.ImageSectionHeaders[tail].SizeOfRawData = uint32(size)
	} else {
		vOffset := p.ImageSectionHeaders[tail-1].VirtualAddress + p.ImageSectionHeaders[tail-1].PhysicalAddressOrVirtualSize
		if vOffset%sAlignment != 0 {
			vOffset = vOffset + (sAlignment - (vOffset % sAlignment))
		}
		p.ImageSectionHeaders[tail].VirtualAddress = vOffset
		p.ImageSectionHeaders[tail].PhysicalAddressOrVirtualSize = uint32(size)

		p.ImageSectionHeaders[tail].PointerToRawData = PointerToRawData

		if size%sAlignment != 0 {
			size = size + (sAlignment - (size % sAlignment))
		}
		p.ImageSectionHeaders[tail].SizeOfRawData = uint32(size)
		p.ImageSectionHeaders[tail].Characteristics = 0xE00000E0

		p.Raw = append(p.Raw, make([]byte, (fAlignment-((uint32(len(p.Raw)))%fAlignment))+size)...)

		p.Parse(p.Raw)

		if p.ImageOptionalHeader32 != nil {
			p.ImageOptionalHeader32.SizeOfImage = p.ImageSectionHeaders[tail].VirtualAddress + p.ImageSectionHeaders[tail].PhysicalAddressOrVirtualSize
		} else {
			p.ImageOptionalHeader64.SizeOfImage = p.ImageSectionHeaders[tail].VirtualAddress + p.ImageSectionHeaders[tail].PhysicalAddressOrVirtualSize
		}
	}
}
