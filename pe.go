package main

import (
	"debug/pe"
	"errors"
	"reflect"
	"unsafe"
)

type PE struct {
	raw                   []byte
	ImageDosHeader        *ImageDosHeader
	ImageNTHeaders        *ImageNTHeaders
	ImageOptionalHeader32 *pe.OptionalHeader32
	ImageOptionalHeader64 *pe.OptionalHeader64
	ImageSectionHeaders   []*ImageSectionHeader
	ExportDirectory       *IMAGE_EXPORT_DIRECTORY
}

func (p *PE) GetIcon() ([][]byte, error) {

	var icons [][]byte
	//p.Parse(f)
	if len(p.raw) == 0 {
		return nil, errors.New("please call Parse function first")
	}

	firstResourceDir, rootOffset := GetResourceDirectory(p.raw)

	dirEntryNum := firstResourceDir.NumberOfIdEntries

	entrySlice := make([]*ImageResourceDirectoryEntry, dirEntryNum)

	for i := uint16(0); i < dirEntryNum; i++ {
		entryOffset := rootOffset + uint32(unsafe.Sizeof(ImageResourceDirectory{})) + (uint32(unsafe.Sizeof(ImageResourceDirectoryEntry{})) * uint32(i))
		entry := (*ImageResourceDirectoryEntry)(unsafe.Pointer(&p.raw[entryOffset]))
		entrySlice[i] = entry
	}

	for _, v := range entrySlice {

		if v.Name&(1<<31) == 0 && v.Name == ENTRY_NAME_ICON {

			offset := v.OffsetToData & (^uint32(1 << 31))

			offset += rootOffset

			//Secondary directory
			secondResourceDir := (*ImageResourceDirectory)(unsafe.Pointer(&p.raw[offset]))

			dirEntryNum = secondResourceDir.NumberOfIdEntries

			secEntrySlice := make([]*ImageResourceDirectoryEntry, dirEntryNum)

			for i := uint16(0); i < dirEntryNum; i++ {
				entryOffset := offset + uint32(unsafe.Sizeof(ImageResourceDirectory{})) + (uint32(unsafe.Sizeof(ImageResourceDirectoryEntry{})) * uint32(i))
				entry := (*ImageResourceDirectoryEntry)(unsafe.Pointer(&p.raw[entryOffset]))
				secEntrySlice[i] = entry
			}

			for _, v := range secEntrySlice {

				// high bit is 1 meat point to next dir
				if v.Name&(1<<31) == 0 {

					offset := v.OffsetToData & (^uint32(1 << 31))

					offset += rootOffset

					thirdResourceDir := (*ImageResourceDirectory)(unsafe.Pointer(&p.raw[offset]))

					dirEntryNum = thirdResourceDir.NumberOfIdEntries

					thirdEntrySlice := make([]*ImageResourceDirectoryEntry, dirEntryNum)

					for i := uint16(0); i < dirEntryNum; i++ {
						entryOffset := offset + uint32(unsafe.Sizeof(ImageResourceDirectory{})) + (uint32(unsafe.Sizeof(ImageResourceDirectoryEntry{})) * uint32(i))
						entry := (*ImageResourceDirectoryEntry)(unsafe.Pointer(&p.raw[entryOffset]))
						thirdEntrySlice[i] = entry
					}

					for _, v := range thirdEntrySlice {

						offset := v.OffsetToData
						offset += rootOffset

						data := (*ImageResourceDataEntry)(unsafe.Pointer(&p.raw[offset]))

						rva := data.OffsetToData
						rawaddr := RVAToOffset(rva, p.raw)

						icons = append(icons, p.raw[rawaddr:rawaddr+data.Size])
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

	p.raw = file

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
}

func (p *PE) AddSection(name string, size uint32) {
	p.ImageNTHeaders.FileHeader.NumberOfSections++
	p.Parse(p.raw)

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

	var alignment uint32
	if p.ImageOptionalHeader32 != nil {
		alignment = (p.ImageOptionalHeader32.SectionAlignment)
	} else {
		alignment = (p.ImageOptionalHeader64.SectionAlignment)
	}

	if tail == 0 {
		p.ImageSectionHeaders[tail].VirtualAddress = alignment
		p.ImageSectionHeaders[tail].PhysicalAddressOrVirtualSize = uint32(size)
		p.ImageSectionHeaders[tail].PointerToRawData = uint32(len(p.raw))
		p.ImageSectionHeaders[tail].SizeOfRawData = uint32(size)
	} else {
		vOffset := p.ImageSectionHeaders[tail-1].VirtualAddress + p.ImageSectionHeaders[tail-1].PhysicalAddressOrVirtualSize
		if vOffset%alignment != 0 {
			vOffset = vOffset + (alignment - (vOffset % alignment))
		}
		p.ImageSectionHeaders[tail].VirtualAddress = vOffset
		p.ImageSectionHeaders[tail].PhysicalAddressOrVirtualSize = uint32(size)

		p.ImageSectionHeaders[tail].PointerToRawData = uint32(len(p.raw))

		if size%alignment != 0 {
			size = size + (alignment - (size % alignment))
		}
		p.ImageSectionHeaders[tail].SizeOfRawData = uint32(size)
		p.ImageSectionHeaders[tail].Characteristics = 0xE00000E0

		p.raw = append(p.raw, make([]byte, size)...)

		p.Parse(p.raw)

		if p.ImageOptionalHeader32 != nil {
			p.ImageOptionalHeader32.SizeOfImage = p.ImageSectionHeaders[tail].VirtualAddress + p.ImageSectionHeaders[tail].PhysicalAddressOrVirtualSize
		} else {
			p.ImageOptionalHeader64.SizeOfImage = p.ImageSectionHeaders[tail].VirtualAddress + p.ImageSectionHeaders[tail].PhysicalAddressOrVirtualSize
		}
	}
}
