package main

import "debug/pe"

type PE struct {
	raw                   []byte
	ImageDosHeader        *ImageDosHeader
	ImageNTHeaders        *ImageNTHeaders
	ImageOptionalHeader32 *pe.OptionalHeader32
	ImageOptionalHeader64 *pe.OptionalHeader64
	ImageSectionHeaders   []*ImageSectionHeader
	ExportDirectory       *IMAGE_EXPORT_DIRECTORY
}

func (p *PE) Parse(file []byte) {

	p.raw = file

	p.ImageDosHeader = GetDOSHeader(file)

	p.ImageNTHeaders = GetNtHeader(file)

	switch p.ImageNTHeaders.FileHeader.SizeOfOptionalHeader {

	case 0xf0:
		//x64
		p.ImageOptionalHeader64 = GetOptHeader64(file)

	case 0xe0:
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
