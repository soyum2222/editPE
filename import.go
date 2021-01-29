package editPE

import (
	"reflect"
	"unsafe"
)

type ImageImportDirectory struct {
	OriginalFirstThunk uint32
	TimeDateStamp      uint32
	ForwarderChain     uint32
	Name               uint32
	FirstThunk         uint32
}

func (i *ImageImportDirectory) ShowName(file []byte) string {
	nameOffset := RVAToOffset(i.Name, file)
	begin := nameOffset
	end := nameOffset
	for {
		if file[end] == 0 {
			break
		}
		end++
	}

	name := *(*string)(unsafe.Pointer(&reflect.SliceHeader{
		Data: uintptr(unsafe.Pointer(&file[begin])),
		Len:  int(end - begin),
	}))
	return name
}

type ImageImportByName struct {
	Hint uint16
	Name byte
}

func (name *ImageImportByName) ShowName() string {
	begin := uintptr(unsafe.Pointer(&name.Name))
	end := begin
	for {
		if (*(*byte)(unsafe.Pointer(end))) == 0 {
			break
		}
		end++
	}

	return *(*string)(unsafe.Pointer(&reflect.SliceHeader{
		Data: begin,
		Len:  int(end - begin),
	}))
}

type ImportTable struct {
	*ImageImportDirectory
	APIName []*ImageImportByName
}
