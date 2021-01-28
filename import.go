package editPE

type ImageImportDirectory struct {
	OriginalFirstThunk uint32
	TimeDateStamp      uint32
	ForwarderChain     uint32
	Name               uint32
	FirstThunk         uint32
}

type ImageImportByName struct {
	Hint uint16
	Name [20]byte
}

type ImageImport struct {
}
