package main

/*
typedef struct _IMAGE_EXPORT_DIRECTORY {

DWORD   Characteristics;    // 未使用，总为0
DWORD   TimeDateStamp;      // 文件创建时间戳
WORD    MajorVersion;       // 未使用，总为0
WORD    MinorVersion;       // 未使用，总为0
DWORD   Name;               // 指向一个代表此 DLL名字的 ASCII字符串的 RVA
DWORD   Base;               // 函数的起始序号
DWORD   NumberOfFunctions;  // 导出函数的总数
DWORD   NumberOfNames;      // 以名称方式导出的函数的总数
DWORD   AddressOfFunctions;     // 指向输出函数地址的RVA
DWORD   AddressOfNames;         // 指向输出函数名字的RVA
DWORD   AddressOfNameOrdinals;  // 指向输出函数序号的RVA
} IMAGE_EXPORT_DIRECTORY, *PIMAGE_EXPORT_DIRECTORY;
*/

type ImageExportDirectory struct {
	Characteristics       uint32 // always 0
	TimeDateStamp         uint32 // create file time
	MajorVersion          uint16 // always 0
	MinorVersion          uint16 // always 0
	Name                  uint32 // pointer of dll name ascii string rva
	Base                  uint32 // number of function
	NumberOfFunctions     uint32 // function total
	NumberOfNames         uint32 //
	AddressOfFunctions    uint32 // RVA from base of image
	AddressOfNames        uint32 // RVA from base of image
	AddressOfNameOrdinals uint32 // RVA from base of image
}
