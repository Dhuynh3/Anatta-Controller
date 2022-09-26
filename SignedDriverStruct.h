#pragma once

//Usermode
#define IOCTL_READ_REQUEST CTL_CODE(FILE_DEVICE_UNKNOWN, 0x691, METHOD_BUFFERED, FILE_ANY_ACCESS)  
#define IOCTL_WRITE_REQUEST CTL_CODE(FILE_DEVICE_UNKNOWN, 0x692, METHOD_BUFFERED, FILE_ANY_ACCESS) 
#define IOCTL_BASE_ADDRESS_REQUEST CTL_CODE(FILE_DEVICE_UNKNOWN, 0x693, METHOD_BUFFERED, FILE_ANY_ACCESS)  
#define IOCTL_MAP_REQUEST CTL_CODE(FILE_DEVICE_UNKNOWN, 0x694, METHOD_BUFFERED, FILE_ANY_ACCESS)  
#define IOCTL_INJECT_REQUEST CTL_CODE(FILE_DEVICE_UNKNOWN, 0x695, METHOD_BUFFERED, FILE_ANY_ACCESS) 
#define IOCTL_GETMODULE_REQUEST CTL_CODE(FILE_DEVICE_UNKNOWN, 0x696, METHOD_BUFFERED, FILE_ANY_ACCESS)  

static const std::string	gsc_szSymLink = "\\\\.\\Habibi";
static HANDLE				gs_hDriver = INVALID_HANDLE_VALUE;

typedef struct _KERNEL_READ_REQUEST
{
	//IN
	BOOL ReadVirt;
	ULONG ProcessID;
	PVOID TargetAddress;

	//Both
	SIZE_T BufferSize;

	//Out
	PVOID BufferAddress;

} KERNEL_READ_REQUEST, * PKERNEL_READ_REQUEST;

typedef struct _KERNEL_WRITE_REQUEST {
	//IN
	BOOL WriteVirt;
	ULONG ProcessID;
	PVOID BufferAddress;

	//BOTH
	SIZE_T BufferSize;

	//OUT
	PVOID TargetAddress;

}KERNEL_WRITE_REQUEST, * PKERNEL_WRITE_REQUEST;

typedef struct _KERNEL_BASE_REQUEST {

	//IN
	ULONG ProcessID;

	//Out
	PVOID BaseAddress;

}KERNEL_BASE_REQUEST, * PKERNEL_BASE_REQUEST;

typedef struct _KERNEL_GETMODULE_REQUEST {

	//IN
	ULONG ProcessID;
	WCHAR ModuleName[260];

	//OUT
	PVOID ModuleBase;
	DWORD ModuleSIze;

} KERNEL_GETMODULE_REQUEST, * PKERNEL_GETMODULE_REQUEST;

typedef struct _KERNEL_MAP_REQUEST {

	//IN
	SIZE_T DriverSize;
	PVOID DriverAddress;

} KERNEL_MAP_REQUEST, * PKERNEL_MAP_REQUEST;