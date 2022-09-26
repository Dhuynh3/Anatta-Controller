#include <Windows.h>
#include <winternl.h>
#include <string>
#include <ntstatus.h>
#include <ntddmou.h>
#include <iostream>
#include <fstream>

#include "loadup.hpp"
#include "raw_driver.h"
#include "SignedDriverStruct.h"

#pragma comment (lib, "ntdll.lib")

using namespace std;

bool MapDriver(std::vector<std::uint8_t> DriverData) {
	
	IO_STATUS_BLOCK IoSb;
	KERNEL_MAP_REQUEST pData;
	SecureZeroMemory(&pData, sizeof(KERNEL_MAP_REQUEST));
	pData.DriverAddress = reinterpret_cast<PVOID>(DriverData.data());
	pData.DriverSize = DriverData.size();
	
	NTSTATUS bRet = NtDeviceIoControlFile(gs_hDriver, NULL, NULL, NULL, &IoSb, IOCTL_MAP_REQUEST, &pData, sizeof(pData), &pData, sizeof(pData));

	if (NT_SUCCESS(bRet)) {
		printf("Driver Mapped\n");
		return true;
	}
	return false;
}

BOOL ReadRequest(DWORD processID, PVOID DestinationToRead, PVOID buffer, DWORD size) {

	IO_STATUS_BLOCK IoSb;
	KERNEL_READ_REQUEST pData;
	SecureZeroMemory(&pData, sizeof(KERNEL_READ_REQUEST));

	pData.ProcessID = processID;
	pData.TargetAddress = DestinationToRead;
	pData.BufferAddress = buffer;
	pData.BufferSize = size;
	pData.ReadVirt = false;

	NTSTATUS bRet = NtDeviceIoControlFile(gs_hDriver, NULL, NULL, NULL, &IoSb, IOCTL_READ_REQUEST, &pData, sizeof(pData), &pData, sizeof(pData));

	if (NT_SUCCESS(bRet)) {
		return pData.ReadVirt;
	}

	return pData.ReadVirt;
}

BOOL WriteRequest(DWORD processID, PVOID DestinationToWrite, PVOID buffer, DWORD size) {

	IO_STATUS_BLOCK IoSb;
	KERNEL_WRITE_REQUEST pData;
	SecureZeroMemory(&pData, sizeof(KERNEL_WRITE_REQUEST));

	pData.ProcessID = processID;
	pData.TargetAddress = DestinationToWrite;
	pData.BufferAddress = buffer;
	pData.BufferSize = size;
	pData.WriteVirt = false;

	NTSTATUS bRet = NtDeviceIoControlFile(gs_hDriver, NULL, NULL, NULL, &IoSb, IOCTL_WRITE_REQUEST, &pData, sizeof(pData), &pData, sizeof(pData));

	if (NT_SUCCESS(bRet)) {
	
		return pData.WriteVirt;
	}

	return pData.WriteVirt;

}

PVOID GetBaseAddress(DWORD processID) {

	IO_STATUS_BLOCK IoSb;
	KERNEL_BASE_REQUEST pData;
	SecureZeroMemory(&pData, sizeof(KERNEL_BASE_REQUEST));

	pData.ProcessID = processID;
	pData.BaseAddress = 0;

	NTSTATUS bRet = NtDeviceIoControlFile(gs_hDriver, NULL, NULL, NULL, &IoSb, IOCTL_BASE_ADDRESS_REQUEST, &pData, sizeof(pData), &pData, sizeof(pData));

	if (NT_SUCCESS(bRet)) {

		return pData.BaseAddress;
	}

	return pData.BaseAddress;
}

template<class T> __forceinline T read(int pid, PVOID address)
{
	T buff = {};

	if (ReadRequest(pid, (PVOID)address, &buff, sizeof(T))) {
		return *(T*)&buff;
	}
	else {
		return buff;
	}

	return buff;
}

__forceinline bool read_buffer(int pid, uintptr_t address, void* buffer, size_t size)
{
	return ReadRequest(pid, (PVOID)address, &buffer, size);
}


uintptr_t getImageSectionByName(const std::uintptr_t imageBase, const char* sectionName, std::size_t* sizeOut) {
	if (reinterpret_cast<PIMAGE_DOS_HEADER>(imageBase)->e_magic != 0x5A4D)
		return {};
	const auto ntHeader = reinterpret_cast<PIMAGE_NT_HEADERS64>(imageBase + reinterpret_cast<PIMAGE_DOS_HEADER>(imageBase)->e_lfanew);
	const auto sectionCount = ntHeader->FileHeader.NumberOfSections;
	auto sectionHeader = IMAGE_FIRST_SECTION(ntHeader);

	/*
	for (std::size_t i{}; i < sectionCount; ++i, ++sectionHeader) {
		if (!LI_FN(strcmp)(sectionName, reinterpret_cast<const char*>(sectionHeader->Name))) {
			if (sizeOut)
				*sizeOut = sectionHeader->Misc.VirtualSize;
			return imageBase + sectionHeader->VirtualAddress;
		}
	}
	*/
	return {};
}

/*
uintptr_t GetImageSectionRemote(int pid, const std::uintptr_t imagebase, const char* sectionName, std::size_t* sizeOut) {
	auto dos_header = read<IMAGE_DOS_HEADER>(pid, imagebase);
	if (dos_header.e_magic != 0x5A4D) {
		printf("Bad emagic\n");
		return {0};
	}

	auto nt_header = read<IMAGE_NT_HEADERS>(pid, imagebase + dos_header.e_lfanew);

	const auto sectionCout = nt_header.FileHeader.NumberOfSections;


}
*/


int main() {

	
	/*
	const auto& [status, service_name] = driver::load(rawData, sizeof(rawData));
	if (!status) {
		printf("Unable to load signed driver\n");
		return -1;
	}
	*/

	auto deviceName = (L"\\??\\Habibi");
	UNICODE_STRING HI;
	RtlInitUnicodeString(&HI, deviceName);
	IO_STATUS_BLOCK IoSb;
	OBJECT_ATTRIBUTES Oa = { 0 }; Oa.Length = sizeof Oa; Oa.ObjectName = &HI; Oa.Attributes = OBJ_CASE_INSENSITIVE; Oa.RootDirectory = 0;
	NtOpenFile(&gs_hDriver, FILE_READ_DATA, &Oa, &IoSb, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_SEQUENTIAL_ONLY);

	if (!gs_hDriver || gs_hDriver == INVALID_HANDLE_VALUE) {
		printf("Invalid Driver Handle\n");
		return -1;
	}
	else {
		printf("Driver Handle Valid\n");
	}


	printf("Loaded Driver\n");

	int pid = 28504;

	uintptr_t base_address = (uintptr_t)GetBaseAddress(pid);
	uintptr_t text_base = base_address + 0x1000;
	printf("Base %p\n", base_address);
	
	
	auto dos_header = read<IMAGE_DOS_HEADER>(pid, (PVOID)base_address);
	auto nt_header = read<IMAGE_NT_HEADERS>(pid, (PVOID)(base_address + dos_header.e_lfanew));

	const auto image_size = nt_header.OptionalHeader.SizeOfImage;
	auto buffer = (BYTE*)malloc(image_size);
	#define BLOCK_SIZE 2048
	int chunkcount = image_size / BLOCK_SIZE;

	BYTE buff = 0x0;

	for (int i = 0; i < chunkcount; i++) {
		
		if (WriteRequest(pid, PVOID(base_address + (i * BLOCK_SIZE)), &buff, sizeof(buff))) {
			printf("Wrote good\n");
		}
		else {
			printf("Wrote failed\n");
		}

		if (!ReadRequest(pid, PVOID(base_address + (i * BLOCK_SIZE)), buffer + (i * BLOCK_SIZE), BLOCK_SIZE)) {
			printf("Failed at reading :%p\n", PVOID(base_address + (i * BLOCK_SIZE)));
		}
		else {
			printf("Good at reading :%p\n", PVOID(base_address + (i * BLOCK_SIZE)));
		}

	}

	ofstream dump("C:\\Users\\Microsoft\\Desktop\\GameDumps\\cod.exe", ios::binary);
	if (dump) {
		dump.write((char*)buffer, image_size);
		dump.close();
	}
	

	/*
	auto dos_header = read<IMAGE_DOS_HEADER>(pid, base_address);
	
	auto nt_header = read<IMAGE_NT_HEADERS>(pid, base_address + dos_header.e_lfanew);
	BYTE buffer[10];
	ReadRequest(pid, (PVOID)base_address, buffer, sizeof(buffer));
	for (int i = 0; i < 10; i++) {
		printf("%x ", buffer[i]);
	}
	
	*/

	/*
	bool unload = driver::unload(service_name);
	if (!unload) {
		printf("Unable to unload signed driver\n");
	}
		printf("Unloaded Driver\n");

	*/


	system("pause");
	return 0;
}