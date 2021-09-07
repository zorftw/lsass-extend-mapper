#pragma once

#include <Windows.h>
#include <Winternl.h>
#include <ntstatus.h>
#include <mutex>
#pragma comment (lib, "ntdll.lib")

typedef struct _SYSTEM_HANDLE {
	ULONG ProcessId;
	UCHAR ObjectTypeNumber;
	UCHAR Flags;
	USHORT Handle;
	PVOID Object;
	ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE, * PSYSTEM_HANDLE;

typedef struct _SYSTEM_HANDLE_INFORMATION {
	ULONG HandleCount; // Or NumberOfHandles if you prefer
	SYSTEM_HANDLE Handles[1];
} SYSTEM_HANDLE_INFORMATION, * PSYSTEM_HANDLE_INFORMATION;

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO {
	DWORD UniqueProcessId;
	WORD HandleType;
	USHORT HandleValue;
	PVOID Object;
	ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO, * PSYSTEM_HANDLE_TABLE_ENTRY_INFO;

typedef enum _MEMORY_INFORMATION_CLASS {
	MemoryBasicInformation
} MEMORY_INFORMATION_CLASS;

typedef struct _OBJECT_TYPE_INFORMATION {
	UNICODE_STRING TypeName;
	ULONG TotalNumberOfObjects;
	ULONG TotalNumberOfHandles;
	ULONG TotalPagedPoolUsage;
	ULONG TotalNonPagedPoolUsage;
	ULONG TotalNamePoolUsage;
	ULONG TotalHandleTableUsage;
	ULONG HighWaterNumberOfObjects;
	ULONG HighWaterNumberOfHandles;
	ULONG HighWaterPagedPoolUsage;
	ULONG HighWaterNonPagedPoolUsage;
	ULONG HighWaterNamePoolUsage;
	ULONG HighWaterHandleTableUsage;
	ULONG InvalidAttributes;
	GENERIC_MAPPING GenericMapping;
	ULONG ValidAccessMask;
	BOOLEAN SecurityRequired;
	BOOLEAN MaintainHandleCount;
	UCHAR TypeIndex;
	CHAR ReservedByte;
	ULONG PoolType;
	ULONG DefaultPagedPoolCharge;
	ULONG DefaultNonPagedPoolCharge;
} OBJECT_TYPE_INFORMATION, * POBJECT_TYPE_INFORMATION;

using NtQueryVirtualMemoryFn = NTSTATUS (NTAPI*)(
	HANDLE                   ProcessHandle,
	PVOID                    BaseAddress,
	MEMORY_INFORMATION_CLASS MemoryInformationClass,
	PVOID                    MemoryInformation,
	SIZE_T                   MemoryInformationLength,
	PSIZE_T                  ReturnLength);


using NtReadVirtualMemoryFn = NTSTATUS (NTAPI*)(HANDLE handle, PVOID base, PVOID buffer, ULONG num_to_read, PULONG read);

static NTSTATUS NtReadVirtualMemory(HANDLE handle, PVOID base, PVOID buffer, ULONG num_to_read, PULONG read) {
	static std::intptr_t  fn_address = 0;
	static std::once_flag initialized;

	std::call_once(initialized, [&]() {
			auto ntdll = GetModuleHandle("ntdll.dll");

			if (!ntdll)
				ntdll = LoadLibrary("ntdll");

			if (!fn_address) fn_address = (std::intptr_t)GetProcAddress(ntdll, "NtReadVirtualMemory");
		});

	reinterpret_cast<NtReadVirtualMemoryFn>(fn_address)(handle, base, buffer, num_to_read, read);
}

static NTSTATUS NtQueryVirtualMemory(HANDLE                   ProcessHandle,
	PVOID                    BaseAddress,
	MEMORY_INFORMATION_CLASS MemoryInformationClass,
	PVOID                    MemoryInformation,
	SIZE_T                   MemoryInformationLength,
	PSIZE_T                  ReturnLength) {

	static std::intptr_t  fn_address = 0;
	static std::once_flag initialized;
	
	std::call_once(initialized, [&]() {
		auto ntdll = GetModuleHandle("ntdll.dll");

		if (!ntdll)
			ntdll = LoadLibrary("ntdll");

		if (!fn_address) fn_address = (std::intptr_t)GetProcAddress(ntdll, "NtQueryVirtualMemory");
	});

	reinterpret_cast<NtQueryVirtualMemoryFn>(fn_address)(ProcessHandle, BaseAddress, MemoryInformationClass, MemoryInformation, MemoryInformationLength, ReturnLength);
}


EXTERN_C NTSTATUS NTAPI NtDuplicateObject(HANDLE, HANDLE, HANDLE, PHANDLE, ACCESS_MASK, BOOLEAN, ULONG);