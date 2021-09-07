#pragma once

#include <filesystem>
#include <fstream>

#include "process.hpp"

namespace lsass {
	
	constexpr auto SIZE_OF_MAPPER	= 0x255; // note: this size is +A
	constexpr auto SIZE_OF_UTIL		= 0xD6; // same here

	namespace utils {
		using LoadLibraryFn      = HINSTANCE(WINAPI*)(const char* lpLibFilename);
		using GetProcAddressFn   = std::uintptr_t(__stdcall*)(HINSTANCE mod, const char* name);
		using DllMainFn          = bool(__stdcall*)(void* base, std::size_t reason, void* data);

		inline auto get_peb() -> PEB* {
			return reinterpret_cast<PEB*>(__readgsqword(0x60));
		}

		inline auto get_syscall_idx(std::string mod, std::string fn_name) -> std::int32_t {
			auto fn = GetProcAddress(GetModuleHandleA(mod.c_str()), fn_name.c_str());

			std::uint8_t pre_syscall_opcodes[] = {
				0x4C, 0x8B, 0xD1,	// mov r10, rcx;
				0xB8				// mov eax, XXh ; Syscall ID
			};

			for (int i = 0; i < 4; ++i)
				if (*(std::uint8_t*)((DWORD64)fn + i) != pre_syscall_opcodes[i])
					return 0; // The function has been tampered with already...

			return *(DWORD*)((DWORD64)fn + 4);

		}

		typedef struct _LDR_DATA_TABLE_ENTRY_NATIVE {
			LIST_ENTRY     InLoadOrderLinks;
			LIST_ENTRY     InMemoryOrderLinks;
			LIST_ENTRY     InInitializationOrderLinks;
			LPVOID         DllBase;
			LPVOID         EntryPoint;
			ULONG          SizeOfImage;
			UNICODE_STRING FullDllName;
			UNICODE_STRING BaseDllName;
		} LDR_DATA_TABLE_ENTRY_NATIVE, * PLDR_DATA_TABLE_ENTRY_NATIVE;

		struct manual_map_data {
			// pointer to DLL buffer
			std::uint8_t* buffer;
			std::size_t   buffer_size;

			// function pointers
			LoadLibraryFn      load_library;
			GetProcAddressFn   get_proc_address;
		};

		struct controller {
			// spinlock
			std::uintptr_t spinlock	= 1;	// 0
			std::uintptr_t target	= 0;	// 8
			std::uintptr_t base		= 0;	// 16
			std::uintptr_t size		= 0;	// 24
			std::uintptr_t buffer	= 0;	// 32
			std::uintptr_t mm_data	= 0;	// 40
		};


		#define RELOC_FLAG32(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_HIGHLOW)
		#define RELOC_FLAG64(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_DIR64)

		#ifdef _WIN64
		#define RELOC_FLAG RELOC_FLAG64
		#else
		#define RELOC_FLAG RELOC_FLAG32
		#endif
	}

	// Shellcode to map the DLL into memory
	__declspec(noinline) static auto shellcode_mapper(utils::manual_map_data* data) -> void {
		auto nt = reinterpret_cast<IMAGE_NT_HEADERS*>(data->buffer + reinterpret_cast<IMAGE_DOS_HEADER*>(data->buffer)->e_lfanew);

		auto loc_delta = data->buffer - nt->OptionalHeader.ImageBase;

		// store main function
		auto main = reinterpret_cast<utils::DllMainFn>(data->buffer + nt->OptionalHeader.AddressOfEntryPoint);

		// relocate...
		if (loc_delta)
		{
			if (nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size)
			{
				auto reloc_data = reinterpret_cast<IMAGE_BASE_RELOCATION*>(data->buffer + nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

				while (reloc_data->VirtualAddress)
				{
					auto n_entries = (reloc_data->SizeOfBlock - sizeof IMAGE_BASE_RELOCATION) / sizeof WORD;
					auto reloc_info = reinterpret_cast<WORD*>(reloc_data + 1);

					for (auto i = 0; i != n_entries; ++i, ++reloc_info)
					{
						if (RELOC_FLAG(*reloc_info))
						{
							auto patch = reinterpret_cast<UINT_PTR*>(data->buffer + reloc_data->VirtualAddress + ((*reloc_info) & 0xFFF));
							*patch += reinterpret_cast<UINT_PTR>(loc_delta);
						}
					}
				}
			}
		}

		// imports...
		if (nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size)
		{
			auto import_desc = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(data->buffer + nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

			while (import_desc->Name)
			{
				auto sz_mod = reinterpret_cast<char*>(data->buffer + import_desc->Name);
				auto dll = data->load_library(sz_mod);

				auto thunk_ref = reinterpret_cast<ULONG_PTR*>(data->buffer + import_desc->OriginalFirstThunk);
				auto func_ref  = reinterpret_cast<ULONG_PTR*>(data->buffer + import_desc->FirstThunk);

				if (!thunk_ref)
					thunk_ref = func_ref;

				for (; *thunk_ref; ++thunk_ref, ++func_ref)
				{
					if (IMAGE_SNAP_BY_ORDINAL(*thunk_ref))
						*func_ref = data->get_proc_address(dll, reinterpret_cast<char*>(*thunk_ref & 0xFFFF));
					else
					{
						auto _import = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(data->buffer + *thunk_ref);
						*func_ref = data->get_proc_address(dll, _import->Name);
					}
				}

				++import_desc;
			}
		}
		

		// tls...
		if (nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size)
		{
			auto tls = reinterpret_cast<IMAGE_TLS_DIRECTORY*>(data->buffer + nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
			auto callback = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(tls->AddressOfCallBacks);

			for (; callback && *callback; ++callback)
				(*callback)(data->buffer, DLL_PROCESS_ATTACH, nullptr);
		}

		// zero out headers
		auto dos_size = sizeof IMAGE_DOS_HEADER;
		auto base = data->buffer;

		for (auto i = 0; i < dos_size; ++i)
			*(std::uint8_t*)(base + i) = 0;

		auto nt_size  = sizeof IMAGE_NT_HEADERS;

		for (auto i = 0; i < nt_size; ++i)
			*(std::uint8_t*)(nt + i) = 0;

		// call entry
		// note: this makes DllMain responsible for the cleaning up of the data
		main(data->buffer, DLL_PROCESS_ATTACH, data);
	}

	// Map dll at path {path_to_file} into a target process
	static auto map_into_lsass(std::filesystem::path path_to_file, std::string target) -> bool {

		// Initialize portal wars thing
		auto target_process = std::make_unique<process::remote_process>(target);

		// Couldn't find target
		if (!target_process->pid()) {
			return false;
		}

		// Init lsass
		auto lsass_process = std::make_unique<process::remote_process>("lsass");

		// Couldn't find lsass
		if (!lsass_process->pid()) {
			return false;
		}

		// Try and find a handle to {target} within LSASS
		auto remote_handle = lsass_process->retrieve_handle_to(target_process->name());

		// Sanity check
		if (!remote_handle) {
			return false;
		}

		// Copy file to a buffer
		auto file = std::ifstream(path_to_file, std::ios::binary | std::ios::ate);

		// Sanity check
		if (file.fail())
		{
			file.close();
			return false;
		}

		// Allocate buffer
		auto file_size = file.tellg();

		auto source_data = new std::uint8_t[static_cast<UINT_PTR>(file_size)];

		if (!source_data)
		{
			file.close();
			return false;
		}

		// Back to the start of file
		file.seekg(0, std::ios::beg);

		// Copy file into buffer
		file.read(reinterpret_cast<char*>(source_data), file_size);

		// Close
		file.close();

		if (reinterpret_cast<IMAGE_DOS_HEADER*>(source_data)->e_magic != 0x5a4d)
		{
			delete[] source_data;
			return false;
		}

		// ...
		auto old_nt = reinterpret_cast<IMAGE_NT_HEADERS*>(source_data + reinterpret_cast<IMAGE_DOS_HEADER*>(source_data)->e_lfanew);
		auto old_opt = &old_nt->OptionalHeader;
		auto old_fil = &old_nt->FileHeader;

		if (old_fil->Machine != IMAGE_FILE_MACHINE_AMD64)
		{
			delete[] source_data;
			return false;
		}

		std::size_t		size = old_opt->SizeOfImage;
		PVOID			base = nullptr;

		lsass_process->open(PROCESS_ALL_ACCESS);

		// allocate buffer for our DLL into lsass
		auto res = NtAllocateVirtualMemory(lsass_process->handle(), &base, 0, &size, MEM_COMMIT, PAGE_READWRITE);

		if (size < old_opt->SizeOfImage) {
			NtFreeVirtualMemory(lsass_process->handle(), reinterpret_cast<PVOID*>(&base), 0, MEM_RELEASE);
			delete[] source_data;
			return false;
		}

		if (!base) {
			delete[] source_data;
			return false;
		}

		utils::manual_map_data	mm{};
		mm.load_library			= GetModuleHandleA;
		mm.get_proc_address		= reinterpret_cast<utils::GetProcAddressFn>(GetProcAddress);

		auto section_header = IMAGE_FIRST_SECTION(old_nt);

		for (auto i = 0; i != old_fil->NumberOfSections; ++i, ++section_header)
		{
			if (section_header->SizeOfRawData)
			{
				// write section to thing
				if (!WriteProcessMemory(lsass_process->handle(), reinterpret_cast<LPVOID>((std::intptr_t)base + section_header->VirtualAddress), source_data + section_header->PointerToRawData, section_header->SizeOfRawData, nullptr))
				{
					NtFreeVirtualMemory(lsass_process->handle(), reinterpret_cast<PVOID*>(&base), 0, MEM_RELEASE);
					delete[] source_data;
					return false;
				}
			}
		}

		// manual map data at beginning of that buffer
		memcpy(source_data, &mm, sizeof mm); 

		// write to target
		WriteProcessMemory(lsass_process->handle(), reinterpret_cast<LPVOID>(base), source_data, 0x1000, nullptr);

		// cleanup
		delete[] source_data;

		// Allocate memory for remote controller
		std::size_t		controller_size = sizeof utils::controller;
		PVOID			controller_base = nullptr;

		NtAllocateVirtualMemory(lsass_process->handle(), &controller_base, 0, &controller_size, MEM_COMMIT, PAGE_READWRITE);

		// TODO:
		// the rest.
		// Note so that I know what I'm doing from here on out:
		// also, spawn a local shellcode buffer so we can easily write
		// The DLL is copied into LSASS with address of {base} and size {size}
		// Current steps are
		// 1. Write shellcode with spinlock & function templates
		// {
		//		mov al, [&spinlock]
		//		cmp al, 0
		//		pause
		//		jnz -14
		// ---------------------- We're past the spinlock
		//	registers: (1) RCX (2) RDX (3) r8 (4) r9 (5...) stack
		//	functions:
		//		(0): AVM
		//		(1): WVM
		//		(2): CreateRemoteThread
		//
		auto wvm_syscall = utils::get_syscall_idx("ntdll.dll", "NtWriteVirtualMemory");
		auto avm_syscall = utils::get_syscall_idx("ntdll.dll", "NtAllocateVirtualMemory");

		std::uintptr_t	local_shellcode_buffer	= reinterpret_cast<std::uintptr_t>(VirtualAlloc(nullptr, 4096, MEM_COMMIT, PAGE_READWRITE));

		auto original_local_shellcode_buffer_address = local_shellcode_buffer;

		if (!local_shellcode_buffer)
		{
			NtFreeVirtualMemory(lsass_process->handle(), reinterpret_cast<PVOID*>(&base), 0, MEM_RELEASE);
			return false;
		}

		std::uint8_t spinlock_shellcode[] = {
			0xa0, 0,0,0,0,0,0,0,0,	// mov al, [&spinlock]
			0x3c, 0,				// cmp al, 0
			0xf3, 0x90,				// pause
			0x75, 0xf1,				// jnz -15
			0x50,					// push rax				
			0x48, 0x83, 0xec, 0x28,	// sub rsp, 0x28		
		};
		*(std::uintptr_t*)(spinlock_shellcode + 1) = (std::uintptr_t)(controller_base);

		// copy shellcode into buffer
		std::memcpy((void*)local_shellcode_buffer, spinlock_shellcode, sizeof spinlock_shellcode);
		local_shellcode_buffer += sizeof spinlock_shellcode;

		std::uint8_t controller_shellcode[] = {
			0xa0, 0,0,0,0,0,0,0,0,					// mov al, [&function]	(+0)  (&function +1)
			0x3c, 2,								// cmp al, 2			(+9) NOTE: The reason we check CreateRemoteThread first is because it basically needs its own stack
			0x74, 102,								// je +104				(+11) Jump to CreateRemoteThread instead


			0x48, 0xa1, 0, 0, 0, 0, 0, 0, 0, 0,		// mov rax, [&target]	(+13) (&target	+15)
			0x48, 0x89, 0xc1,						// mov rcx, rax			(+23)
			0x48, 0xa1, 0, 0, 0, 0, 0, 0, 0, 0,		// mov rax, [&base]		(+26) (&base	+28)
			0x48, 0x89, 0xc2,						// mov rdx, rax			(+36)
			0x3c, 0,								// cmp al, 0			(+39) This is AVM
			0x75, 33,								// jne +33				(+41) Jump to WVM

			// We're now inside syscall for AVM !!!!
			// Arguments left: Buffer (ZERO_BITS), Size (done), AllocationType, Protect,
			0x49, 0xc7, 0, 0, 0, 0,					// mov r8, 0			(+43)
			0x48, 0xa1, 0, 0, 0, 0, 0, 0, 0, 0,		// mov rax, [&size]		(+49) (&size	+51)
			0x49, 0x89, 0xc1,						// mov r9, rax			(+59)
			0x68, 0x00, 0x10, 0x00, 0x00,			// push MEM_COMMIT		(+62)
			0x6a, 0x40,								// push PAGE_EXECUTE_READWRITE (+67)
			0xb8, 0,0,0,0,							// mov eax, syscall id	(+69) (&syscall +70)
			0x0f, 0x05,								// syscall				(+74)
			0xeb, 93,								// jmp +93				(+76)

			// We're now inside syscall for WVM!!!
			// Arguments left: buffer (done), size (done), num_of_bytes_written
			0x48, 0xa1, 0, 0, 0, 0, 0, 0, 0, 0,		// mov rax, [&buffer]	(+78) (&buffer	+80)
			0x49, 0x89, 0xc0,						// mov r8, rax			(+88)
			0x48, 0xa1, 0, 0, 0, 0, 0, 0, 0, 0,		// mov rax, [&size]		(+91) (&size	+93)
			0x49, 0x89, 0xc1,						// mov r9, rax			(+101)
			//  push 0 on the stack, this is equivalent to the NumberOfBytesWritten argument for WVM
			0x48, 0x31, 0xc0,						// xor rax, rax			(+104)
			0x50,									// push rax				(+107)
			0xb8, 0,0,0,0,							// mov eax, syscall id	(+108) (&syscall +109)
			0x0f, 0x05,								// syscall				(+113)
			0xeb, 54,								// jmp +54				(+115)

			// We're now inside CreateRemoteThread
			0x48, 0xa1, 0, 0, 0, 0, 0, 0, 0, 0,		// mov rax, [&target]	(+117) (&target	+119)
			0x48, 0x89, 0xc1,						// mov rcx, rax			(+127) 
			0x48, 0xc7, 0xc2, 0,0,0,0,				// mov rdx, 0			(+130)	//threadattributes
			0x49, 0xc7, 0xc0, 0, 0, 0, 0,			// mov r8, 0			(+137)	//stacksize
			0x48, 0xa1, 0, 0, 0, 0, 0, 0, 0, 0,		// mov rax, [&data]		(+144) (&data	+146)
			0x49, 0x89, 0xc1,						// mov r9, rax			(+154)  //args
			0x6a, 0,								// push 0				(+157)	//creation flags
			0x6a, 0,								// push 0				(+157)	//thread id
			0x48, 0xb8, 0, 0, 0, 0, 0 ,0 ,0 ,0,		// mov rax [&create_remote_thread]	(+159) (&create_remote_thread	+161)
			0xff, 0xd0,								// call rax				(+169)
			0x48, 0x83, 0xC4, 0x30					// add rsp, 0x30		(+171)
		};

		//members
		*(DWORD64*)(controller_shellcode + 1)	= (DWORD64)(ULONG_PTR)((DWORD64)controller_base + 0);	// <-- function

		*(DWORD64*)(controller_shellcode + 15)	= (DWORD64)(ULONG_PTR)((DWORD64)controller_base + 8);	// <-- target
		*(DWORD64*)(controller_shellcode + 119) = (DWORD64)(ULONG_PTR)((DWORD64)controller_base + 8);	// <-- target

		*(DWORD64*)(controller_shellcode + 28)	= (DWORD64)(ULONG_PTR)((DWORD64)controller_base + 16);	// <-- base

		*(DWORD64*)(controller_shellcode + 80) = (DWORD64)(ULONG_PTR)((DWORD64)controller_base + 32);	// <-- buffer

		*(DWORD64*)(controller_shellcode + 51)	= (DWORD64)(ULONG_PTR)((DWORD64)controller_base + 24);	// <-- size
		*(DWORD64*)(controller_shellcode + 93) = (DWORD64)(ULONG_PTR)((DWORD64)controller_base + 24);	// <-- size

		*(DWORD64*)(controller_shellcode + 146) = (DWORD64)(ULONG_PTR)((DWORD64)controller_base + 40);	// <-- size
		*(DWORD64*)(controller_shellcode + 161) = (DWORD64)(ULONG_PTR)(CreateRemoteThread);	// <-- size

		// syscalls
		*(DWORD*)(controller_shellcode + 70)	= (DWORD)(ULONG_PTR)avm_syscall;
		*(DWORD*)(controller_shellcode + 109) = (DWORD)(ULONG_PTR)wvm_syscall;

		// append to shellcode buffer
		std::memcpy((void*)local_shellcode_buffer, controller_shellcode, sizeof controller_shellcode);
		local_shellcode_buffer += sizeof controller_shellcode;

		// toggle spinlock again
		std::uint8_t toggle_spinlock_shellcode[] = {
			0xB0, 1,								// mov al, 1
			0xA2, 0, 0, 0, 0, 0, 0, 0, 0			// mov [&spinlock], al
		};
		*(DWORD64*)((PUCHAR)toggle_spinlock_shellcode + 3) = (DWORD64)(ULONG_PTR)((DWORD64)controller_base + 0);

		// append to shellcode buffer
		std::memcpy((void*)local_shellcode_buffer, toggle_spinlock_shellcode, sizeof toggle_spinlock_shellcode);
		local_shellcode_buffer += sizeof toggle_spinlock_shellcode;

		// jump back to begin
		std::uint8_t reset_shellcode[]{
			0x48, 0xb8,	0, 0, 0, 0, 0, 0, 0, 0,		// mov rax, controller
			0xff, 0xe0								// jmp rax
		};


		// !!!!! Don't forget this
		*(DWORD64*)((PUCHAR)reset_shellcode + 2) = (DWORD64)(ULONG_PTR)(0xFFFFFFFF);

		// append to shellcode buffer
		std::memcpy((void*)local_shellcode_buffer, reset_shellcode, sizeof reset_shellcode);
		local_shellcode_buffer += sizeof reset_shellcode;

		auto shellcode_size = (local_shellcode_buffer - original_local_shellcode_buffer_address);

		//TODO:
		//write shellcode, spawn thread, and proceed to write DLL into target process


		// free the shellcode buffer
		VirtualFree(reinterpret_cast<LPVOID>(original_local_shellcode_buffer_address), 0, MEM_RELEASE);
	}
}