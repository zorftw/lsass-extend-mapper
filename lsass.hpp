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

		// TODO:
		// the rest.
	}
}