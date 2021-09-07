#pragma once

#include <Windows.h>
#include <iostream>
#include <thread>

// Shoutout to Ian
// love you bro <3
namespace privelege {

	// Get current path to executable
	static auto get_file_path(char* out) -> void
	{
		char file_name[MAX_PATH];
		GetModuleFileNameA(nullptr, file_name, sizeof file_name);
		GetFullPathNameA(file_name, sizeof file_name, out, nullptr);
	}

	// Check if the current process is elevated
	static auto is_elevated() -> bool {
		auto* token = HANDLE{};

		if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token))
			return false;
		
		auto size = DWORD{};
		auto elevation = TOKEN_ELEVATION{};

		if (!GetTokenInformation(token, TokenElevation, &elevation, sizeof elevation, &size))
			return false;

		CloseHandle(token);

		return elevation.TokenIsElevated;
	}

	// Set dbg privelege
	static auto set_dbg_privelege(bool val) -> bool {
		auto priveleges = TOKEN_PRIVILEGES{};
		auto token = HANDLE{};

		if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &token)) {

			if (token)
				CloseHandle(token);

			return false;
		}

		auto luid = LUID{};
		if (!LookupPrivilegeValueA(0, SE_DEBUG_NAME, &luid)) {
			CloseHandle(token);
			return false;
		}

		priveleges.PrivilegeCount = 1;
		priveleges.Privileges[0].Luid = luid;
		priveleges.Privileges[0].Attributes = val ? SE_PRIVILEGE_ENABLED : SE_PRIVILEGE_REMOVED;

		if (!AdjustTokenPrivileges(token, false, &priveleges, 0, 0, 0)) {
			CloseHandle(token);
			return false;
		}

		CloseHandle(token);
		return true;
	}

	// Ensure the process we're running is actually elevated,
	// that way we can access LSASS
	static auto ensure_elevation() -> void {
		if (!is_elevated())
		{
			// Request runas...
			char file_path[MAX_PATH];
			get_file_path(file_path);

			ShellExecuteA(nullptr, "runas", file_path, "", nullptr, SW_SHOWNORMAL);

			exit(0);
		}

		// Set debug privelege so that we can actually access lsass...
		if (!set_dbg_privelege(true))
			__fastfail(0);
	}
}