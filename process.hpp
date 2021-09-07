#pragma once

#include <string>
#include <Windows.h>
#include <TlHelp32.h>
#include <vector>
#include <iostream>
#include <algorithm>
#include <map>
#include <Psapi.h>
#include <memory>

#include "nt.hpp"

template <typename T, typename = void>
struct has_begin : std::false_type {};

template <typename T>
struct has_begin<T, decltype(void(std::declval<T&>().begin()))> : std::true_type {};

namespace process {
	// Convert a PROCESSENTRY to std::string
	static auto entry_to_string(const PROCESSENTRY32 entry) -> const std::string {
		return std::string(entry.szExeFile);
	}

	// Utilities
	namespace utils {

		template <typename T, std::enable_if_t<std::is_void<decltype(void(std::declval<T&>().begin()))>::value, bool> = true>
		auto to_lowercase(T entry) -> T {
			std::transform(entry.begin(), entry.end(), entry.begin(), [](unsigned char c) {
				return std::tolower(c);
			});
			return entry;
		}

		struct TARGETABLE_REGION {
			std::intptr_t base;
			std::size_t    size;
			MEMORY_BASIC_INFORMATION info;
		};
	}

	// Remote process structure
	class remote_process {
	private:
		std::string _name;
		std::size_t _pid;
		std::size_t _rights;
		HANDLE		_handle;
	public:

		// Attempt to find a process by its name
		remote_process(std::string);

		// Open target process with rights [rights]
		auto open(std::size_t rights) -> bool;

		// Get the address of the handle that remote process has to [process]
		auto retrieve_handle_to(std::string name, std::size_t owner = 0) -> void*;

		// Find executable region where we can write our shellcode
		auto find_targetable_regions() -> std::vector<utils::TARGETABLE_REGION>;

		// Returns true if the address is inside a module
		auto is_address_in_module(std::intptr_t address) -> bool;

		// Close the current handle
		auto close() -> void;

		// Get the current handle
		auto handle() -> void* {
			return _handle;
		}

		// Returns the PID of the remote process
		auto pid() -> std::size_t {
			return _pid;
		}

		// Attempt to read from target process
		template<typename T>
		auto read(std::uintptr_t address)->T = delete;

		// Attempt to write to target process
		template<typename T>
		auto write(std::uintptr_t address, T value) -> bool = delete;
	};

	// Module iterator for remote_process
	class enum_modules {
	private:
		remote_process* _process;
	public:
		// C++17 is good but also very bad
		class iterator : public std::iterator<std::input_iterator_tag, MODULEENTRY32> {
		private:
			// Cache for processes with key {pid}
			static inline std::map<std::size_t, std::vector<MODULEENTRY32>> _cache;
			remote_process* __process;
			int _idx;
		public:
			// Populate cache for the current process
			explicit iterator(remote_process* process, int index = 0, bool recache = false) : _idx(index), __process(process) {

				// Check if the process in question has a cached module list
				if (_cache[process->pid()].size() > 0 && !recache)
					return;

				// Open handle
				auto handle = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, process->pid());

				if (!handle) {
					__fastfail(-1);
				}

				auto entry = MODULEENTRY32{};
				entry.dwSize = sizeof MODULEENTRY32;

				// Populate the cache for remote process
				for (auto res = Module32First(handle, &entry); res; res = Module32Next(handle, &entry)) {
					_cache[__process->pid()].push_back(entry);
				}

				// Close the handle
				CloseHandle(handle);
			}

			auto length() -> const std::size_t {
				return _cache[__process->pid()].size();
			}

			// Returns current index
			auto idx() -> const int {
				return _idx;
			}

			// Returns true if the given index {i} is correct given the size of our cache
			auto is_valid_index(int i) -> const bool {
				return i <= (_cache[__process->pid()].size() - 1);
			}

			// Increment the iterator
			auto operator++() -> iterator& {
				_idx++; return *this;
			}

			auto operator==(iterator other) -> const bool {
				return _idx == other._idx;
			}

			auto operator!=(iterator other) -> const bool {
				return !(*this == other);
			}

			auto operator*() -> reference {
				if (!is_valid_index(_idx))
					_idx = length() - 1;

				return _cache[__process->pid()].at(_idx);
			}

			auto operator->() -> pointer {
				if (!is_valid_index(_idx))
					_idx = length() - 1;

				return &_cache[__process->pid()].at(_idx);
			}

			auto name() -> std::string {
				return std::string(_cache[__process->pid()].at(_idx).szModule);
			}
		};

		enum_modules(remote_process* process) : _process(process) {}

		iterator find(std::string name) {
			return std::find_if(begin(), end(), [&](MODULEENTRY32 entry) -> bool {
				return std::strstr(utils::to_lowercase(std::string(entry.szExePath)).c_str(), utils::to_lowercase(name).c_str()) != nullptr;
			});
		}

		iterator find(std::intptr_t address) {
			return std::find_if(begin(), end(), [&](MODULEENTRY32 entry) -> bool {
				return address >= reinterpret_cast<std::intptr_t>(entry.modBaseAddr) && address <= reinterpret_cast<std::intptr_t>(entry.modBaseAddr + entry.modBaseSize);
			});
		}

		iterator begin() { return iterator(_process); }
		iterator end() { return iterator(_process, iterator(_process).length()); }
	};

	// Process iterator
	class enum_processes {
	public:
		// Deprecated but cba to do the other way lol!
		class iterator : public std::iterator<std::input_iterator_tag, PROCESSENTRY32> {
		private:
			static inline std::vector<PROCESSENTRY32> _cache;
			int _idx;
		public:
			// Populate the cache with all process entries
			// And set the first index ofc..
			explicit iterator(int index = 0, bool recache = false) : _idx(index) {

				// Check if the process list has been cached, if we are specifically asked to recache
				// we will
				if (_cache.size() > 0 && !recache)
					return;

				auto handle = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

				if (!handle) {
					__fastfail(-1);
				}

				auto entry = PROCESSENTRY32{};
				entry.dwSize = sizeof PROCESSENTRY32;

				// Populate the cache
				for (auto res = Process32First(handle, &entry); res; res = Process32Next(handle, &entry)) {
					_cache.push_back(entry);
				}

				// Close the handle
				CloseHandle(handle);

				// Nice!
				std::cout << "Size of _cache: " << _cache.size() << std::endl;
			}

			// Returns size of our cache
			auto length() -> const std::size_t {
				return _cache.size();
			}
			
			// Returns current index
			auto idx() -> const int {
				return _idx;
			}


			// Returns true if the given index i is correct given the size of our cache
			auto is_valid_index(int i) -> const bool {
				return i <= (_cache.size() - 1);
			}

			// Increment the iterator
			auto operator++() -> iterator& {
				_idx++; return *this;
			}

			auto operator==(iterator other) -> const bool {
				return _idx == other._idx;
			}

			auto operator!=(iterator other) -> const bool {
				return !(*this == other);
			}

			auto operator*() -> reference {
				if (!is_valid_index(_idx))
					_idx = length() - 1;

				return _cache[_idx];
			}

			auto operator->() -> pointer {
				if (!is_valid_index(_idx))
					_idx = length() - 1;

				return &_cache[_idx];
			}
		};

		iterator begin() { return iterator(); }
		iterator end() { return iterator(iterator().length()); }
	};
}