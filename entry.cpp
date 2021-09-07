 
#include "process.hpp"
#include "elevation.hpp"

int main()
{
	privelege::ensure_elevation();

	auto remote_lsass = std::make_unique<process::remote_process>("lsass");

	auto modules = process::enum_modules(remote_lsass.get());
	
	auto devobj = modules.find("devobj");

	if (devobj != modules.end())
		std::cout << "Found module devobj.dll at 0x" << std::hex << (std::uintptr_t)devobj->modBaseAddr << std::endl;

	auto handle_to_discord = remote_lsass->retrieve_handle_to("discord");

	std::cout << "Handle to discord found: 0x" << std::hex << handle_to_discord << std::endl;

	auto regions = remote_lsass->find_targetable_regions();
	 
	for (const auto& region : regions) {
		if(remote_lsass->is_address_in_module(region.base)) {

			auto mod = modules.find(reinterpret_cast<std::intptr_t>(region.info.BaseAddress));

			if (mod == modules.end()) {
				continue;
			}

			std::cout << "Region @ 0x" << std::hex << region.base << " with size " << region.size << " inside " << mod.name().c_str() << std::endl;
		}
	}

	std::this_thread::sleep_for(std::chrono::seconds(1000));
}