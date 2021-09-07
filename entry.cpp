 
#include "process.hpp"
#include "elevation.hpp"

#include <fstream>
#include <filesystem>

#include "lsass.hpp"

int main()
{
	privelege::ensure_elevation();

	lsass::map_into_lsass("C:\\Users\\Zor\\Crates\\lsass-cpp\\test_project\\x64\\Release\\test_project.dll", "minecraft");
}