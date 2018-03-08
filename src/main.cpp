#include <string>
#include <iostream>
#include <algorithm>
#include <boost/filesystem.hpp>
#include <boost/algorithm/string.hpp>
#include <LIEF/LIEF.hpp>

namespace fs = boost::filesystem;
using namespace LIEF::ELF;

std::vector<std::string> lib_exceptions = { "libc.so.6" , "libc.so" };
std::vector<std::string> lib_dirs = { "/usr/lib", "/lib" };

std::string find_lib(const std::string& filename)
{
	for (const auto& lib_dir: lib_dirs)
	{
		fs::path lib_path(lib_dir);
		lib_path /= filename;
		if (fs::exists(lib_path))
		{
			return lib_path.native();
		}
	}

	throw;
}

std::vector<std::string> get_libs(Binary *binary)
{
	// Get the imported lib names
	std::vector<std::string> imported_libs_name;
	for (const DynamicEntry& entry : binary->dynamic_entries()) {
		if (dynamic_cast<const DynamicEntryLibrary*>(&entry)) {
			imported_libs_name.push_back(
			dynamic_cast<const DynamicEntryLibrary*>(&entry)->name());
		}
	}
	std::cout << "Imported libs found: ";
	for (const auto& i: imported_libs_name)
        { std::cout << i << ' '; }
	std::cout << std::endl;

	// Remove the unwanted libs
	for (const auto& lib_name: lib_exceptions)
	{
		auto it = std::find(
				imported_libs_name.begin(),
				imported_libs_name.end(),
				lib_name);
		if (it != imported_libs_name.end())
		{
			std::cout << "Removing " << lib_name << std::endl;
			imported_libs_name.erase(it);
		}
	}

	return imported_libs_name;
}

std::vector<Binary *> parse_libs(const std::vector<std::string>& imported_libs_name)
{
	// Parse the libs
	std::vector<Binary *> libs;
	for (const auto& lib_name: imported_libs_name)
	{
		auto lib_path = find_lib(lib_name);
		libs.push_back(Parser::parse(lib_path));
		std::cout << lib_path << " parsed" << std::endl;
	}

	return libs;
}

void merge(std::string& path)
{
	// Parse the binary
	auto binary = Parser::parse(path);
	std::cout << path << " parsed" << std::endl;

	// Parse the libs
	std::vector<std::string> imported_libs_name = get_libs(binary);
	std::vector<Binary *> libs = parse_libs(imported_libs_name);

	// Merge the libs
	for (const auto& lib : libs)
	{
		std::cout << "Merging " << lib->name() << std::endl;

		// Merge the LOAD sections
		Segment *code_segment = nullptr;
		for (const auto& segment : lib->segments())
		{
			if (segment.type() == SEGMENT_TYPES::PT_LOAD)
			{
				auto& new_segment = binary->add(segment);
				if (new_segment.has(ELF_SEGMENT_FLAGS::PF_X))
				{ code_segment = &new_segment; }
			}
		}

		// Relocate the symbols
		for  (const auto& symbol : binary->imported_symbols())
		{
		}
	}

	// Drop the imported libraries
	for (const auto& lib_name : imported_libs_name)
	{ binary->remove_library(lib_name); }

	// Dump the file
	fs::path output(path);
	output = output.filename();
	output += "_merged";
	binary->write(output.native());
	std::cout << output << " written" << std::endl;


	// Be clean, delete
	for (auto lib: libs)
	{ delete lib; }
	delete binary;
}

int main(int argc, char **argv)
{
	if (argc != 2)
	{ return 1; }

	std::string binary_path(argv[1]);
	char* lib_path_ptr = std::getenv("LD_LIBRARY_PATH");
	if (lib_path_ptr)
	{
		std::string lib_paths(lib_path_ptr);
		std::vector<std::string> tmp;
		boost::algorithm::split(tmp, lib_paths, boost::is_any_of(":"));
		lib_dirs.insert(lib_dirs.begin(), tmp.begin(), tmp.end());
	}
	merge(binary_path);
}
