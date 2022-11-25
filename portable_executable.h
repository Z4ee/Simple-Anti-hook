#pragma once

// https://github.com/TheCruZ/kdmapper/blob/master/kdmapper/portable_executable.cpp

namespace portable_executable {

	struct ImportFunctionInfo
	{
		std::string name;
		uint64_t* address;
	};

	struct ImportInfo
	{
		std::string module_name;
		std::vector<ImportFunctionInfo> function_datas;
	};

	using vec_imports = std::vector<ImportInfo>;

	PIMAGE_NT_HEADERS64 GetNtHeaders(void* image_base) {
		const auto dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(image_base);

		if (dos_header->e_magic != IMAGE_DOS_SIGNATURE)
			return nullptr;

		const auto nt_headers = reinterpret_cast<PIMAGE_NT_HEADERS64>(reinterpret_cast<uint64_t>(image_base) + dos_header->e_lfanew);

		if (nt_headers->Signature != IMAGE_NT_SIGNATURE)
			return nullptr;

		return nt_headers;
	}


	vec_imports GetImports(void* image_base) {
		const PIMAGE_NT_HEADERS64 nt_headers = GetNtHeaders(image_base);

		if (!nt_headers)
			return {};

		DWORD import_va = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;

		if (!import_va)
			return {};

		vec_imports imports;

		auto current_import_descriptor = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(reinterpret_cast<uint64_t>(image_base) + import_va);

		while (current_import_descriptor->FirstThunk) {
			ImportInfo import_info;

			import_info.module_name = std::string(reinterpret_cast<char*>(reinterpret_cast<uint64_t>(image_base) + current_import_descriptor->Name));

			auto current_first_thunk = reinterpret_cast<PIMAGE_THUNK_DATA64>(reinterpret_cast<uint64_t>(image_base) + current_import_descriptor->FirstThunk);
			auto current_originalFirstThunk = reinterpret_cast<PIMAGE_THUNK_DATA64>(reinterpret_cast<uint64_t>(image_base) + current_import_descriptor->OriginalFirstThunk);

			while (current_originalFirstThunk->u1.Function) {
				ImportFunctionInfo import_function_data;

				auto thunk_data = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(reinterpret_cast<uint64_t>(image_base) + current_originalFirstThunk->u1.AddressOfData);

				import_function_data.name = thunk_data->Name;
				import_function_data.address = &current_first_thunk->u1.Function;

				import_info.function_datas.push_back(import_function_data);

				++current_originalFirstThunk;
				++current_first_thunk;
			}

			imports.push_back(import_info);
			++current_import_descriptor;
		}

		return imports;
	}

}