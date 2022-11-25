#include <windows.h>
#include <iostream>
#include <vector>
using namespace std;
#include "portable_executable.h"

int main()
{
	DWORD64 address;
	unsigned char byte;

	portable_executable::vec_imports imports = portable_executable::GetImports(GetModuleHandleA(NULL));

	for (const auto& current_import : imports) {
		for (auto& current_function_data : current_import.function_datas) {
			address = *reinterpret_cast<DWORD64*>(current_function_data.address);
		l1:;
			byte = *reinterpret_cast<unsigned char*>(address);

			if (byte == 0x90) {
				address++;
				goto l1;
			}

			if (byte == 0xE9) {
				byte = *reinterpret_cast<unsigned char*>(address + 5);
				if (byte != 0xCC) {
					cout << "[!] Hook detected: " << current_function_data.name << endl;
					Sleep(5000);
					return 1;
				}
			}
		}
	}	
	return 0;
}
