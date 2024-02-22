#include <string>
#include <windows.h>
#include "ImagePatcher.h"
#include "IO.h"


static std::wstring       g_original_filename = L"default.exe";
static std::wstring       g_new_filename = L"default-patched.exe";
static unsigned long long g_patched_file_size;
static unsigned char*     g_patched_file_mapped_mem;
static HANDLE             g_patched_file_handle = INVALID_HANDLE_VALUE;
static HANDLE             g_patched_file_mapping_handle;

// patch code into file
bool PatchFile(unsigned long long mem_addr, unsigned char* code, unsigned long code_len, bool reset) {
	unsigned long long image_base = (unsigned long long)IoGetImageBase();
	bool ret = IoCreatePatchedFile(reset);
	if (!ret) {
		printf("[ERROR] Cannot create patched file!\n");
		return false;
	}
	PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)g_patched_file_mapped_mem;
	PIMAGE_NT_HEADERS64 nt_header = (PIMAGE_NT_HEADERS64)(g_patched_file_mapped_mem + dos_header->e_lfanew);
	PIMAGE_SECTION_HEADER section_header = (PIMAGE_SECTION_HEADER)((char*)nt_header +
		sizeof(nt_header->Signature) + sizeof(nt_header->FileHeader) + nt_header->FileHeader.SizeOfOptionalHeader);
	int number_of_section = nt_header->FileHeader.NumberOfSections;
	for (int i = 0; i < number_of_section; i++) {
		if (mem_addr >= image_base + section_header[i].VirtualAddress &&
			mem_addr < image_base + section_header[i].VirtualAddress + section_header[i].SizeOfRawData) {
			unsigned long long file_offset = section_header[i].PointerToRawData +
				(mem_addr - image_base - section_header[i].VirtualAddress);
			// patch it
			memcpy(g_patched_file_mapped_mem + file_offset, code, code_len);
			break;
		}
	}
	IoClosePatchedFile();
	return true;
}

// patch file with patched vm ins blocks
bool PatchFile(tvm::VmIns& vm_ins, bool reset) {
	unsigned long long image_base = (unsigned long long)IoGetImageBase();
	bool ret = IoCreatePatchedFile(reset);
	if (!ret) {
		printf("[ERROR] Cannot create patched file!\n");
		return false;
	}
	PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)g_patched_file_mapped_mem;
	PIMAGE_NT_HEADERS64 nt_header = (PIMAGE_NT_HEADERS64)(g_patched_file_mapped_mem + dos_header->e_lfanew);
	PIMAGE_SECTION_HEADER section_header = (PIMAGE_SECTION_HEADER)((char*)nt_header +
		sizeof(nt_header->Signature) + sizeof(nt_header->FileHeader) + nt_header->FileHeader.SizeOfOptionalHeader);
	int number_of_section = nt_header->FileHeader.NumberOfSections;
	for (auto i = vm_ins.blocks.begin(); i != vm_ins.blocks.end(); i++) {
		if ((*i)->patched) {
			for (int k = 0; k < number_of_section; k++) {
				if ((*i)->addr >= image_base + section_header[k].VirtualAddress &&
					(*i)->addr < image_base + section_header[k].VirtualAddress + section_header[k].SizeOfRawData) {
					unsigned long long file_offset = section_header[k].PointerToRawData +
						((*i)->addr - image_base - section_header[k].VirtualAddress);
					// patch it
					memcpy(g_patched_file_mapped_mem + file_offset, (*i)->code, (*i)->length);
					break;
				}
			}
		}
	}
	IoClosePatchedFile();
	return true;
}

// patch file with ins blocks
bool PatchFileWithBlocks(std::vector<tvm::PInsBlock>& blocks, bool reset) {
	unsigned long long image_base = (unsigned long long)IoGetImageBase();
	bool ret = IoCreatePatchedFile(reset);
	if (!ret) {
		printf("[ERROR] Cannot create patched file!\n");
		return false;
	}
	PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)g_patched_file_mapped_mem;
	PIMAGE_NT_HEADERS64 nt_header = (PIMAGE_NT_HEADERS64)(g_patched_file_mapped_mem + dos_header->e_lfanew);
	PIMAGE_SECTION_HEADER section_header = (PIMAGE_SECTION_HEADER)((char*)nt_header +
		sizeof(nt_header->Signature) + sizeof(nt_header->FileHeader) + nt_header->FileHeader.SizeOfOptionalHeader);
	int number_of_section = nt_header->FileHeader.NumberOfSections;
	for (auto i = blocks.begin(); i != blocks.end(); i++) {
		if ((*i)->patched) {
			for (int k = 0; k < number_of_section; k++) {
				if ((*i)->addr >= image_base + section_header[k].VirtualAddress &&
					(*i)->addr < image_base + section_header[k].VirtualAddress + section_header[k].SizeOfRawData) {
					unsigned long long file_offset = section_header[k].PointerToRawData +
						((*i)->addr - image_base - section_header[k].VirtualAddress);
					// patch it
					memcpy(g_patched_file_mapped_mem + file_offset, (*i)->code, (*i)->length);
					break;
				}
			}
		}
	}
	IoClosePatchedFile();
	return true;
}

// patch file with patched vm ins group
bool PatchFile(tvm::VmInsGroup& group, bool reset) {
	unsigned long long image_base = (unsigned long long)IoGetImageBase();
	bool ret = IoCreatePatchedFile(reset);
    if (!ret) {
        printf("[ERROR] Cannot create patched file!\n");
        return false;
    }
	PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)g_patched_file_mapped_mem;
	PIMAGE_NT_HEADERS64 nt_header = (PIMAGE_NT_HEADERS64)(g_patched_file_mapped_mem + dos_header->e_lfanew);
	PIMAGE_SECTION_HEADER section_header = (PIMAGE_SECTION_HEADER)((char*)nt_header +
		sizeof(nt_header->Signature) + sizeof(nt_header->FileHeader) + nt_header->FileHeader.SizeOfOptionalHeader);
	int number_of_section = nt_header->FileHeader.NumberOfSections;
	for (auto i = group.sequence.begin(); i != group.sequence.end(); i++) {
		for (auto j = (*i)->sequence.begin(); j != (*i)->sequence.end(); j++) {
				for (int k = 0; k < number_of_section; k++) {
					if (j->addr >= image_base + section_header[k].VirtualAddress &&
						j->addr < image_base + section_header[k].VirtualAddress + section_header[k].SizeOfRawData) {
						unsigned long long file_offset = section_header[k].PointerToRawData +
							(j->addr - image_base - section_header[k].VirtualAddress);
						// safe version
						//if (j->code[0] == (g_patched_file_mapped_mem + file_offset)[0]) {
						//	// nop it
						//	memset((unsigned char*)g_patched_file_mapped_mem + file_offset, 0x90, j->code_len);
						//}
						//else {
						//	printf("patch error\n");
						//}

						// fast version
						// nop it
						memset(g_patched_file_mapped_mem + file_offset, 0x90, j->code_len);
						break;
					}
				}
		}
	}
	IoClosePatchedFile();
	return true;
}

// the app is already run by debugger
const WCHAR* IoGetAppFileName() {
    return g_original_filename.c_str();
}

void IoSetAppFileName(const WCHAR* filename) {
    g_original_filename = filename;
}

// new file that is patched from original file
const WCHAR* IoGetPatchedFileName() {
    return g_new_filename.c_str();
}

void IoSetPatchedFileName(const WCHAR* filename) {
    g_new_filename = filename;
}

// it is not simple wrappers of similar Windows APIs
// file mapping is used in these functions, which accelerates a lot in patching
// return the mapped buffer
bool IoCreatePatchedFile(bool reset) {
	if (reset) {
		DeleteFile(g_new_filename.c_str());
		// create and open patched file with the same content of original file
		CopyFile(g_original_filename.c_str(), g_new_filename.c_str(), FALSE);
	}
    HANDLE file_handle = CreateFile(
        g_new_filename.c_str(),
        GENERIC_ALL,
        0, 0,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);
    if (file_handle == INVALID_HANDLE_VALUE) {
        return false;
    }
    // get file size
    LARGE_INTEGER file_size = { 0 };
    BOOL ret = GetFileSizeEx(file_handle, &file_size);
    if (ret) {
        g_patched_file_size = file_size.QuadPart;
    }
    else {
        CloseHandle(file_handle);
        return false;
    }
    // create file mapping to accelerate patching
    HANDLE file_mapping_handle = CreateFileMapping(
        file_handle, NULL,
        PAGE_READWRITE,
        0, 0, NULL);
    if (!file_mapping_handle) {
        CloseHandle(file_handle);
        return false;
    }
    // map file to memory
    g_patched_file_mapped_mem = (unsigned char*)MapViewOfFile(
        file_mapping_handle,
        FILE_MAP_ALL_ACCESS,
        0, 0, 0);
    if (!g_patched_file_mapped_mem) {
        CloseHandle(file_mapping_handle);
        CloseHandle(file_handle);
        return false;
    }
    // these handles can be closed.
    // when UnmapViewOfFile, the resources will be fully released.
    g_patched_file_mapping_handle = file_mapping_handle;
    g_patched_file_handle = file_handle;
    return true;
}

void IoClosePatchedFile() {
    if (g_patched_file_mapped_mem) {
        FlushViewOfFile(g_patched_file_mapped_mem, g_patched_file_size);
        UnmapViewOfFile(g_patched_file_mapped_mem);
        g_patched_file_mapped_mem = nullptr;
        CloseHandle(g_patched_file_mapping_handle);
        FlushFileBuffers(g_patched_file_handle);
        CloseHandle(g_patched_file_handle);
    }
}
