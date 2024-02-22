#ifndef _IMAGE_PATCHER_H_
#define _IMAGE_PATCHER_H_

#include "vm.h"

// the app is already run by debugger
const WCHAR* IoGetAppFileName();
void         IoSetAppFileName(const WCHAR* filename);

// new file that is patched from original file
const WCHAR* IoGetPatchedFileName();
void         IoSetPatchedFileName(const WCHAR* filename);
// it is not simple wrappers of similar Windows APIs
// file mapping is used in these functions, which accelerates a lot in patching
// return the mapped buffer
bool IoCreatePatchedFile(bool reset);
void IoClosePatchedFile();

// patch code into file
bool PatchFile(unsigned long long mem_addr, unsigned char* code, unsigned long code_len, bool reset);

// patch file with patched vm ins blocks
bool PatchFile(tvm::VmIns& vm_ins, bool reset);

// patch file with patched vm ins group
bool PatchFile(tvm::VmInsGroup& group, bool reset);

// patch file with ins blocks
bool PatchFileWithBlocks(std::vector<tvm::PInsBlock>& blocks, bool reset);

#endif // _IMAGE_PATCHER_H_