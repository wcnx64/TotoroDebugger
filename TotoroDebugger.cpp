#include <stdio.h>
#include <stdlib.h>
#include <string.h>
//#include <processthreadsapi.h>
//#include <minwinbase.h>
#include <windows.h>
#include <debugapi.h>
#include <dbghelp.h>
#include <vector>
#include "settings.h"
#include "debug.h"
#define ZYDIS_STATIC_BUILD
extern "C" {
#include "zydis/Zydis.h"
}
#include "InstructionTrace.h"
#include "IO.h"
#include "ImagePatcher.h"
#define TEST_HACK_AES
#include "hack_aes.h"

using namespace std;


#ifdef TEST_VMP_INLINE_PROTECTED_AES
int BpCallbackCipherBeginVmpInline(uint8_t* address, void* user_data) {
    // break on VMP common entry
    // the 1st time, it is called by the AES cipher wrapper
    // the 2nd time, it is called by the block cipher
    static int count = 1; // skip the 1st call
    if (count > 0) {
        count--;
        return BREAKPOINT_CALLBACK_RETURN_CONTINUE;
    }
    bool ret = StartVMInsGroup();
    if (ret) {
        return BREAKPOINT_CALLBACK_RETURN_SINGLE_STEP;
    }
    else {
        printf("BpCallbackCipherBeginVmp Error: Failed to start vm ins group analysis!\n");
        return BREAKPOINT_CALLBACK_RETURN_ABORT;
    }
}

int BpCallbackCopyEncryptedBlockVmpInline(uint8_t* address, void* user_data) {
    FinishVMInsGroupVmpInline(address, user_data);
    return BREAKPOINT_CALLBACK_RETURN_CONTINUE_NO_SINGLE_STEP;
}

void LoadAesConfigVmpInline() {
    // VMProtect on inline sensitive functions
    // call VMProtectBegin("Cipher"), by vmp init pattern recognition
    TDbgAddBreakpoint(0x1a186, BpCallbackCipherBeginVmpInline, nullptr, nullptr);
    // copy encrypted block, recognizing memcpy manually
    TDbgAddBreakpoint(0x3b6c,  BpCallbackCopyEncryptedBlockVmpInline, nullptr, nullptr);
}
#endif // TEST_VMP_INLINE_PROTECTED_AES

#ifdef TEST_UNPROTECTED_AES
int BpCallbackCipherStartUnprotected(uint8_t* address, void* user_data) {
    bool ret = StartVMInsGroup();
    if (ret) {
        return BREAKPOINT_CALLBACK_RETURN_SINGLE_STEP;
    }
    else {
        printf("BpCallbackCipherStartUnprotected Error: Failed to start vm ins group analysis!\n");
        return BREAKPOINT_CALLBACK_RETURN_ABORT;
    }
}

int BpCallbackCipherEndUnprotected(uint8_t* address, void* user_data) {
    FinishVMInsGroupUnprotected(address, user_data);
    return BREAKPOINT_CALLBACK_RETURN_CONTINUE_NO_SINGLE_STEP;
}

void LoadAesConfigUnprotected() {
    // unprotected for debugging
    TDbgAddBreakpoint(0x31b2, BpCallbackCipherStartUnprotected, nullptr, nullptr);
    TDbgAddBreakpoint(0x2e9c, BpCallbackCipherEndUnprotected, nullptr, nullptr);
}
#endif // TEST_UNPROTECTED_AES

#ifdef TEST_VMP_PATCH
int BpCallbackStartVmp(uint8_t* addr, void* user_data) {
    bool ret = StartVmInsGroup((uint64_t)addr);
    if (!ret) {
        return tcr::ABORT;
    }
    return tcr::CONTINUE | tcr::ENTER_SINGLE_STEP;
}

int BpCallbackEndVmp(uint8_t* addr, void* user_data) {
    bool repeat = false;
    FinishVmInsGroup((uint64_t)addr, &repeat);
    if (repeat)
        return tcr::REPEAT;
    else
        return tcr::CONTINUE | tcr::EXIT_SINGLE_STEP | tcr::REMOVE_BREAKPOINT;
}
#endif // TEST_VMP_PATCH

int main(int argc, WCHAR** argv) {
    bool ret = TDbgInit();
    if (!ret)
        return 0;
    // set config file
    const WCHAR* config_file_name = L"default.json";
    if (argc > 1)
        config_file_name = argv[1];
#ifdef USE_CONFIG_FILE
    // load config and run debugger
    DbgLoadConfigAndRun(config_file_name);
#else // USE_CONFIG_FILE
    TDbgSetPatch(true);
    TDbgSetSavePatch(true);
    TDbgAddBreakpoint(0x42152, BpCallbackStartVmp, nullptr, nullptr);
    TDbgAddBreakpoint(0x70048, BpCallbackEndVmp, nullptr, nullptr);
    IoSetPatchedFileName(L"arithmetic.vmp.patched.exe");
    TDbgDebugProcess(L"arithmetic.vmp.exe", nullptr);
#endif // USE_CONFIG_FILE
    TDbgUninit();
    return 0;
}
