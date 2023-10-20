#define TEST_VMP_INLINE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
//#include <processthreadsapi.h>
//#include <minwinbase.h>
#include <windows.h>
#include <debugapi.h>
#include <dbghelp.h>
#include <vector>
#include "debug.h"
#define ZYDIS_STATIC_BUILD
extern "C" {
#include "Zydis.h"
}
#include "InstructionTrace.h"
#include "IO.h"
#define TEST_HACK_AES
#include "hack_aes.h"

using namespace std;

//#define PRINT_DECODE_ERROR printf
#define PRINT_DECODE_ERROR(...)


static ZydisDecoder g_decoder;

void LoadAesConfig();

#define ANALYZE_DO_NOTHING 0
int AnalyzeTrace(unsigned long long ins_addr) {
#define ANALYZE_INST_MAX 5
    static ULONGLONG Inst[ANALYZE_INST_MAX * 2] = { 0 };
    static int       CurrentInstOffset = ANALYZE_INST_MAX - 1;
    CurrentInstOffset = (CurrentInstOffset + 1) % ANALYZE_INST_MAX;
    IoReadProcessMemory(ins_addr, &Inst[CurrentInstOffset], sizeof(Inst[CurrentInstOffset]));
    Inst[5 + CurrentInstOffset] = Inst[CurrentInstOffset];
    CurrentInstOffset += 5;
#define VM_MAJOR_STATE_INS_GROUP_NO_VM    0
#define VM_MAJOR_STATE_INS_GROUP_STARTING 1
#define VM_MAJOR_STATE_INS_GROUP_STARTED  2
#define VM_MAJOR_STATE_INS_GROUP_STOPPING 3
    static int vm_state = VM_MAJOR_STATE_INS_GROUP_STARTED; //  VM_MAJOR_STATE_INS_GROUP_NO_VM;
    static ZydisRegister StackReg = ZYDIS_REGISTER_NONE;
    static ULONGLONG StackAddr = 0;
    static ULONGLONG VMCount = 0;
    static ULONGLONG ErrCount = 0;
    static int State = 0;
    BOOL Hit = FALSE;
    if (ErrCount >= 10) {
        //getchar();
        ErrCount = 0;
    }
    if ((Inst[CurrentInstOffset] & 0xff) == 0xc3) {
        // ret
        //printf("VM INSTRUCTION COUNT %llx\n", VMCount);
        VMCount++;
        FinishVMIns();
        return ANALYZE_DO_NOTHING;
    }
    ZydisDecoderContext zctx = { 0 };
    ZydisDecodedInstruction zins;
    ZyanStatus ZStatus = ZydisDecoderDecodeInstruction(&g_decoder, &zctx,
        &Inst[CurrentInstOffset], sizeof(Inst[CurrentInstOffset]), &zins);
    if (!ZYAN_SUCCESS(ZStatus)) {
        PRINT_DECODE_ERROR("Decoder Error Address: %llx\n", (ULONGLONG)Address);
        ErrCount++;
        return ANALYZE_DO_NOTHING;
    }
    // mov
    if (zins.mnemonic == ZYDIS_MNEMONIC_MOV ||
        zins.mnemonic == ZYDIS_MNEMONIC_MOVZX) {
        if (zins.operand_count >= 2) {
            ZydisDecodedOperand operands[5] = { 0 };
            ZydisDecoderDecodeOperands(&g_decoder, &zctx, &zins, operands, zins.operand_count);
            if (!ZYAN_SUCCESS(ZStatus)) {
                PRINT_DECODE_ERROR("Decoder Error Address: %llx\n", (ULONGLONG)Address);
                ErrCount++;
                return ANALYZE_DO_NOTHING;
            }
            //if (((ULONGLONG)Address & 0xffff) == 0x14BB)
            //    putchar(' '); // TEMP DEBUG
            // mov r, rsp
            if (vm_state == VM_MAJOR_STATE_INS_GROUP_NO_VM &&
                operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                operands[1].reg.value == ZYDIS_REGISTER_RSP &&
                operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER) {
                // 4c8bcc          mov     r,rsp
                //puts("VM Group Starts");
                //StackReg = operands[0].reg.value;
                vm_state = VM_MAJOR_STATE_INS_GROUP_STARTING;
                // get registery value
                StackAddr = IoReadRegister(operands[1].reg.value);
                //printf("VM Stack: 0x%llx, 0x%llx\n", (ULONGLONG)Address, StackAddr);
                //SetTraceMemory(StackAddr, 0x1000);
                StartVMInsGroup();
                VMCount = 0;
                vm_state = VM_MAJOR_STATE_INS_GROUP_STARTED;
            }
            // mov rsp, r
            //else if (vm_state == VM_MAJOR_STATE_INS_GROUP_STARTED &&
            //    operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
            //    operands[0].reg.value == ZYDIS_REGISTER_RSP &&
            //    operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER/* &&
            //    operands[1].reg.value == StackReg*/) {
            //    // 4c8bcc          mov     rsp,r
            //    //puts("VM Group Ends With Following Results:");
            //    //vm_state = VM_MAJOR_STATE_INS_GROUP_STOPPING;
            //    //puts("VM Group Analysis Completed:");
            //    //FinishVMInsGroup();
            //    VMCount = 0;
            //    //vm_state = VM_MAJOR_STATE_INS_GROUP_NO_VM;
            //}
            else if (vm_state == VM_MAJOR_STATE_INS_GROUP_STARTED) {
                // mov r, mem
                if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                    operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY) {
                    if (operands[1].mem.index == ZYDIS_REGISTER_NONE) {
                        ULONGLONG MemAddr = IoReadRegister(operands[1].mem.base) +
                            (operands[1].mem.disp.has_displacement ? operands[1].mem.disp.value : 0);
                        TraceLoadMem(ins_addr, operands[0].reg.value, MemAddr);
                    }
                    else {
                        ULONGLONG MemAddr = IoReadRegister(operands[1].mem.base) +
                            IoReadRegister(operands[1].mem.index) * operands[1].mem.scale +
                            (operands[1].mem.disp.has_displacement ? operands[1].mem.disp.value : 0);
                        TraceLoadMem(ins_addr, operands[0].reg.value, MemAddr);
                    }
                }
                // mov mem, r
                else if (operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                    operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER) {
                    if (operands[0].mem.index == ZYDIS_REGISTER_NONE) {
                        ULONGLONG MemAddr = IoReadRegister(operands[0].mem.base) +
                            (operands[0].mem.disp.has_displacement ? operands[0].mem.disp.value : 0);
                        TraceSaveMem(ins_addr, MemAddr, operands[1].reg.value);
                    }
                    else {
                        ULONGLONG MemAddr = IoReadRegister(operands[0].mem.base) +
                            IoReadRegister(operands[0].mem.index) * operands[0].mem.scale +
                            (operands[0].mem.disp.has_displacement ? operands[0].mem.disp.value : 0);
                        TraceSaveMem(ins_addr, MemAddr, operands[1].reg.value);
                    }
                }
                // mov r1, r2
                else if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                    operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER) {
                    TraceMovRR(ins_addr, operands[0].reg.value, operands[1].reg.value);
                }
            }
        }
    }
    else if (vm_state == VM_MAJOR_STATE_INS_GROUP_STARTED) {
        // push
        if (zins.mnemonic == ZYDIS_MNEMONIC_PUSH) {
            if (zins.operand_count >= 1) {
                ZydisDecodedOperand operands[5] = { 0 };
                ZydisDecoderDecodeOperands(&g_decoder, &zctx, &zins, operands, zins.operand_count);
                if (!ZYAN_SUCCESS(ZStatus)) {
                    PRINT_DECODE_ERROR("Decoder Error Address: %llx\n", (ULONGLONG)Address);
                    ErrCount++;
                    return ANALYZE_DO_NOTHING;
                }
                if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER) {
                    unsigned long long mem_addr = IoReadRegister(ZYDIS_REGISTER_RSP);
                    TraceSaveMem(ins_addr, mem_addr, operands[0].reg.value);
                }
            }
        }
        // pop
        else if (zins.mnemonic == ZYDIS_MNEMONIC_POP) {
            if (zins.operand_count >= 1) {
                ZydisDecodedOperand operands[5] = { 0 };
                ZydisDecoderDecodeOperands(&g_decoder, &zctx, &zins, operands, zins.operand_count);
                if (!ZYAN_SUCCESS(ZStatus)) {
                    PRINT_DECODE_ERROR("Decoder Error Address: %llx\n", (ULONGLONG)Address);
                    ErrCount++;
                    return ANALYZE_DO_NOTHING;
                }
                if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER) {
                    unsigned long long mem_addr = IoReadRegister(ZYDIS_REGISTER_RSP);
                    TraceLoadMem(ins_addr, operands[0].reg.value, mem_addr);
                }
            }
        }
        // not
        if (zins.mnemonic == ZYDIS_MNEMONIC_NOT) {
            if (zins.operand_count >= 1) {
                ZydisDecodedOperand operands[5] = { 0 };
                ZydisDecoderDecodeOperands(&g_decoder, &zctx, &zins, operands, zins.operand_count);
                if (!ZYAN_SUCCESS(ZStatus)) {
                    PRINT_DECODE_ERROR("Decoder Error Address: %llx\n", (ULONGLONG)Address);
                    ErrCount++;
                    return ANALYZE_DO_NOTHING;
                }
                if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER) {
                    TraceUnitaryArithmetic(ins_addr, ZYDIS_MNEMONIC_NOT, operands[0].reg.value);
                }
            }
        }
        // neg
        if (zins.mnemonic == ZYDIS_MNEMONIC_NEG) {
            if (zins.operand_count >= 1) {
                ZydisDecodedOperand operands[5] = { 0 };
                ZydisDecoderDecodeOperands(&g_decoder, &zctx, &zins, operands, zins.operand_count);
                if (!ZYAN_SUCCESS(ZStatus)) {
                    PRINT_DECODE_ERROR("Decoder Error Address: %llx\n", (ULONGLONG)Address);
                    ErrCount++;
                    return ANALYZE_DO_NOTHING;
                }
                if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER) {
                    TraceUnitaryArithmetic(ins_addr, ZYDIS_MNEMONIC_NEG, operands[0].reg.value);
                }
            }
        }
        // add, and, or, xor, sub
        else if (zins.mnemonic == ZYDIS_MNEMONIC_ADD ||
            zins.mnemonic == ZYDIS_MNEMONIC_AND ||
            zins.mnemonic == ZYDIS_MNEMONIC_OR ||
            zins.mnemonic == ZYDIS_MNEMONIC_XOR ||
            zins.mnemonic == ZYDIS_MNEMONIC_SUB) {
            if (zins.operand_count >= 2) {
                ZydisDecodedOperand operands[5] = { 0 };
                ZydisDecoderDecodeOperands(&g_decoder, &zctx, &zins, operands, zins.operand_count);
                if (!ZYAN_SUCCESS(ZStatus)) {
                    PRINT_DECODE_ERROR("Decoder Error Address: %llx\n", (ULONGLONG)Address);
                    ErrCount++;
                    return ANALYZE_DO_NOTHING;
                }
                if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER) {
                    if (operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER) {
                        TraceBinaryArithmeticRR(ins_addr, zins.mnemonic, operands[0].reg.value, operands[1].reg.value);
                    }
                    else if (operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
                        TraceBinaryArithmeticRR(ins_addr, zins.mnemonic, operands[0].reg.value, operands[1].imm.value.u);
                    }
                }
            }
        }
        // lea
        else if (zins.mnemonic == ZYDIS_MNEMONIC_LEA) {
            if (zins.operand_count >= 2) {
                ZydisDecodedOperand operands[5] = { 0 };
                ZydisDecoderDecodeOperands(&g_decoder, &zctx, &zins, operands, zins.operand_count);
                if (!ZYAN_SUCCESS(ZStatus)) {
                    PRINT_DECODE_ERROR("Decoder Error Address: %llx\n", (ULONGLONG)Address);
                    ErrCount++;
                    return ANALYZE_DO_NOTHING;
                }
                // mov immeidate value to register or addition
                if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                    operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY) {
                    // reg = base + index * scale + disp
                    if (operands[1].mem.index == ZYDIS_REGISTER_NONE) { // index == 0
                        if (operands[0].reg.value == operands[1].mem.base) { // reg == base, index == 0
                            // reg = reg + disp
                            if (operands[1].mem.disp.has_displacement)
                                TraceBinaryArithmeticRI(ins_addr, ZYDIS_MNEMONIC_ADD, operands[0].reg.value, operands[1].mem.disp.value);
                        }
                        else { // reg != base, index == 0
                            // reg = base + disp
                            TraceMovRR(ins_addr, operands[0].reg.value, operands[1].mem.base);
                            if (operands[1].mem.disp.has_displacement)
                                TraceBinaryArithmeticRI(ins_addr, ZYDIS_MNEMONIC_ADD, operands[0].reg.value, operands[1].mem.disp.value);
                        }
                    }
                    else { // index != 0
                        if (operands[0].reg.value == operands[1].mem.base) { // value == base, index != 0
                            if (operands[0].reg.value == operands[1].mem.index) { // value == index, value == base, index != 0
                                // reg = reg * (1 + scale) + disp
                                TraceMulFactor(ins_addr, operands[0].reg.value, 1 + operands[1].mem.scale);
                                if (operands[1].mem.disp.has_displacement)
                                    TraceBinaryArithmeticRI(ins_addr, ZYDIS_MNEMONIC_ADD, operands[0].reg.value, operands[1].mem.disp.value);
                            }
                            else { // value != index, value == base, disp != 0, index != 0
                                // reg = reg + index * scale + disp
                                if (operands[1].mem.scale != 1)
                                    TraceMulFactor(ins_addr, operands[1].mem.index, operands[1].mem.scale);
                                TraceBinaryArithmeticRR(ins_addr, ZYDIS_MNEMONIC_ADD, operands[0].reg.value, operands[1].mem.index);
                                if (operands[1].mem.disp.has_displacement)
                                    TraceBinaryArithmeticRI(ins_addr, ZYDIS_MNEMONIC_ADD, operands[0].reg.value, operands[1].mem.disp.value);
                            }
                        }
                        else { // value != base, index != 0
                            if (operands[0].reg.value == operands[1].mem.index) { // value == index, value != base, index != 0
                                // reg = base + reg * scale + disp
                                if (operands[1].mem.scale != 1)
                                    TraceMulFactor(ins_addr, operands[0].reg.value, operands[1].mem.scale);
                                TraceBinaryArithmeticRR(ins_addr, ZYDIS_MNEMONIC_ADD, operands[0].reg.value, operands[1].mem.base);
                                if (operands[1].mem.disp.has_displacement)
                                    TraceBinaryArithmeticRI(ins_addr, ZYDIS_MNEMONIC_ADD, operands[0].reg.value, operands[1].mem.disp.value);
                            }
                            else { // value != index, value != base, index != 0
                                // reg = base + index * scale + disp
                                TraceMovRR(ins_addr, operands[0].reg.value, operands[1].mem.base);
                                if (operands[1].mem.scale != 1)
                                    TraceMulFactor(ins_addr, operands[1].mem.index, operands[1].mem.scale);
                                TraceBinaryArithmeticRR(ins_addr, ZYDIS_MNEMONIC_ADD, operands[0].reg.value, operands[1].mem.index);
                                if (operands[1].mem.disp.has_displacement)
                                    TraceBinaryArithmeticRI(ins_addr, ZYDIS_MNEMONIC_ADD, operands[0].reg.value, operands[1].mem.disp.value);
                            }
                        }
                    }
                }
            }
        }
        // shl
        else if (zins.mnemonic == ZYDIS_MNEMONIC_SHL) {
            if (zins.operand_count >= 2) {
                ZydisDecodedOperand operands[5] = { 0 };
                ZydisDecoderDecodeOperands(&g_decoder, &zctx, &zins, operands, zins.operand_count);
                if (!ZYAN_SUCCESS(ZStatus)) {
                    PRINT_DECODE_ERROR("Decoder Error Address: %llx\n", (ULONGLONG)Address);
                    ErrCount++;
                    return ANALYZE_DO_NOTHING;
                }
                if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                    operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
                    if (operands[1].imm.value.u != 0) {
                        TraceMulFactor(ins_addr, operands[0].reg.value, (double)(2ull << operands[1].imm.value.u));
                    }
                }
            }
        }
        // shr
        else if (zins.mnemonic == ZYDIS_MNEMONIC_SHR) {
            if (zins.operand_count >= 2) {
                ZydisDecodedOperand operands[5] = { 0 };
                ZydisDecoderDecodeOperands(&g_decoder, &zctx, &zins, operands, zins.operand_count);
                if (!ZYAN_SUCCESS(ZStatus)) {
                    PRINT_DECODE_ERROR("Decoder Error Address: %llx\n", (ULONGLONG)Address);
                    ErrCount++;
                    return ANALYZE_DO_NOTHING;
                }
                if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                    operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
                    if (operands[1].imm.value.u != 0) {
                        TraceMulFactor(ins_addr, operands[0].reg.value, 1.0 / (2ull << operands[1].imm.value.u));
                    }
                }
            }
        }
    }
    static int TraceNext = 0;
    if (TraceNext > 0) {
        TraceNext--;
        //printf("Trace: 0x%llx\n", Address);
    }
    if (Hit) {
        //printf("Trace: 0x%llx\n", Address);
        CONTEXT ctx = { 0 };
        ctx.ContextFlags = CONTEXT_ALL;
        GetThreadContext(IoGetThreadHandle(), &ctx);
        printf("[Call Boundary] 0x%llx\n", ins_addr);
        char Buf[1024];
        IoReadProcessMemory(ctx.Rcx, Buf, sizeof(Buf));
        printf("p1: %s\n", Buf);
        IoReadProcessMemory(ctx.Rdx, Buf, sizeof(Buf));
        printf("p2: %s\n", Buf);
        IoReadProcessMemory(ctx.R8, Buf, sizeof(Buf));
        printf("p3: %s\n", Buf);
        IoReadProcessMemory(ctx.R9, Buf, sizeof(Buf));
        printf("p4: %s\n", Buf);
        TraceNext = 1;
        getchar();
    }
    return ANALYZE_DO_NOTHING;
}

int BpCallbackCipherStartUnprotected(unsigned char* address, void* user_data) {
    bool ret = StartVMInsGroup();
    if (ret) {
        return BREAKPOINT_CALLBACK_RETURN_SINGLE_STEP;
    }
    else {
        printf("BpCallbackCipherStartUnprotected Error: Failed to start vm ins group analysis!\n");
        return BREAKPOINT_CALLBACK_RETURN_ABORT;
    }
}

static ULONGLONG g_ucrtbase = 0;
DWORD ProcessDebugEvent(DEBUG_EVENT debugEvent) {
    // Call the correct function depending on what the event code is
    switch (debugEvent.dwDebugEventCode) {
    case EXCEPTION_DEBUG_EVENT: // 1: Called whenever any exception occurs in the process being debugged
        //ProcessException(debug_event);
        //puts("EXCEPTION_DEBUG_EVENT");
        //printf("0x%llx\n", (char*)debugEvent.u.Exception.ExceptionRecord.ExceptionAddress);
        OnDebugEvent((unsigned char*)debugEvent.u.Exception.ExceptionRecord.ExceptionAddress);
        break;
    case CREATE_PROCESS_DEBUG_EVENT: // 2: Called when the debuggee process is first created
    {
        printf("thread %llx\n", (ULONGLONG)debugEvent.u.CreateProcessInfo.hThread);
        SetDbgCreateProcessInfo(
            debugEvent.u.CreateProcessInfo.hProcess,
            debugEvent.u.CreateProcessInfo.hThread,
            (unsigned char*)debugEvent.u.CreateProcessInfo.lpBaseOfImage,
            (unsigned char*)debugEvent.u.CreateProcessInfo.lpStartAddress);
        LoadAesConfig();
        break;
    }
    case OUTPUT_DEBUG_STRING_EVENT: // Called when a string is sent to the debugger for display
        //OutputString(debug_event);
        break;
    case EXIT_PROCESS_DEBUG_EVENT: // Called when the debuggee process exits
        //ExitDebuggeeProcess(debug_event);
        break;
    case LOAD_DLL_DEBUG_EVENT: // 6
    {
        WCHAR Buf[MAX_PATH] = { 0 };
        ULONGLONG ullLength = 0;
        GetFinalPathNameByHandle(debugEvent.u.LoadDll.hFile, Buf, MAX_PATH, FILE_NAME_OPENED);
        wprintf(L"Load DLL: %s\n", Buf + 4);
        if (wcscmp(Buf + 4, L"C:\\Windows\\System32\\ucrtbase.dll") == 0) {
            g_ucrtbase = (ULONGLONG)debugEvent.u.LoadDll.lpBaseOfDll;
            //0:000> u ucrtbase + 00080210  
            //ucrtbase!fgetchar:,
            //00007ffd`dd1a0210 488d0d89f20700  lea     rcx, [ucrtbase!iob(00007ffd`dd21f4a0)]
            //00007ffd`dd1a0217 e9547af8ff      jmp     ucrtbase!fgetc(00007ffd`dd127c70)
            // dumpbin /exports C:\Windows\System32\ucrtbase.dll
            //ULONGLONG ucrtbase_getchar_offset = 0x00080210;
            //ULONGLONG ucrtbase_getchar_offset = 0x000A0C60;
            //ULONGLONG ucrtbase_base = (ULONGLONG)GetModuleHandle(L"ucrtbase.dll"); // ucrtbased.dll for debug version
            //if (ucrtbase_base > 0) {
            //    ucrtbase_getchar_offset = (ULONGLONG)GetProcAddress((HMODULE)ucrtbase_base, "getchar") - ucrtbase_base;
            //    AddBreakpoint((unsigned char*)g_ucrtbase + ucrtbase_getchar_offset, BpCallbackStartVM, NULL); // ucrtbase!getchar
            //}
        }
        break;
    }
    }
    return DBG_CONTINUE;
}

int BpCallbackCipherBeginVmpInline(unsigned char* address, void* user_data) {
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

int BpCallbackCipherEndUnprotected(unsigned char* address, void* user_data) {
    FinishVMInsGroupUnprotected(address, user_data);
    return BREAKPOINT_CALLBACK_RETURN_CONTINUE_NO_SINGLE_STEP;
}

int BpCallbackCopyEncryptedBlockVmpInline(unsigned char* address, void* user_data) {
    FinishVMInsGroupVmpInline(address, user_data);
    return BREAKPOINT_CALLBACK_RETURN_CONTINUE_NO_SINGLE_STEP;
}

void CbTraceCallback(unsigned char* address, unsigned char* bp_address, void* bp_user_data) {
    AnalyzeTrace((unsigned long long)address);
}

void LoadAesConfig() {
#ifdef TEST_VMP_INLINE
    // VMProtect on inline sensitive functions
    // call VMProtectBegin("Cipher"), by vmp init pattern recognition
    AddBreakpoint(IoGetImageBase() + 0x1a186, BpCallbackCipherBeginVmpInline, NULL, CbTraceCallback);
    // copy encrypted block, recognizing memcpy manually
    AddBreakpoint(IoGetImageBase() + 0x3b6c,  BpCallbackCopyEncryptedBlockVmpInline, NULL, NULL);
#else
    // unprotected for debugging
    AddBreakpoint(IoGetImageBase() + 0x31b2, BpCallbackCipherStartUnprotected, NULL, CbTraceCallback);
    AddBreakpoint(IoGetImageBase() + 0x2e9c, BpCallbackCipherEndUnprotected, NULL, NULL);
#endif
}

int main(int argc, char** argv) {
    //ha_show_rev_key_128();
    // Init
    ZyanStatus ZStatus = ZydisDecoderInit(&g_decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_MAX_VALUE);
    if (!ZYAN_SUCCESS(ZStatus)) {
        puts("Decoder Error");
        getchar();
        return 0;
    }
    bool ret = InitTrace();
    if (!ret) {
        puts("Init Tracor Error");
        getchar();
        return 0;
    }
    STARTUPINFO si = { 0 }; // Contains startup information about the debugged process
    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi = { 0 };

    // Create the process to debug
#ifdef TEST_VMP_INLINE
    WCHAR szApp[MAX_PATH] = { L"protected.vmp.exe" };
#else
    WCHAR szApp[MAX_PATH] = { L"protected.exe" };
#endif
    BOOL bRet = CreateProcess(szApp, NULL, NULL, NULL, 0, DEBUG_ONLY_THIS_PROCESS, NULL, NULL, &si, &pi);
    if (!bRet) {
        puts("Cannot open exe!");
        getchar();
        return 0;
    }
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    wprintf(L"Run %s\n", szApp);

    // Process debugging events
    DEBUG_EVENT debug_event = { 0 };
    while (true) {
        if (!WaitForDebugEvent(&debug_event, INFINITE)) {
            break; // Break the loop if the function fails
        }
        DWORD dwContinueStatus = ProcessDebugEvent(debug_event); // User-defined function that will process the event
        ContinueDebugEvent(debug_event.dwProcessId, debug_event.dwThreadId, dwContinueStatus); // Continue execution
    }

    // Exit the debugger
    printf("Debugger will now exit.\n");
    return 0;
}
