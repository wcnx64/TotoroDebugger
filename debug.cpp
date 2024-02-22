#include <vector>
#include <windows.h>
#include "debug.h"
#include "io.h"
#define ZYDIS_STATIC_BUILD
extern "C" {
#include "zydis/Zydis.h"
}
#include "InstructionTrace.h"
#include "ImagePatcher.h"

//#define PRINT_DECODE_ERROR printf
#define PRINT_DECODE_ERROR(...)

// the bp_addr and user_data are the ones of the associated breakpoint
typedef struct TDbgSingleStepTracor {
    TDbgSingleStepTraceCallback callback;
    uint8_t*                    bp_addr;
    void*                       bp_user_data;
} TDbgSingleStepTracor, *PTDbgSingleStepTracor;

typedef struct TDbgBreakpoint {
    uint8_t*               addr;
    bool                   is_relative_to_base;
    uint8_t                backup_byte;
    TDbgBreakpointCallback callback;
    void*                  user_data;
    bool                   has_trace;
    TDbgSingleStepTracor   trace;
} TDbgBreakpoint, *PTDbgBreakpoint;

int TDbgAnalyzeTrace(uint64_t ins_addr, uint64_t from_breakpoint);
DWORD TDbgProcessDebugEvent(DEBUG_EVENT debugEvent);


// globals
static ZydisDecoder g_decoder;
static std::vector<TDbgBreakpoint> g_breakpoints;
static bool g_do_patch = false; // do patch while analyzing
static bool g_save_patch = false; // save patch result after analyzing

bool TDbgInit() {
    // zydis disassembler
    ZyanStatus ZStatus = ZydisDecoderInit(&g_decoder,
        ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_MAX_VALUE);
    if (!ZYAN_SUCCESS(ZStatus)) {
        return false;
    }
    // trace module
    bool ret = InitTrace();
    if (!ret) {
        return false;
    }
    // all passed
    return true;
}

void TDbgUninit() {
    ;
}

bool TDbgCreateProcessWithDebugFlag(const WCHAR* app_name, WCHAR* cmd_line) {
    STARTUPINFO si = { 0 };
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi = { 0 };
    // create process with default settings except the creation flag
    BOOL ret = CreateProcess(app_name, cmd_line, NULL, NULL, 0,
        DEBUG_ONLY_THIS_PROCESS, NULL, NULL, &si, &pi);
    if (!ret) {
        // failed to create, maybe the file is not found or occupied
        return false;
    }
    // release resources
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return true;
}

bool TDbgProcessDebuggingEvents() {
    DEBUG_EVENT debug_event = { 0 };
    while (true) {
        if (!WaitForDebugEvent(&debug_event, INFINITE)) {
            break; // time out
        }
        DWORD status = TDbgProcessDebugEvent(debug_event);
        if (status == DBG_TERMINATE_PROCESS) { // the debuggee process is terminated
            break;
        }
        // continue execution
        ContinueDebugEvent(debug_event.dwProcessId, debug_event.dwThreadId, status);
    }
    return true;
}

bool TDbgDebugProcess(const WCHAR* app_name, WCHAR* cmd_line) {
    bool next_loop = false;
    do {
        // open the app
        bool ret = TDbgCreateProcessWithDebugFlag(app_name, cmd_line);
        if (!ret)
            return ret;
        // register the app
        IoSetAppFileName(app_name);
        // debug the app
        ret = TDbgProcessDebuggingEvents();
        // stop the app if needed
        // post debug jobs, e.g. patch the program
        next_loop = false;
    } while (next_loop);
    return true;
}

bool TDbgLoadConfig(const WCHAR* config_file_name) {
    return true;
}

bool TDbgLoadConfigAndRun(const WCHAR* config_file_name) {
    bool ret = TDbgLoadConfig(config_file_name);
    if (!ret) {
        return false;
    }
    // start debugging with parameters in config file.
    // it may repeat multiple times.
    ret = TDbgDebugProcess(nullptr, nullptr);
    if (!ret) {
        return false;
    }
    return true;
}

// set if do patch while analyzing. return old value
bool TDbgSetPatch(bool patch) {
    bool old_do_path = g_do_patch;
    g_do_patch = patch;
    return old_do_path;
}

// set if save patch result after analyzing. return old value
bool TDbgSetSavePatch(bool save) {
    bool old_save_patch = g_save_patch;
    g_save_patch = save;
    return old_save_patch;
}

// the addr is the relative address from the image base
bool TDbgAddBreakpoint(
    uint64_t                    addr,
    TDbgBreakpointCallback      callback,
    void*                       user_data,
    TDbgSingleStepTraceCallback trace_callback) {
    TDbgBreakpoint bp = { 0 };
    bp.is_relative_to_base = (IoGetImageBase() == 0) ? true : false;
    bp.addr = IoGetImageBase() + addr;
    bp.callback = callback;
    bp.user_data = user_data;
    if (trace_callback) {
        bp.has_trace = true;
        bp.trace.callback = trace_callback;
        bp.trace.bp_addr = (uint8_t*)addr;
        bp.trace.bp_user_data = user_data;
    }
    else {
        bp.has_trace = false;
    }
    // set int 3 into machine codes
    if (!bp.is_relative_to_base) {
        IoReadProcessMemory((uint64_t)addr, &bp.backup_byte, 1);
        uint8_t cc = 0xcc;
        IoWriteProcessMemory((uint64_t)addr, &cc, 1);
    }
    g_breakpoints.push_back(bp);
    return true;
}

// delete breakpoint with addr as key
// the addr is an updated address, which is the real memory address
void TDbgDeleteBreakpoint(uint8_t* addr, void* user_contect) {
    for (auto i = g_breakpoints.begin(); i != g_breakpoints.end();) {
        if (i->addr == addr) {
            i = g_breakpoints.erase(i);
        }
        else {
            i++;
        }
    }
}

// update breakpoints with process info
void TDbgUpdateBreakpoints() {
    for (auto i = g_breakpoints.begin(); i != g_breakpoints.end(); i++) {
        if (i->is_relative_to_base) {
            i->addr = IoGetImageBase() + (uint64_t)i->addr;
            i->is_relative_to_base = false;
            // set int 3 into machine codes
            IoReadProcessMemory((uint64_t)i->addr, &i->backup_byte, 1);
            uint8_t cc = 0xcc;
            IoWriteProcessMemory((uint64_t)i->addr, &cc, 1);
        }
    }
}

bool TDbgOnBreakpoint(
    TDbgBreakpoint&        bp,
    bool                   from_breakpoint,
    bool&                  single_step,
    PTDbgSingleStepTracor& tracor,
    PTDbgBreakpoint&       breakpoint_to_recover,
    bool&                  erase,
    bool&                  abort) {
    if (bp.callback) {
        int callback_ret = bp.callback(bp.addr, bp.user_data);
        int callback_ret_no_flag = callback_ret & tcr::NOFLAG_MASK;
        if (callback_ret_no_flag == tcr::REPEAT) {
            single_step = true;
            tracor = &bp.trace;
            return true;
        }
        else {
            // set breakpoint to recover
            breakpoint_to_recover = &bp;
            // get thread context
            CONTEXT ctx;
            ctx.ContextFlags = CONTEXT_ALL;
            GetThreadContext(IoGetThreadHandle(), &ctx);
            // If reach here because of single step tracing, Rip is the breakpoint.
            // If reach here because of "int 3",
            // the next instruction of "int 3" is Rip, so Rip - 1 is the breakpoint
            if (from_breakpoint)
                ctx.Rip--;
            // recover the original code
            IoWriteProcessMemory((ULONGLONG)bp.addr, &bp.backup_byte, 1);
            // handle return values
            bool ret = true;
            if (callback_ret_no_flag == tcr::CONTINUE) {
            }
            else if (callback_ret_no_flag == tcr::ABORT) {
                breakpoint_to_recover = nullptr;
                g_breakpoints.clear();
            }
            else {
                ret = false;
            }
            if (ret) {
                // handle return flags
                if (callback_ret & tcr::ENTER_SINGLE_STEP) {
                    ctx.EFlags |= 0x0100; // TF
                    single_step = true;
                    tracor = &bp.trace;
                }
                if (callback_ret & tcr::EXIT_SINGLE_STEP) {
                    ctx.EFlags &= ~0x0100; // TF
                    single_step = false;
                }
                if (callback_ret & tcr::REMOVE_BREAKPOINT) {
                    breakpoint_to_recover = nullptr;
                    erase = true;
                }
            }
            ctx.ContextFlags = CONTEXT_ALL;
            SetThreadContext(IoGetThreadHandle(), &ctx);
            return ret;
        }
    }
    return false;
}

void TDbgOnDebugEvent(uint8_t* addr) {
    static bool is_aborted = false;
    static PTDbgBreakpoint breakpoint_to_recover = nullptr;
    static bool is_being_traced = false;
    static PTDbgSingleStepTracor tracor = nullptr;
    if (is_aborted) return; // aborted
    // Recover breakpoint, write int 3 to enable the breakpoint again
    // When a snapshot was restored and register rip was set to a breakpoint,
    // breakpoint_to_recover->addr == addr would happen in the next single step.
    if (breakpoint_to_recover && breakpoint_to_recover->addr != addr) {
        uint8_t cc = 0xcc;
        IoWriteProcessMemory((uint64_t)breakpoint_to_recover->addr, &cc, 1);
        breakpoint_to_recover = nullptr;
    }
    // get thread context
    CONTEXT ctx = { 0 };
    ctx.ContextFlags = CONTEXT_ALL;
    GetThreadContext(IoGetThreadHandle(), &ctx);
    bool from_breakpoint = (ctx.Rip == (uint64_t)addr + 1);
    // continue single stepping
    if (is_being_traced) {
        ctx.EFlags |= 0x0100; // TF
        SetThreadContext(IoGetThreadHandle(), &ctx);
        // on single step tracing
        if (tracor) {
            if (tracor->callback == nullptr ||
                !tracor->callback(addr, tracor->bp_addr, tracor->bp_user_data)) {
                TDbgAnalyzeTrace((uint64_t)addr, from_breakpoint);
            }
        }
    }
    // multiple callbacks can be set on an address
    for (std::vector<TDbgBreakpoint>::iterator i = g_breakpoints.begin(); i != g_breakpoints.end();) {
        if (i->addr == addr) { // hit a breakpoint
            printf("Breakpoint Hit: 0x%llx\n", (ULONGLONG)addr);
            bool erase = false;
            // process breakpoint hit
            bool bp_ret = TDbgOnBreakpoint(*i, from_breakpoint, is_being_traced, tracor,
                breakpoint_to_recover, erase, is_aborted);
            if (bp_ret) {
                if (erase) { // remove the breakpoint
                    i = g_breakpoints.erase(i);
                    continue;
                }
                if (is_aborted) break; // abort the debugging
            }
        }
        i++; // next breakpoint
    }
    if (is_aborted)
        g_breakpoints.clear();
}

DWORD TDbgProcessDebugEvent(DEBUG_EVENT debugEvent) {
    switch (debugEvent.dwDebugEventCode) {
    case EXCEPTION_DEBUG_EVENT: // on exceptions including int 3, single step tracing ...
        TDbgOnDebugEvent((uint8_t*)debugEvent.u.Exception.ExceptionRecord.ExceptionAddress);
        break;
    case CREATE_PROCESS_DEBUG_EVENT: // on process creation
    {
        // set globals
        IoSetCreateProcessInfo(
            debugEvent.u.CreateProcessInfo.hProcess,
            debugEvent.u.CreateProcessInfo.hThread,
            (uint8_t*)debugEvent.u.CreateProcessInfo.lpBaseOfImage,
            (uint8_t*)debugEvent.u.CreateProcessInfo.lpStartAddress);
        // update breakpoints with process info
        TDbgUpdateBreakpoints();
        break;
    }
    case EXIT_PROCESS_DEBUG_EVENT:
        return DBG_TERMINATE_PROCESS;
    case LOAD_DLL_DEBUG_EVENT: // 6
    {
        //WCHAR buf[MAX_PATH] = { 0 };
        //GetFinalPathNameByHandle(debugEvent.u.LoadDll.hFile, buf, MAX_PATH, FILE_NAME_OPENED);
        break;
    }
    }
    return DBG_CONTINUE;
}

inline uint64_t GetMemoryAddress(ZydisDecodedOperand operand) {
    uint64_t mem_addr = 0;
    if (operand.type == ZYDIS_OPERAND_TYPE_MEMORY) {
        if (operand.mem.index == ZYDIS_REGISTER_NONE) {
            mem_addr = IoReadRegister(operand.mem.base) +
                (operand.mem.disp.has_displacement ? operand.mem.disp.value : 0);
        }
        else {
            mem_addr = IoReadRegister(operand.mem.base) +
                IoReadRegister(operand.mem.index) * operand.mem.scale +
                (operand.mem.disp.has_displacement ? operand.mem.disp.value : 0);
        }
    }
    return mem_addr;
}

#define ANALYZE_DO_NOTHING 0
int TDbgAnalyzeTrace(uint64_t ins_addr, uint64_t from_breakpoint) {
    uint8_t ins_buf[16] = { 0 };
    IoReadProcessMemory(ins_addr, ins_buf, sizeof(ins_buf));
#define VM_MAJOR_STATE_INS_GROUP_NO_VM    0
#define VM_MAJOR_STATE_INS_GROUP_STARTING 1
#define VM_MAJOR_STATE_INS_GROUP_STARTED  2
#define VM_MAJOR_STATE_INS_GROUP_STOPPING 3
    static int              vm_state = VM_MAJOR_STATE_INS_GROUP_NO_VM;
    ZydisDecoderContext     zctx = { 0 };
    ZydisDecodedInstruction zins;
    ZyanStatus ZStatus = ZydisDecoderDecodeInstruction(&g_decoder, &zctx,
        ins_buf, sizeof(ins_buf), &zins);
    if (!ZYAN_SUCCESS(ZStatus)) {
        PRINT_DECODE_ERROR("Decoder Error Address: %llx\n", (ULONGLONG)ins_addr);
        return ANALYZE_DO_NOTHING;
    }
    // register assembly instruction to vm instruction
    ZydisDecodedOperand operands[10] = { 0 };
    ZydisDecoderDecodeOperands(&g_decoder, &zctx, &zins, operands, zins.operand_count);
    if (!ZYAN_SUCCESS(ZStatus)) {
        TraceCommon(ins_addr, true, 0, 0, ins_buf, zins.length);
        return ANALYZE_DO_NOTHING;
    }
    else {
        if (zins.mnemonic == ZYDIS_MNEMONIC_RET) {
            TraceCommon(ins_addr, tvm::INS_FLAG_CONTROL_FLOW | tvm::INS_FLAG_RET, 0, 0, ins_buf, zins.length);
            FinishVmIns(ins_addr);
            StartVmIns(ins_addr);
            // printf("Instruction Address: 0x%llx\n", ins_addr);
            return ANALYZE_DO_NOTHING;
        }
        else if (zins.mnemonic == ZYDIS_MNEMONIC_INT3) {
            return ANALYZE_DO_NOTHING;
        }
        else if (zins.mnemonic == ZYDIS_MNEMONIC_NOP) {
            return ANALYZE_DO_NOTHING;
        }
        else if ((zins.mnemonic >= ZYDIS_MNEMONIC_JB && zins.mnemonic <= ZYDIS_MNEMONIC_JZ) ||
            zins.mnemonic == ZYDIS_MNEMONIC_CALL) {
            uint32_t flag = 0;
            uint64_t des_mem_addr = 0;
            if (zins.mnemonic == ZYDIS_MNEMONIC_JMP) { // most probably
                flag = tvm::INS_FLAG_CONTROL_FLOW | tvm::INS_FLAG_JMP;
            }
            else if (zins.mnemonic == ZYDIS_MNEMONIC_CALL) {
                flag = tvm::INS_FLAG_CONTROL_FLOW | tvm::INS_FLAG_CALL;
            }
            else {
                flag = tvm::INS_FLAG_CONTROL_FLOW | tvm::INS_FLAG_JMP | tvm::INS_FLAG_CONDITIONAL;
            }
            if (zins.operand_count >= 2) { // jmp imm: imm, rip. jmp reg: reg, rip. jmp mem: mem, rip.
                if (operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
                    des_mem_addr = ins_addr + zins.length + operands[0].imm.value.u;
                }
                else if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER) {
                    flag |= tvm::INS_FLAG_WITH_REG;
                    des_mem_addr = IoReadRegister(operands[0].reg.value);
                }
                else if (operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY) {
                    flag |= tvm::INS_FLAG_WITH_MEM;
                    des_mem_addr = GetMemoryAddress(operands[0]);
                }
            }
            TraceCommon(ins_addr, flag, des_mem_addr, ins_addr, ins_buf, zins.length);
        }
        else if (zins.mnemonic == ZYDIS_MNEMONIC_PUSH) {
            uint64_t mem_addr = IoReadRegister(ZYDIS_REGISTER_RSP);
            TraceCommon(ins_addr, tvm::INS_FLAG_PUSH, mem_addr, 0, ins_buf, zins.length);
        }
        else if (zins.operand_count == 1) {
            TraceCommon(ins_addr, 0, 0, 0, ins_buf, zins.length);
        }
        else if (zins.operand_count >= 2) {
            uint64_t des_mem_addr = 0;
            uint64_t src_mem_addr = 0;
            if (operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY) {
                des_mem_addr = GetMemoryAddress(operands[0]);
            }
            if (operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY) {
                src_mem_addr = GetMemoryAddress(operands[1]);
            }
            TraceCommon(ins_addr, 0, des_mem_addr, src_mem_addr, ins_buf, zins.length);
        }
    }
    // mov
    if (zins.mnemonic == ZYDIS_MNEMONIC_MOV ||
        zins.mnemonic == ZYDIS_MNEMONIC_MOVZX) {
        if (zins.operand_count >= 2) {
            // mov r, rsp
            if (vm_state == VM_MAJOR_STATE_INS_GROUP_NO_VM &&
                operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                operands[1].reg.value == ZYDIS_REGISTER_RSP &&
                operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER) {
                // 4c8bcc          mov     r,rsp
                //puts("VM Group Starts");
                //StackReg = operands[0].reg.value;
                vm_state = VM_MAJOR_STATE_INS_GROUP_STARTING;
                // get stack reg and address
                uint32_t stack_reg = operands[1].reg.value;
                uint64_t stack_addr = IoReadRegister(operands[1].reg.value);
                SetStackRegisterAndAddr(stack_reg, stack_addr);
                //printf("VM Stack: 0x%llx, 0x%llx\n", (ULONGLONG)Address, stack_addr);
                vm_state = VM_MAJOR_STATE_INS_GROUP_STARTED;
            }
            else if (vm_state == VM_MAJOR_STATE_INS_GROUP_STARTED) {
                // mov r, mem
                if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                    operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY) {
                    TraceLoadMem(ins_addr, operands[0].reg.value, GetMemoryAddress(operands[1]));
                }
                // mov mem, r
                else if (operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                    operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER) {
                    TraceSaveMemEx(ins_addr, GetMemoryAddress(operands[0]), operands[1].reg.value,
                        operands[0].mem.base,
                        operands[0].mem.index == ZYDIS_REGISTER_NONE ? false : true,
                        operands[0].mem.index, operands[0].mem.scale,
                        operands[0].mem.disp.has_displacement, operands[0].mem.disp.value);
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
                if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER) {
                    uint64_t mem_addr = IoReadRegister(ZYDIS_REGISTER_RSP);
                    TraceSaveMem(ins_addr, mem_addr, operands[0].reg.value);
                }
            }
        }
        // pop
        else if (zins.mnemonic == ZYDIS_MNEMONIC_POP) {
            if (zins.operand_count >= 1) {
                if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER) {
                    uint64_t mem_addr = IoReadRegister(ZYDIS_REGISTER_RSP);
                    TraceLoadMem(ins_addr, operands[0].reg.value, mem_addr);
                }
            }
        }
        // not
        if (zins.mnemonic == ZYDIS_MNEMONIC_NOT) {
            if (zins.operand_count >= 1) {
                if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER) {
                    TraceUnitaryArithmetic(ins_addr, ZYDIS_MNEMONIC_NOT, operands[0].reg.value);
                }
            }
        }
        // neg
        if (zins.mnemonic == ZYDIS_MNEMONIC_NEG) {
            if (zins.operand_count >= 1) {
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
                if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER) {
                    if (operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER) {
                        TraceBinaryArithmeticRR(ins_addr, zins.mnemonic, operands[0].reg.value, operands[1].reg.value);
                    }
                    else if (operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
                        TraceBinaryArithmeticRI(ins_addr, zins.mnemonic, operands[0].reg.value, operands[1].imm.value.u);
                    }
                }
            }
        }
        // lea
        else if (zins.mnemonic == ZYDIS_MNEMONIC_LEA) {
            if (zins.operand_count >= 2) {
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
                if (operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                    operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
                    if (operands[1].imm.value.u != 0) {
                        TraceMulFactor(ins_addr, operands[0].reg.value, 1.0 / (2ull << operands[1].imm.value.u));
                    }
                }
            }
        }
    }
    return ANALYZE_DO_NOTHING;
}
