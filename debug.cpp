#include <vector>
#include <windows.h>
#include "debug.h"
#include "io.h"

// the bp_address and user_data are the ones of the associated breakpoint
typedef struct TDbgSingleStepTracor {
    SingleStepTraceCallback callback;
    unsigned char*          bp_address;
    void*                   bp_user_data;
} TDbgSingleStepTracor, *PTDbgSingleStepTracor;

typedef struct TDbgBreakpoint {
    unsigned char*       address;
    unsigned char        backup_byte;
    BreakpointCallback   callback;
    void*                user_data;
    bool                 has_trace;
    TDbgSingleStepTracor trace;
} TDbgBreakpoint, * PTDbgBreakpoint;
static std::vector<TDbgBreakpoint> g_breakpoints;

bool AddBreakpoint(unsigned char* address,
    BreakpointCallback callback,
    void* user_data,
    SingleStepTraceCallback trace_callback) {
    TDbgBreakpoint bp = { 0 };
    bp.address = address;
    bp.callback = callback;
    bp.user_data = user_data;
    if (trace_callback) {
        bp.has_trace = true;
        bp.trace.callback = trace_callback;
        bp.trace.bp_address = address;
        bp.trace.bp_user_data = user_data;
    }
    else {
        bp.has_trace = false;
    }
    IoReadProcessMemory((unsigned long long)address, &bp.backup_byte, 1);
    unsigned char cc = 0xcc;
    IoWriteProcessMemory((unsigned long long)address, &cc, 1);
    g_breakpoints.push_back(bp);
    return true;
}

void DeleteBreakpoint(unsigned char* address, void* user_contect) {
    for (std::vector<TDbgBreakpoint>::iterator i = g_breakpoints.begin(); i != g_breakpoints.end();) {
        if (i->address == address) {
            i = g_breakpoints.erase(i);
        }
        else {
            i++;
        }
    }
}

bool OnBreakpoint(
    TDbgBreakpoint&        bp,
    CONTEXT&               ctx,
    bool&                  single_step,
    PTDbgSingleStepTracor& tracor,
    PTDbgBreakpoint&       breakpoint_to_recover,
    bool&                  erase,
    bool&                  abort) {
    if (bp.callback) {
        int callback_ret = bp.callback(bp.address, bp.user_data);
        // set breakpoint to recover
        breakpoint_to_recover = &bp;
        // recover the original code
        ctx.Rip--;
        ctx.EFlags |= 0x0100; // TF
        SetThreadContext(IoGetThreadHandle(), &ctx);
        IoWriteProcessMemory((ULONGLONG)bp.address, &bp.backup_byte, 1);
        // handle return values
        if (callback_ret == BREAKPOINT_CALLBACK_RETURN_SINGLE_STEP) {
            single_step = true;
            tracor = &bp.trace;
        }
        else if (callback_ret == BREAKPOINT_CALLBACK_RETURN_REMOVE) {
            breakpoint_to_recover = nullptr;
            erase = true;
        }
        else if (callback_ret == BREAKPOINT_CALLBACK_RETURN_ABORT) {
            breakpoint_to_recover = nullptr;
            g_breakpoints.clear();
        }
        else if (callback_ret == BREAKPOINT_CALLBACK_RETURN_CONTINUE) {
        }
        else {
            return false;
        }
        return true;
    }
    return false;
}

void OnSingleStepTrace(unsigned char* address) {
    ;
}

void OnDebugEvent(unsigned char* address) {
    static bool is_aborted = false;
    static PTDbgBreakpoint breakpoint_to_recover = nullptr;
    static bool is_being_traced = false;
    static PTDbgSingleStepTracor tracor = nullptr;
    if (is_aborted) return; // aborted
    // recover breakpoint
    if (breakpoint_to_recover) {
        unsigned char cc = 0xcc;
        IoWriteProcessMemory((unsigned long long)breakpoint_to_recover->address, &cc, 1);
        breakpoint_to_recover = nullptr;
    }
    CONTEXT ctx = { 0 };
    ctx.ContextFlags = CONTEXT_ALL;
    GetThreadContext(IoGetThreadHandle(), &ctx);
    // continue single stepping
    if (is_being_traced) {
        ctx.EFlags |= 0x0100; // TF
        SetThreadContext(IoGetThreadHandle(), &ctx);
        if (tracor && tracor->callback)
            tracor->callback(address, tracor->bp_address, tracor->bp_user_data);
    }
    // multiple callbacks can be set on an address
    for (std::vector<TDbgBreakpoint>::iterator i = g_breakpoints.begin(); i != g_breakpoints.end();) {
        if (i->address == address) {
            printf("Breakpoint Hit: 0x%llx\n", (ULONGLONG)address);
            bool erase = false;
            bool bp_ret = OnBreakpoint(*i, ctx, is_being_traced, tracor,
                breakpoint_to_recover, erase, is_aborted);
            if (bp_ret) {
                if (erase) {
                    i = g_breakpoints.erase(i);
                    continue;
                }
                if (is_aborted) break;
            }
        }
        i++;
    }
    if (is_aborted)
        g_breakpoints.clear();
}
