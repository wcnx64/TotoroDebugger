#include <windows.h>
#include "IO.h"
#define ZYDIS_STATIC_BUILD
extern "C" {
#include "zydis/Zydis.h"
}


///
/// Process I/O
///

typedef struct TDbgCreateProcessInfo {
    BOOL           Init;
    HANDLE         ProcessHandle;
    HANDLE         ThreadHandle;
    unsigned char* BaseOfImage;
    unsigned char* StartAddress;
} TDbgCreateProcessInfo, * PTDbgCreateProcessInfo;

static TDbgCreateProcessInfo g_tdbgCreateProcessInfo;
#define HPROC g_tdbgCreateProcessInfo.ProcessHandle
#define HTHD  g_tdbgCreateProcessInfo.ThreadHandle
#define BASE  g_tdbgCreateProcessInfo.BaseOfImage

void IoSetCreateProcessInfo(
    HANDLE ProcessHandle,
    HANDLE ThreadHandle,
    unsigned char* BaseOfImage,
    unsigned char* StartAddress) {
    g_tdbgCreateProcessInfo.ProcessHandle = ProcessHandle;
    g_tdbgCreateProcessInfo.ThreadHandle = ThreadHandle;
    g_tdbgCreateProcessInfo.BaseOfImage = BaseOfImage;
    g_tdbgCreateProcessInfo.StartAddress = StartAddress;
    g_tdbgCreateProcessInfo.Init = TRUE;
}

unsigned char* IoGetImageBase() {
    return g_tdbgCreateProcessInfo.BaseOfImage;
}

HANDLE IoGetThreadHandle() {
    return HTHD;
}

HANDLE IoGetProcessHandle() {
    return HPROC;
}

unsigned char IoGetRegisterWidth(unsigned long reg) {
    switch ((ZydisRegister)reg) {
    case ZYDIS_REGISTER_RAX:
    case ZYDIS_REGISTER_RCX:
    case ZYDIS_REGISTER_RDX:
    case ZYDIS_REGISTER_RBX:
    case ZYDIS_REGISTER_RSP:
    case ZYDIS_REGISTER_RBP:
    case ZYDIS_REGISTER_RSI:
    case ZYDIS_REGISTER_RDI:
    case ZYDIS_REGISTER_R8:
    case ZYDIS_REGISTER_R9:
    case ZYDIS_REGISTER_R10:
    case ZYDIS_REGISTER_R11:
    case ZYDIS_REGISTER_R12:
    case ZYDIS_REGISTER_R13:
    case ZYDIS_REGISTER_R14:
    case ZYDIS_REGISTER_R15:
        return 8;
    case ZYDIS_REGISTER_EAX:
    case ZYDIS_REGISTER_ECX:
    case ZYDIS_REGISTER_EDX:
    case ZYDIS_REGISTER_EBX:
    case ZYDIS_REGISTER_ESP:
    case ZYDIS_REGISTER_EBP:
    case ZYDIS_REGISTER_ESI:
    case ZYDIS_REGISTER_EDI:
    case ZYDIS_REGISTER_R8D:
    case ZYDIS_REGISTER_R9D:
    case ZYDIS_REGISTER_R10D:
    case ZYDIS_REGISTER_R11D:
    case ZYDIS_REGISTER_R12D:
    case ZYDIS_REGISTER_R13D:
    case ZYDIS_REGISTER_R14D:
    case ZYDIS_REGISTER_R15D:
    case ZYDIS_REGISTER_RFLAGS:
        return 4;
    case ZYDIS_REGISTER_AX:
    case ZYDIS_REGISTER_CX:
    case ZYDIS_REGISTER_DX:
    case ZYDIS_REGISTER_BX:
    case ZYDIS_REGISTER_SP:
    case ZYDIS_REGISTER_BP:
    case ZYDIS_REGISTER_SI:
    case ZYDIS_REGISTER_DI:
    case ZYDIS_REGISTER_R8W:
    case ZYDIS_REGISTER_R9W:
    case ZYDIS_REGISTER_R10W:
    case ZYDIS_REGISTER_R11W:
    case ZYDIS_REGISTER_R12W:
    case ZYDIS_REGISTER_R13W:
    case ZYDIS_REGISTER_R14W:
    case ZYDIS_REGISTER_R15W:
        return 2;
    case ZYDIS_REGISTER_AL:
    case ZYDIS_REGISTER_AH:
    case ZYDIS_REGISTER_CL:
    case ZYDIS_REGISTER_CH:
    case ZYDIS_REGISTER_DL:
    case ZYDIS_REGISTER_DH:
    case ZYDIS_REGISTER_BL:
    case ZYDIS_REGISTER_BH:
    case ZYDIS_REGISTER_SPL:
    case ZYDIS_REGISTER_BPL:
    case ZYDIS_REGISTER_SIL:
    case ZYDIS_REGISTER_DIL:
    case ZYDIS_REGISTER_R8B:
    case ZYDIS_REGISTER_R9B:
    case ZYDIS_REGISTER_R10B:
    case ZYDIS_REGISTER_R11B:
    case ZYDIS_REGISTER_R12B:
    case ZYDIS_REGISTER_R13B:
    case ZYDIS_REGISTER_R14B:
    case ZYDIS_REGISTER_R15B:
        return 1;
    }
    return 0;

}

unsigned long long IoGetRegisterMask(unsigned long reg) {
    switch ((ZydisRegister)reg) {
    case ZYDIS_REGISTER_RAX:
    case ZYDIS_REGISTER_RCX:
    case ZYDIS_REGISTER_RDX:
    case ZYDIS_REGISTER_RBX:
    case ZYDIS_REGISTER_RSP:
    case ZYDIS_REGISTER_RBP:
    case ZYDIS_REGISTER_RSI:
    case ZYDIS_REGISTER_RDI:
    case ZYDIS_REGISTER_R8:
    case ZYDIS_REGISTER_R9:
    case ZYDIS_REGISTER_R10:
    case ZYDIS_REGISTER_R11:
    case ZYDIS_REGISTER_R12:
    case ZYDIS_REGISTER_R13:
    case ZYDIS_REGISTER_R14:
    case ZYDIS_REGISTER_R15:
        return 0xffffffffffffffff;
    case ZYDIS_REGISTER_EAX:
    case ZYDIS_REGISTER_ECX:
    case ZYDIS_REGISTER_EDX:
    case ZYDIS_REGISTER_EBX:
    case ZYDIS_REGISTER_ESP:
    case ZYDIS_REGISTER_EBP:
    case ZYDIS_REGISTER_ESI:
    case ZYDIS_REGISTER_EDI:
    case ZYDIS_REGISTER_R8D:
    case ZYDIS_REGISTER_R9D:
    case ZYDIS_REGISTER_R10D:
    case ZYDIS_REGISTER_R11D:
    case ZYDIS_REGISTER_R12D:
    case ZYDIS_REGISTER_R13D:
    case ZYDIS_REGISTER_R14D:
    case ZYDIS_REGISTER_R15D:
    case ZYDIS_REGISTER_RFLAGS:
        return 0xffffffff;
    case ZYDIS_REGISTER_AX:
    case ZYDIS_REGISTER_CX:
    case ZYDIS_REGISTER_DX:
    case ZYDIS_REGISTER_BX:
    case ZYDIS_REGISTER_SP:
    case ZYDIS_REGISTER_BP:
    case ZYDIS_REGISTER_SI:
    case ZYDIS_REGISTER_DI:
    case ZYDIS_REGISTER_R8W:
    case ZYDIS_REGISTER_R9W:
    case ZYDIS_REGISTER_R10W:
    case ZYDIS_REGISTER_R11W:
    case ZYDIS_REGISTER_R12W:
    case ZYDIS_REGISTER_R13W:
    case ZYDIS_REGISTER_R14W:
    case ZYDIS_REGISTER_R15W:
        return 0xffff;
    case ZYDIS_REGISTER_AL:
    case ZYDIS_REGISTER_AH:
    case ZYDIS_REGISTER_CL:
    case ZYDIS_REGISTER_CH:
    case ZYDIS_REGISTER_DL:
    case ZYDIS_REGISTER_DH:
    case ZYDIS_REGISTER_BL:
    case ZYDIS_REGISTER_BH:
    case ZYDIS_REGISTER_SPL:
    case ZYDIS_REGISTER_BPL:
    case ZYDIS_REGISTER_SIL:
    case ZYDIS_REGISTER_DIL:
    case ZYDIS_REGISTER_R8B:
    case ZYDIS_REGISTER_R9B:
    case ZYDIS_REGISTER_R10B:
    case ZYDIS_REGISTER_R11B:
    case ZYDIS_REGISTER_R12B:
    case ZYDIS_REGISTER_R13B:
    case ZYDIS_REGISTER_R14B:
    case ZYDIS_REGISTER_R15B:
        return 0xff;
    }
    return 0;
}

unsigned long IoGet64bitRegister(unsigned long reg) {
    switch ((ZydisRegister)reg) {
    case ZYDIS_REGISTER_RAX:
    case ZYDIS_REGISTER_EAX:
    case ZYDIS_REGISTER_AX:
    case ZYDIS_REGISTER_AL:
    case ZYDIS_REGISTER_AH:
        return ZYDIS_REGISTER_RAX;
    case ZYDIS_REGISTER_RCX:
    case ZYDIS_REGISTER_ECX:
    case ZYDIS_REGISTER_CX:
    case ZYDIS_REGISTER_CL:
    case ZYDIS_REGISTER_CH:
        return ZYDIS_REGISTER_RCX;
    case ZYDIS_REGISTER_RDX:
    case ZYDIS_REGISTER_EDX:
    case ZYDIS_REGISTER_DX:
    case ZYDIS_REGISTER_DL:
    case ZYDIS_REGISTER_DH:
        return ZYDIS_REGISTER_RDX;
    case ZYDIS_REGISTER_RBX:
    case ZYDIS_REGISTER_EBX:
    case ZYDIS_REGISTER_BX:
    case ZYDIS_REGISTER_BL:
    case ZYDIS_REGISTER_BH:
        return ZYDIS_REGISTER_RBX;
    case ZYDIS_REGISTER_RSP:
    case ZYDIS_REGISTER_ESP:
    case ZYDIS_REGISTER_SPL:
        return ZYDIS_REGISTER_RSP;
    case ZYDIS_REGISTER_RBP:
    case ZYDIS_REGISTER_EBP:
    case ZYDIS_REGISTER_BPL:
        return ZYDIS_REGISTER_RBP;
    case ZYDIS_REGISTER_RSI:
    case ZYDIS_REGISTER_ESI:
    case ZYDIS_REGISTER_SIL:
        return ZYDIS_REGISTER_RSI;
    case ZYDIS_REGISTER_RDI:
    case ZYDIS_REGISTER_EDI:
    case ZYDIS_REGISTER_DIL:
        return ZYDIS_REGISTER_RDI;
    case ZYDIS_REGISTER_R8:
    case ZYDIS_REGISTER_R8D:
    case ZYDIS_REGISTER_R8W:
    case ZYDIS_REGISTER_R8B:
        return ZYDIS_REGISTER_R8;
    case ZYDIS_REGISTER_R9:
    case ZYDIS_REGISTER_R9D:
    case ZYDIS_REGISTER_R9W:
    case ZYDIS_REGISTER_R9B:
        return ZYDIS_REGISTER_R9;
    case ZYDIS_REGISTER_R10:
    case ZYDIS_REGISTER_R10D:
    case ZYDIS_REGISTER_R10W:
    case ZYDIS_REGISTER_R10B:
        return ZYDIS_REGISTER_R10;
    case ZYDIS_REGISTER_R11:
    case ZYDIS_REGISTER_R11D:
    case ZYDIS_REGISTER_R11W:
    case ZYDIS_REGISTER_R11B:
        return ZYDIS_REGISTER_R11;
    case ZYDIS_REGISTER_R12:
    case ZYDIS_REGISTER_R12D:
    case ZYDIS_REGISTER_R12W:
    case ZYDIS_REGISTER_R12B:
        return ZYDIS_REGISTER_R12;
    case ZYDIS_REGISTER_R13:
    case ZYDIS_REGISTER_R13D:
    case ZYDIS_REGISTER_R13W:
    case ZYDIS_REGISTER_R13B:
        return ZYDIS_REGISTER_R13;
    case ZYDIS_REGISTER_R14:
    case ZYDIS_REGISTER_R14D:
    case ZYDIS_REGISTER_R14W:
    case ZYDIS_REGISTER_R14B:
        return ZYDIS_REGISTER_R14;
    case ZYDIS_REGISTER_R15:
    case ZYDIS_REGISTER_R15D:
    case ZYDIS_REGISTER_R15W:
    case ZYDIS_REGISTER_R15B:
        return ZYDIS_REGISTER_R15;
    case ZYDIS_REGISTER_RFLAGS:
        return ZYDIS_REGISTER_RFLAGS;
    }
    return reg;
}

unsigned long long IoReadRegister(unsigned long Reg) {
    CONTEXT ctx = { 0 };
    ctx.ContextFlags = CONTEXT_ALL;
    GetThreadContext(HTHD, &ctx);
    switch ((ZydisRegister)Reg) {
    case ZYDIS_REGISTER_RAX:
        return ctx.Rax;
    case ZYDIS_REGISTER_EAX:
        return ctx.Rax & 0xffffffff;
    case ZYDIS_REGISTER_AX:
        return ctx.Rax & 0xffff;
    case ZYDIS_REGISTER_AL:
        return ctx.Rax & 0xff;
    case ZYDIS_REGISTER_AH:
        return (ctx.Rax & 0xff00) >> 8;
    case ZYDIS_REGISTER_RCX:
        return ctx.Rcx;
    case ZYDIS_REGISTER_ECX:
        return ctx.Rcx & 0xffffffff;
    case ZYDIS_REGISTER_CX:
        return ctx.Rcx & 0xffff;
    case ZYDIS_REGISTER_CL:
        return ctx.Rcx & 0xff;
    case ZYDIS_REGISTER_CH:
        return (ctx.Rcx & 0xff00) >> 8;
    case ZYDIS_REGISTER_RDX:
        return ctx.Rdx;
    case ZYDIS_REGISTER_EDX:
        return ctx.Rdx & 0xffffffff;
    case ZYDIS_REGISTER_DX:
        return ctx.Rdx & 0xffff;
    case ZYDIS_REGISTER_DL:
        return ctx.Rdx & 0xff;
    case ZYDIS_REGISTER_DH:
        return (ctx.Rdx & 0xff00) >> 8;
    case ZYDIS_REGISTER_RBX:
        return ctx.Rbx;
    case ZYDIS_REGISTER_EBX:
        return ctx.Rbx & 0xffffffff;
    case ZYDIS_REGISTER_BX:
        return ctx.Rbx & 0xffff;
    case ZYDIS_REGISTER_BL:
        return ctx.Rbx & 0xff;
    case ZYDIS_REGISTER_BH:
        return (ctx.Rbx & 0xff00) >> 8;
    case ZYDIS_REGISTER_RSP:
        return ctx.Rsp;
    case ZYDIS_REGISTER_ESP:
        return ctx.Rsp & 0xffffffff;
    case ZYDIS_REGISTER_SP:
        return ctx.Rsp & 0xffff;
    case ZYDIS_REGISTER_SPL:
        return ctx.Rsp & 0xff;
    case ZYDIS_REGISTER_RBP:
        return ctx.Rbp;
    case ZYDIS_REGISTER_EBP:
        return ctx.Rbp & 0xffffffff;
    case ZYDIS_REGISTER_BP:
        return ctx.Rbp & 0xffff;
    case ZYDIS_REGISTER_BPL:
        return ctx.Rbp & 0xff;
    case ZYDIS_REGISTER_RSI:
        return ctx.Rsi;
    case ZYDIS_REGISTER_ESI:
        return ctx.Rsi & 0xffffffff;
    case ZYDIS_REGISTER_SI:
        return ctx.Rsi & 0xffff;
    case ZYDIS_REGISTER_SIL:
        return ctx.Rsi & 0xff;
    case ZYDIS_REGISTER_RDI:
        return ctx.Rdi;
    case ZYDIS_REGISTER_EDI:
        return ctx.Rdi & 0xffffffff;
    case ZYDIS_REGISTER_DI:
        return ctx.Rdi & 0xffff;
    case ZYDIS_REGISTER_DIL:
        return ctx.Rdi & 0xff;
    case ZYDIS_REGISTER_R8:
        return ctx.R8;
    case ZYDIS_REGISTER_R8D:
        return ctx.R8 & 0xffffffff;
    case ZYDIS_REGISTER_R8W:
        return ctx.R8 & 0xffff;
    case ZYDIS_REGISTER_R8B:
        return ctx.R8 & 0xff;
    case ZYDIS_REGISTER_R9:
        return ctx.R9;
    case ZYDIS_REGISTER_R9D:
        return ctx.R9 & 0xffffffff;
    case ZYDIS_REGISTER_R9W:
        return ctx.R9 & 0xffff;
    case ZYDIS_REGISTER_R9B:
        return ctx.R9 & 0xff;
    case ZYDIS_REGISTER_R10:
        return ctx.R10;
    case ZYDIS_REGISTER_R10D:
        return ctx.R10 & 0xffffffff;
    case ZYDIS_REGISTER_R10W:
        return ctx.R10 & 0xffff;
    case ZYDIS_REGISTER_R10B:
        return ctx.R10 & 0xff;
    case ZYDIS_REGISTER_R11:
        return ctx.R11;
    case ZYDIS_REGISTER_R11D:
        return ctx.R11 & 0xffffffff;
    case ZYDIS_REGISTER_R11W:
        return ctx.R11 & 0xffff;
    case ZYDIS_REGISTER_R11B:
        return ctx.R11 & 0xff;
    case ZYDIS_REGISTER_R12:
        return ctx.R12;
    case ZYDIS_REGISTER_R12D:
        return ctx.R12 & 0xffffffff;
    case ZYDIS_REGISTER_R12W:
        return ctx.R12 & 0xffff;
    case ZYDIS_REGISTER_R12B:
        return ctx.R12 & 0xff;
    case ZYDIS_REGISTER_R13:
        return ctx.R13;
    case ZYDIS_REGISTER_R13D:
        return ctx.R13 & 0xffffffff;
    case ZYDIS_REGISTER_R13W:
        return ctx.R13 & 0xffff;
    case ZYDIS_REGISTER_R13B:
        return ctx.R13 & 0xff;
    case ZYDIS_REGISTER_R14:
        return ctx.R14;
    case ZYDIS_REGISTER_R14D:
        return ctx.R14 & 0xffffffff;
    case ZYDIS_REGISTER_R14W:
        return ctx.R14 & 0xffff;
    case ZYDIS_REGISTER_R14B:
        return ctx.R14 & 0xff;
    case ZYDIS_REGISTER_R15:
        return ctx.R15;
    case ZYDIS_REGISTER_R15D:
        return ctx.R15 & 0xffffffff;
    case ZYDIS_REGISTER_R15W:
        return ctx.R15 & 0xffff;
    case ZYDIS_REGISTER_R15B:
        return ctx.R15 & 0xff;
    case ZYDIS_REGISTER_RFLAGS:
        return ctx.EFlags;
    case ZYDIS_REGISTER_RIP:
        return ctx.Rip;
    }
    return 0;
}

void IoWriteRegister(unsigned long reg, unsigned long long value) {
    CONTEXT ctx = { 0 };
    ctx.ContextFlags = CONTEXT_ALL;
    GetThreadContext(HTHD, &ctx);
    switch ((ZydisRegister)reg) {
    case ZYDIS_REGISTER_RAX:
        ctx.Rax = value;
        break;
    case ZYDIS_REGISTER_EAX:
        ctx.Rax = value & 0xffffffff;
        break;
    case ZYDIS_REGISTER_RCX:
        ctx.Rcx = value;
        break;
    case ZYDIS_REGISTER_ECX:
        ctx.Rcx = value & 0xffffffff;
        break;
    case ZYDIS_REGISTER_RDX:
        ctx.Rdx = value;
        break;
    case ZYDIS_REGISTER_EDX:
        ctx.Rdx = value & 0xffffffff;
        break;
    case ZYDIS_REGISTER_RBX:
        ctx.Rbx = value;
        break;
    case ZYDIS_REGISTER_EBX:
        ctx.Rbx = value & 0xffffffff;
        break;
    case ZYDIS_REGISTER_RSP:
        ctx.Rsp = value;
        break;
    case ZYDIS_REGISTER_ESP:
        ctx.Rsp = value & 0xffffffff;
        break;
    case ZYDIS_REGISTER_RBP:
        ctx.Rbp = value;
        break;
    case ZYDIS_REGISTER_EBP:
        ctx.Rbp = value & 0xffffffff;
        break;
    case ZYDIS_REGISTER_RSI:
        ctx.Rsi = value;
        break;
    case ZYDIS_REGISTER_ESI:
        ctx.Rsi = value & 0xffffffff;
        break;
    case ZYDIS_REGISTER_RDI:
        ctx.Rdi = value;
        break;
    case ZYDIS_REGISTER_EDI:
        ctx.Rdi = value & 0xffffffff;
        break;
    case ZYDIS_REGISTER_R8:
        ctx.R8 = value;
        break;
    case ZYDIS_REGISTER_R8D:
        ctx.R8 = value & 0xffffffff;
        break;
    case ZYDIS_REGISTER_R9:
        ctx.R9 = value;
        break;
    case ZYDIS_REGISTER_R9D:
        ctx.R9 = value & 0xffffffff;
        break;
    case ZYDIS_REGISTER_R10:
        ctx.R10 = value;
        break;
    case ZYDIS_REGISTER_R10D:
        ctx.R10 = value & 0xffffffff;
        break;
    case ZYDIS_REGISTER_R11:
        ctx.R11 = value;
        break;
    case ZYDIS_REGISTER_R11D:
        ctx.R11 = value & 0xffffffff;
        break;
    case ZYDIS_REGISTER_R12:
        ctx.R12 = value;
        break;
    case ZYDIS_REGISTER_R12D:
        ctx.R12 = value & 0xffffffff;
        break;
    case ZYDIS_REGISTER_R13:
        ctx.R13 = value;
        break;
    case ZYDIS_REGISTER_R13D:
        ctx.R13 = value & 0xffffffff;
        break;
    case ZYDIS_REGISTER_R14:
        ctx.R14 = value;
        break;
    case ZYDIS_REGISTER_R14D:
        ctx.R14 = value & 0xffffffff;
        break;
    case ZYDIS_REGISTER_R15:
        ctx.R15 = value;
        break;
    case ZYDIS_REGISTER_R15D:
        ctx.R15 = value & 0xffffffff;
        break;
    case ZYDIS_REGISTER_RFLAGS:
        ctx.EFlags = (unsigned long)value;
        break;
    }
    SetThreadContext(HTHD, &ctx);
}

bool IoReadProcessMemory(unsigned long long Address, void* Buf, unsigned long Len) {
    unsigned long long Length = 0;
    return ReadProcessMemory(HPROC, (char*)Address, Buf, Len, &Length);
}

bool IoWriteProcessMemory(unsigned long long Address, void* Buf, unsigned long Len) {
    unsigned long long Length = 0;
    return WriteProcessMemory(HPROC, (char*)Address, Buf, Len, &Length);
}

static char*     SnapshotMemory = NULL;
static unsigned long long SnapshotMemoryBase = 0;
static unsigned long long SnapshotMemoryLength = 0;
void IoSnapshotMemory(unsigned long long Address, unsigned long long Length) {
    SnapshotMemoryBase = Address;
    SnapshotMemoryLength = Length;
    if (SnapshotMemory)
        delete[] SnapshotMemory;
    SnapshotMemory = new char[Length];
    unsigned long long BytesRead = 0;
    ReadProcessMemory(HPROC, (char*)Address, SnapshotMemory, SnapshotMemoryLength, &BytesRead);
}

void IoReadSnapshotProcessMemory(unsigned long long Address, void* Buf, unsigned long Len) {
    if (Address < SnapshotMemoryBase) {
        for (int i = 0; i < (int)Len; i++) {
            ((char*)Buf)[i] = (char)0xcc;
        }
    }
    else {
        memcpy(Buf, SnapshotMemory + (Address - SnapshotMemoryBase), Len);
    }
}
