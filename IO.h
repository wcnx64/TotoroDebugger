#ifndef _IO_H_
#define _IO_H_

void SetDbgCreateProcessInfo(
    HANDLE         ProcessHandle,
    HANDLE         ThreadHandle,
    unsigned char* BaseOfImage,
    unsigned char* StartAddress);

unsigned char* IoGetImageBase();
HANDLE IoGetThreadHandle();

unsigned long long IoGetRegisterLength(unsigned long reg);
unsigned long long IoGetRegisterMask(unsigned long reg);
unsigned long long IoReadRegister(unsigned long reg);
void IoWriteRegister(unsigned long reg, unsigned long long value);
unsigned long IoGet64bitRegister(unsigned long reg);
unsigned long IoGetRegisterWidth(unsigned long reg);

void IoReadProcessMemory(unsigned long long address, void* buf, unsigned long len);
void IoWriteProcessMemory(unsigned long long address, void* buf, unsigned long len);

void IoSnapshotMemory(unsigned long long address, unsigned long long range);
void IoReadSnapshotProcessMemory(unsigned long long address, void* buf, unsigned long len);

void DbgGoToDelta(int delta);

#endif // _IO_H_