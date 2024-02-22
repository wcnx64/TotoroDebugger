#ifndef _IO_H_
#define _IO_H_

///
/// Process I/O
///

void IoSetCreateProcessInfo(
    HANDLE         ProcessHandle,
    HANDLE         ThreadHandle,
    unsigned char* BaseOfImage,
    unsigned char* StartAddress);

unsigned char* IoGetImageBase();
HANDLE IoGetThreadHandle();
HANDLE IoGetProcessHandle();

unsigned char      IoGetRegisterWidth(unsigned long reg);
unsigned long long IoGetRegisterMask(unsigned long reg);
unsigned long      IoGet64bitRegister(unsigned long reg);

unsigned long long IoReadRegister(unsigned long reg);
void               IoWriteRegister(unsigned long reg, unsigned long long value);

bool IoReadProcessMemory(unsigned long long address, void* buf, unsigned long len);
bool IoWriteProcessMemory(unsigned long long address, void* buf, unsigned long len);

void IoSnapshotMemory(unsigned long long address, unsigned long long range);
void IoReadSnapshotProcessMemory(unsigned long long address, void* buf, unsigned long len);

#endif // _IO_H_