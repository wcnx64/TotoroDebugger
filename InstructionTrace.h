#ifndef _INSTRUCTION_TRACE_H_
#define _INSTRUCTION_TRACE_H_

bool InitTrace();

bool StartVMInsGroup();
void FinishVMInsGroup();
bool StartVMIns();
void FinishVMIns();

void TraceLoadMem(unsigned long long ins_addr, unsigned long reg, unsigned long long addr);
void TraceSaveMem(unsigned long long ins_addr, unsigned long long addr, unsigned long reg);
void TraceMovRR(unsigned long long ins_addr, unsigned long des_reg, unsigned long src_reg);

void TraceUnitaryArithmetic(unsigned long long ins_addr, int op, unsigned long long reg);
void TraceBinaryArithmeticRR(
	unsigned long long ins_addr,
	int                op,
	unsigned long long des_reg,
	unsigned long long src_reg);
void TraceBinaryArithmeticRI(
	unsigned long long ins_addr,
	int                op,
	unsigned long long reg,
	unsigned long long value);
void TraceMulFactor(unsigned long long ins_addr, unsigned long long reg, double factor);

// test and debug
void FinishVMInsGroupUnprotected(unsigned char* address, void* user_data);
void FinishVMInsGroupVmpInline(unsigned char* address, void* user_data);

#endif // _INSTRUCTION_TRACE_H_