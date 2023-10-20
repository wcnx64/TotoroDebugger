#ifndef _DECODER_H_
#define _DECODER_H_

typedef struct Instruction {
	int                nLength;
	unsigned long long code;
} Instruction, *PInstruction;

#define RAX     0
#define RCX     1
#define RDX     2
#define RBX     3
#define RSP     4
#define RBP     5
#define RSI     6
#define RDI     7
#define R8      8
#define R9      9
#define R10     10
#define R11     11
#define R12     12
#define R13     13
#define R14     14
#define R15     15
#define R_DWORD 100
#define R_WORD  1000
#define R_BYTE  10000

// 0 - 4 bytes : Prefix
// 1 - 3 bytes : Opcode
// 0 - 1 byte : Mod - Reg R / M
// 0 - 1 byte : Scale - Index - Base(SIB)
// 0, 1, 2, 4 bytes : Displacement
// 0, 1, 2, 4, 8 bytes : Immediate
#define INS_OPCODE_QWORD 4
#define INS_OPCODE_DWORD 3
#define INS_OPCODE_WORD  6

#define INS_MOV_RR   1
#define INS_MOV_RI   2
#define INS_MOV_RM   3
#define INS_MOV_RMR  4
#define INS_MOV_RMRR 5

typedef struct InsMovRR {
	Instruction ins;
	int         rdes;
	int         rsrc;
} InsMovRR, *PInsMovRR;

typedef struct InsMovRI {
	Instruction        ins;
	int                rdes;
	unsigned long long imm;
} InsMovRI, * PInsMovRI;

typedef struct InsMovRMR {
	Instruction        ins;
	int                rdes;
	int                mrsrc;
	unsigned long long offset;
} InsMovRMR, * PInsMovRMR;

typedef struct InsMovRMRR {
	Instruction        ins;
	int                rdes;
	int                mrsrc1;
	int                mrsrc2;
	unsigned long long offset;
} InsMovRMRR, * PInsMovRMRR;

#endif // _DECODER_H_