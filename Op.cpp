#include "Op.h"
#define ZYDIS_STATIC_BUILD
extern "C" {
#include "zydis/Zydis.h"
}

const char* TranslateOperator(unsigned long Opcode) {
	switch (Opcode) {
	case ZYDIS_MNEMONIC_ADD:
		return "+";
	case ZYDIS_MNEMONIC_SUB:
		return "-";
	case ZYDIS_MNEMONIC_MUL:
		return "*";
	case ZYDIS_MNEMONIC_DIV:
		return "/";
	case ZYDIS_MNEMONIC_AND:
		return "and";
	case ZYDIS_MNEMONIC_OR:
		return "or";
	case ZYDIS_MNEMONIC_XOR:
		return "xor";
	default:
		return "?";
	}
}

const char* TranslateRegister(unsigned long Reg) {
    switch ((ZydisRegister)Reg) {
    case ZYDIS_REGISTER_RAX:
        return "rax";
    case ZYDIS_REGISTER_EAX:
        return "eax";
    case ZYDIS_REGISTER_RCX:
        return "rcx";
    case ZYDIS_REGISTER_ECX:
        return "ecx";
    case ZYDIS_REGISTER_RDX:
        return "rdx";
    case ZYDIS_REGISTER_EDX:
        return "edx";
    case ZYDIS_REGISTER_RBX:
        return "rbx";
    case ZYDIS_REGISTER_EBX:
        return "ebx";
    case ZYDIS_REGISTER_RSP:
        return "rsp";
    case ZYDIS_REGISTER_ESP:
        return "esp";
    case ZYDIS_REGISTER_RBP:
        return "rbp";
    case ZYDIS_REGISTER_EBP:
        return "ebp";
    case ZYDIS_REGISTER_RSI:
        return "rsi";
    case ZYDIS_REGISTER_ESI:
        return "esi";
    case ZYDIS_REGISTER_RDI:
        return "rdi";
    case ZYDIS_REGISTER_EDI:
        return "edi";
    case ZYDIS_REGISTER_R8:
        return "r8";
    case ZYDIS_REGISTER_R8D:
        return "r8d";
    case ZYDIS_REGISTER_R9:
        return "r9";
    case ZYDIS_REGISTER_R9D:
        return "r9d";
    case ZYDIS_REGISTER_R10:
        return "r10";
    case ZYDIS_REGISTER_R10D:
        return "r10d";
    case ZYDIS_REGISTER_R11:
        return "r11";
    case ZYDIS_REGISTER_R11D:
        return "r11d";
    case ZYDIS_REGISTER_R12:
        return "r12";
    case ZYDIS_REGISTER_R12D:
        return "r12d";
    case ZYDIS_REGISTER_R13:
        return "r13";
    case ZYDIS_REGISTER_R13D:
        return "r13d";
    case ZYDIS_REGISTER_R14:
        return "r14";
    case ZYDIS_REGISTER_R14D:
        return "r14d";
    case ZYDIS_REGISTER_R15:
        return "r15";
    case ZYDIS_REGISTER_R15D:
        return "r15d";
    case ZYDIS_REGISTER_RFLAGS:
        return "eflags";
    }
    return "Reg";
}

unsigned long long CalculateOpRR(unsigned long Opcode, unsigned long long R1, unsigned long long R2) {
	switch (Opcode) {
	case ZYDIS_MNEMONIC_ADD:
		return R1 + R2;
	case ZYDIS_MNEMONIC_SUB:
		return R1 - R2;
	case ZYDIS_MNEMONIC_MUL:
		return R1 * R2;
	case ZYDIS_MNEMONIC_DIV:
		return R1 / R2;
	case ZYDIS_MNEMONIC_AND:
		return R1 & R2;
	case ZYDIS_MNEMONIC_OR:
		return R1 | R2;
	case ZYDIS_MNEMONIC_XOR:
		return R1 ^ R2;
	default:
		return 0;
	}
}

bool IsNotByValue(unsigned long long V1, unsigned long long V2, unsigned long* Width) {
    if (V1 != V2) {
        unsigned long long Value = V1 + V2;
        if (Value == 0x100000000 || Value == 0xffffffff) {
            if (Width)
                *Width = 4;
            return true;
        }
        else if (Value == 0 || Value == (unsigned long long)(-1)) {
            if (Width)
                *Width = 8;
            return true;
        }
        else if (Value == 0x10000 || Value == 0xffffffff) {
            if (Width)
                *Width = 2;
            return true;
        }
        else if (Value == 0x100 || Value == 0xff) {
            if (Width)
                *Width = 1;
            return true;
        }
    }
    return false;
}
