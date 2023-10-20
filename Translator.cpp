#include "Translator.h"
#define ZYDIS_STATIC_BUILD
extern "C" {
#include "Zydis.h"
}

const char* TranslateOprator(unsigned long Opcode) {
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
