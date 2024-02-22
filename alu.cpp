#include "alu.h"
#define ZYDIS_STATIC_BUILD
extern "C" {
#include "zydis/Zydis.h"
}

unsigned long long OpCalculate(int op, unsigned long long operand) {
    switch (op) {
    case ZYDIS_MNEMONIC_MOV:
        return operand;
    case ZYDIS_MNEMONIC_NOT:
        return 0 - operand;
    case ZYDIS_MNEMONIC_NEG:
        return ~operand;
    case ZYDIS_MNEMONIC_INC:
        return operand + 1;
    case ZYDIS_MNEMONIC_DEC:
        return operand - 1;
    }
    return 0;
}

unsigned long long OpCalculate(int op, unsigned long long operand1, unsigned long long operand2) {
    switch (op) {
    case ZYDIS_MNEMONIC_ADD:
        return operand1 + operand2;
    case ZYDIS_MNEMONIC_SUB:
        return operand1 - operand2;
    case ZYDIS_MNEMONIC_AND:
        return operand1 & operand2;
    case ZYDIS_MNEMONIC_OR:
        return operand1 | operand2;
    case ZYDIS_MNEMONIC_XOR:
        return operand1 ^ operand2;
    }
    return 0;
}
