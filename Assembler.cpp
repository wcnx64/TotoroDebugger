#include "Assembler.h"
#include "zasm/zasm.hpp"

#pragma comment(lib, "zasm/zasm.lib")


bool AssembleTreeNodeMov(
	OpNode*   node,
	uint64_t  stack_base,
	uint32_t  volatile_reg,
	uint8_t*  code,
	uint32_t  buffer_size,
	uint32_t* code_len);

bool AssembleJmp(
	uint64_t  from,
	uint64_t  to,
	uint8_t*  code,
	uint32_t  buffer_size,
	uint32_t* code_len) {
	long long delta = (long long)(to - from - 2);
	if ((delta & 0xffffffffffffff00) == 0 || (delta & 0xffffffffffffff00) == 0xffffffffffffff00) {
		// jmp near
		*code_len = 2;
		if (buffer_size < 2)
			return false;
		code[0] = 0xeb;
		code[1] = (uint8_t)(delta & 0xff);
		return true;
	}
	delta = (long long)(to - from - 5);
	if ((delta & 0xffffffff00000000) == 0 || (delta & 0xffffffff00000000) == 0xffffffff00000000) {
		// jmp
		*code_len = 5;
		if (buffer_size < 5)
			return false;
		code[0] = 0xe9;
		*(uint32_t*)&code[1] = (uint32_t)(delta & 0xffffffff);
		return true;
	}
	// 64bit far jmp is not supported
	return false;
}

bool AssemblePush(
	uint32_t  reg,
	uint8_t*  code,
	uint32_t  buffer_size,
	uint32_t* code_len) {
	zasm::Program        program(zasm::MachineMode::AMD64);
	zasm::x86::Assembler assembler(program);
	zasm::x86::Gp        zreg((zasm::x86::Reg::Id)reg);
	zasm::Error err = assembler.push(zreg);
	if (err != zasm::Error::None)
		return false;
	// get machine code
	static zasm::Serializer serializer;
	err = serializer.serialize(program, 0);
	if (err != zasm::Error::None)
		return false;
	*code_len = (uint32_t)serializer.getCodeSize();
	if (*code_len > buffer_size)
		return false;
	memcpy(code, serializer.getCode(), *code_len);
	return true;
}

bool AssemblePop(
	uint32_t  reg,
	uint8_t*  code,
	uint32_t  buffer_size,
	uint32_t* code_len) {
	zasm::Program        program(zasm::MachineMode::AMD64);
	zasm::x86::Assembler assembler(program);
	zasm::x86::Gp        zreg((zasm::x86::Reg::Id)reg);
	zasm::Error err = assembler.pop(zreg);
	if (err != zasm::Error::None)
		return false;
	// get machine code
	static zasm::Serializer serializer;
	err = serializer.serialize(program, 0);
	if (err != zasm::Error::None)
		return false;
	*code_len = (uint32_t)serializer.getCodeSize();
	if (*code_len > buffer_size)
		return false;
	memcpy(code, serializer.getCode(), *code_len);
	return true;
}

bool AssembleTree(
	OpNode*   node,
	uint64_t  stack_base,
	uint32_t  volatile_reg,
	uint8_t*  code,
	uint32_t  buffer_size,
	uint32_t* code_len) {
	uint32_t offset = 0;
	uint32_t len = 0;
	bool          ret = false;
	*code_len = 0;
	// Recursion. Child trees are built ahead of parent. so generate child trees' code first.
	if (node->left) {
		ret = AssembleTree(node->left, stack_base, volatile_reg,
			code, buffer_size - offset, &len);
		if (!ret) {
			*code_len = offset + len;
			return false;
		}
		offset += len;
	}
	if (node->right) {
		ret = AssembleTree(node->right, stack_base, volatile_reg,
			code + offset, buffer_size - offset, &len);
		if (!ret) {
			*code_len = offset + len;
			return false;
		}
		offset += len;
	}
	// generate code for the current node
	if (node->left && node->right) {
		;
	}
	else if (node->left) {
		if (node->op == ZYDIS_MNEMONIC_MOV) {
			ret = AssembleTreeNodeMov(node, stack_base, volatile_reg,
				code + offset, buffer_size - offset, &len);
			if (!ret) {
				*code_len = offset + len;
				return false;
			}
			offset += len;
		}
		else {
			;
		}
	}
	*code_len = offset;
	return true;
}

bool AssembleTreeNodeMov(
	OpNode*   node,
	uint64_t  stack_base,
	uint32_t  volatile_reg,
	uint8_t*  code,
	uint32_t  buffer_size,
	uint32_t* code_len) {
	if (node->left) {
		if (node->type == ZYDIS_OPERAND_TYPE_MEMORY &&
			node->left->type == ZYDIS_OPERAND_TYPE_MEMORY) { // maybe reduced to mem to mem
			// mov volatile_reg, src_mem
			bool ret = AssembleLoadStack(node->left->addr - stack_base, volatile_reg,
				code, buffer_size, code_len);
			if (!ret) return false;
			// mov des_mem, volatile_reg
			uint32_t len = 0;
			ret = AssembleSaveStack(node->addr - stack_base, volatile_reg,
				code + *code_len, buffer_size - *code_len, & len);
			(*code_len) += len;
			if (!ret) return false;
		}
		else if (node->type == ZYDIS_OPERAND_TYPE_MEMORY &&
			node->left->type == ZYDIS_OPERAND_TYPE_REGISTER) {
			return false;
		}
		else if (node->type == ZYDIS_OPERAND_TYPE_MEMORY &&
			node->left->type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
			// mov volatile_reg, imm
			bool ret = AssembleMovRI(volatile_reg, node->left->value,
				code, buffer_size, code_len);
			if (!ret) return false;
			// mov des_mem, volatile_reg
			uint32_t len = 0;
			ret = AssembleSaveStack(node->addr - stack_base, volatile_reg,
				code + *code_len, buffer_size - *code_len, &len);
			(*code_len) += len;
			if (!ret) return false;
		}
		else if (node->type == ZYDIS_OPERAND_TYPE_REGISTER &&
			node->left->type == ZYDIS_OPERAND_TYPE_MEMORY) {
			return false;
		}
		else if (node->type == ZYDIS_OPERAND_TYPE_REGISTER &&
			node->left->type == ZYDIS_OPERAND_TYPE_REGISTER) {
			return false;
		}
		else if (node->type == ZYDIS_OPERAND_TYPE_REGISTER &&
			node->left->type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
			return false;
		}
	}
	return true;
}

bool AssembleLoadStack(
	uint64_t  stack_offset,
	uint32_t  des_reg,
	uint8_t*  code,
	uint32_t  buffer_size,
	uint32_t* code_len) {
	// mov rcx, [rsp + 0x12345678] -> 48 8b 8c 24 78 56 34 12
	zasm::Program        program(zasm::MachineMode::AMD64);
	zasm::x86::Assembler assembler(program);
	// mov des_reg, [rsp + stack_offset]
	zasm::x86::Gp  des_reg_gp((zasm::x86::Reg::Id)des_reg);
	zasm::x86::Reg cs_zreg((zasm::x86::Reg::Id)ZYDIS_REGISTER_CS);
	zasm::x86::Reg rsp_zreg((zasm::x86::Reg::Id)ZYDIS_REGISTER_RSP);
	zasm::x86::Reg none_zreg;
	zasm::x86::Mem stack_mem(
		des_reg_gp.getBitSize(zasm::MachineMode::AMD64),
		cs_zreg, rsp_zreg, none_zreg, 0, stack_offset);
	zasm::Error err = assembler.mov(des_reg_gp, stack_mem);
	if (err != zasm::Error::None)
		return false;
	// get machine code
	static zasm::Serializer serializer;
	err = serializer.serialize(program, 0);
	if (err != zasm::Error::None)
		return false;
	*code_len = (uint32_t)serializer.getCodeSize();
	if (*code_len > buffer_size)
		return false;
	memcpy(code, serializer.getCode(), *code_len);
	return true;
}

bool AssembleSaveStack(
	uint64_t  stack_offset,
	uint32_t  src_reg,
	uint8_t*  code,
	uint32_t  buffer_size,
	uint32_t* code_len) {
	// mov [rsp + 0x12345678], rcx -> 48 89 8c 24 78 56 34 12
	zasm::Program        program(zasm::MachineMode::AMD64);
	zasm::x86::Assembler assembler(program);
	// mov [rsp + stack_offset], src_reg
	zasm::x86::Gp  src_zreg((zasm::x86::Reg::Id)src_reg);
	zasm::x86::Reg cs_zreg((zasm::x86::Reg::Id)ZYDIS_REGISTER_CS);
	zasm::x86::Reg rsp_zreg((zasm::x86::Reg::Id)ZYDIS_REGISTER_RSP);
	zasm::x86::Reg none_zreg;
	zasm::x86::Mem stack_mem(
		src_zreg.getBitSize(zasm::MachineMode::AMD64),
		cs_zreg, rsp_zreg, none_zreg, 0, stack_offset);
	zasm::Error err = assembler.mov(stack_mem, src_zreg);
	if (err != zasm::Error::None)
		return false;
	// get machine code
	static zasm::Serializer serializer;
	err = serializer.serialize(program, 0);
	if (err != zasm::Error::None)
		return false;
	*code_len = (uint32_t)serializer.getCodeSize();
	if (*code_len > buffer_size)
		return false;
	memcpy(code, serializer.getCode(), *code_len);
	return true;
}

// mov reg, imm
bool AssembleMovRI(
	uint32_t  reg,
	uint64_t  immediate_value,
	uint8_t*  code,
	uint32_t  buffer_size,
	uint32_t* code_len) {
	// mov [rsp + 0x12345678], 0x7fffffffffffffff -> 48 89 8c 24 78 56 34 12
	zasm::Program        program(zasm::MachineMode::AMD64);
	zasm::x86::Assembler assembler(program);
	// mov [rsp + stack_offset], src_reg
	zasm::x86::Reg zreg((zasm::x86::Reg::Id)reg);
	zasm::x86::Gp  reg_gp((zasm::x86::Reg::Id)reg);
	uint64_t value = immediate_value;
	if (zreg.getBitSize(zasm::MachineMode::AMD64) == zasm::BitSize::_8)
		value &= 0xff;
	else if (zreg.getBitSize(zasm::MachineMode::AMD64) == zasm::BitSize::_16)
		value &= 0xffff;
	else if (zreg.getBitSize(zasm::MachineMode::AMD64) == zasm::BitSize::_32)
		value &= 0xffffffff;
	zasm::Imm src_imm(value);
	zasm::Error err = assembler.mov(reg_gp, src_imm);
	if (err != zasm::Error::None)
		return false;
	// get machine code
	static zasm::Serializer serializer;
	err = serializer.serialize(program, 0);
	if (err != zasm::Error::None)
		return false;
	*code_len = (uint32_t)serializer.getCodeSize();
	if (*code_len > buffer_size)
		return false;
	memcpy(code, serializer.getCode(), *code_len);
	return true;
}

class AssemberWrapperTest {
public:
	AssemberWrapperTest() {
		uint8_t code[256] = { 0 };
		uint32_t code_len = 0;
		// mov rcx, [rsp + 0x12345678] -> 48 8b 8c 24 78 56 34 12
		AssembleLoadStack(
			0x12345678,
			ZYDIS_REGISTER_RCX,
			code,
			sizeof(code),
			&code_len);
		// mov [rsp + 0x12345678], rcx -> 48 89 8c 24 78 56 34 12
		AssembleSaveStack(
			0x12345678,
			ZYDIS_REGISTER_RCX,
			code,
			sizeof(code),
			&code_len);
	}
};

//static AssemberWrapperTest g_AssemberWrapperTest;
