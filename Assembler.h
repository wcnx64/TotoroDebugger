#ifndef _ASSEMBLER_H_
#define _ASSEMBLER_H_

#include "ArithmeticTree.h"

#define ASSEMBLE_JMP_SIZE 5

bool AssembleJmp(
	uint64_t  from,
	uint64_t  to,
	uint8_t*  code,
	uint32_t  buffer_size,
	uint32_t* code_len);

bool AssemblePush(
	uint32_t  reg,
	uint8_t*  code,
	uint32_t  buffer_size,
	uint32_t* code_len);

bool AssemblePop(
	uint32_t  reg,
	uint8_t*  code,
	uint32_t  buffer_size,
	uint32_t* code_len);

bool AssembleTree(
	OpNode*   node,
	uint64_t  stack_base,
	uint32_t  volatile_reg,
	uint8_t*  code,
	uint32_t  buffer_size,
	uint32_t* code_len);

bool AssembleLoadStack(
	uint64_t  stack_offset,
	uint32_t  des_reg,
	uint8_t*  code,
	uint32_t  buffer_size,
	uint32_t* code_len);

bool AssembleSaveStack(
	uint64_t  stack_offset,
	uint32_t  src_reg,
	uint8_t*  code,
	uint32_t  buffer_size,
	uint32_t* code_len);

// mov reg, imm
bool AssembleMovRI(
	uint32_t  reg,
	uint64_t  immediate_value,
	uint8_t*  code,
	uint32_t  buffer_size,
	uint32_t* code_len);

#endif // _ASSEMBLER_H_