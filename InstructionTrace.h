#ifndef _INSTRUCTION_TRACE_H_
#define _INSTRUCTION_TRACE_H_

#include <stdint.h>

/// <summary>
/// initialize the trace facilities
/// </summary>
/// <returns>succeeded or not</returns>
bool InitTrace();

/// <summary>
/// start a vm ins group on the given instruction address
/// </summary>
/// <param name="addr">the instruction address</param>
/// <returns></returns>
bool StartVmInsGroup(uint64_t addr);

/// <summary>
/// Finish the current vm ins group on the given ins address.
/// The given address is included in the current vm ins group
/// as the last instruction.
/// </summary>
/// <param name="addr">the instruction address</param>
/// <param name="repeat">repeat running the current
/// vm ins group or not</param>
void FinishVmInsGroup(uint64_t addr, bool* repeat);

/// <summary>
/// get the initial stack address of the vm ins group
/// </summary>
/// <returns>the initial stack address of the vm ins group</returns>
uint64_t GetVmInsGroupStackAddr();

/// <summary>
/// start a new vm ins on the given instruction address
/// </summary>
/// <param name="addr">the instruction address</param>
/// <returns>succeeded or not</returns>
bool StartVmIns(uint64_t addr);

/// <summary>
/// Finish the current vm ins on the given ins address.
/// The given address is include in the current vm ins
/// as the last instruction.
/// </summary>
/// <param name="addr">the instruction address</param>
void FinishVmIns(uint64_t addr);

/// <summary>
/// set the stack register used by VMP and
/// the current initial stack address
/// </summary>
/// <param name="stack_reg">the stack register used by VMP</param>
/// <param name="stack_addr">the current initial stack address</param>
void SetStackRegisterAndAddr(uint32_t stack_reg, uint64_t stack_addr);

/// <summary>
/// trace a common instruction
/// </summary>
/// <param name="addr">instruction address</param>
/// <param name="flag">combination of INS_FLAG_XXX</param>
/// <param name="des_mem_addr">destination memory address, 0 for unset</param>
/// <param name="src_mem_addr">src memory address, 0 for unset</param>
/// <param name="code">machine code of instructiion</param>
/// <param name="code_len">length of instruction</param>
void TraceCommon(
	uint64_t addr,
	uint32_t flag,
	uint64_t des_mem_addr,
	uint64_t src_mem_addr,
	uint8_t* code,
	uint32_t code_len
);

/// <summary>
/// trace loading memory to register
/// </summary>
/// <param name="ins_addr">the instruction address</param>
/// <param name="reg">the destination register</param>
/// <param name="addr">the source memory</param>
void TraceLoadMem(uint64_t ins_addr, uint32_t reg, uint64_t addr);

/// <summary>
/// trace saving memory from register
/// </summary>
/// <param name="ins_addr">the instruction address</param>
/// <param name="addr">the destination memory</param>
/// <param name="reg">the source register</param>
void TraceSaveMem(uint64_t ins_addr, uint64_t addr, uint32_t reg);

/// </summary>
/// <param name="ins_addr">the instruction address</param>
/// <param name="addr">the destination memory</param>
/// <param name="src_reg">the source register</param>
/// <param name="base">the base register for memory reference</param
/// <param name="has_index">whether or not the index register is represent</param>
/// <param name="index">the index register for memory reference</param>
/// <param name="scale">the scale of the index register</param>
/// <param name="has_displacement">whether or not the displacement is present</param>
/// <param name="displacement_value">the value of the displacement</param>
void TraceSaveMemEx(uint64_t ins_addr, uint64_t addr, uint32_t src_reg,
	uint32_t base,
	bool has_index, uint32_t index, uint32_t scale,
	bool has_displacement, uint64_t displacement_value);

/// <summary>
/// trace mov des_reg, src_reg
/// </summary>
/// <param name="ins_addr">the instruction address</param>
/// <param name="des_reg">the destination register</param>
/// <param name="src_reg">the source register</param>
void TraceMovRR(uint64_t ins_addr, uint32_t des_reg, uint32_t src_reg);

/// <summary>
/// trace op reg
/// an unitary arithmetic operations which takes only one operand
/// </summary>
/// <param name="ins_addr">the instruction address</param>
/// <param name="op">operator</param>
/// <param name="reg">the register to operate on</param>
void TraceUnitaryArithmetic(uint64_t ins_addr, int op, uint32_t reg);

/// <summary>
/// trace op des_reg, src_reg
/// an binary arithmetic operation taking two operands
/// </summary>
/// <param name="ins_addr">the instruction address</param>
/// <param name="op">operator</param>
/// <param name="des_reg">the destination register</param>
/// <param name="src_reg">the source register</param>
void TraceBinaryArithmeticRR(
	uint64_t ins_addr,
	int      op,
	uint32_t des_reg,
	uint32_t src_reg
);

/// <summary>
/// trace op reg, imm
/// </summary>
/// <param name="ins_addr">the instruction address</param>
/// <param name="op">operator</param>
/// <param name="reg">the destination register</param>
/// <param name="value">th immediate value</param>
void TraceBinaryArithmeticRI(
	uint64_t ins_addr,
	int      op,
	uint32_t reg,
	uint64_t value
);

/// <summary>
/// multiply a register's value with a factor
/// </summary>
/// <param name="ins_addr">instruction address</param>
/// <param name="reg">the register whose value
/// is multiplied with the factor</param>
/// <param name="factor">the factor to multiply with</param>
void TraceMulFactor(uint64_t ins_addr, uint32_t reg, double factor);

// test and debug
void FinishVmInsGroupUnprotected(uint8_t* addr, void* user_data);
void FinishVmInsGroupVmpInline(uint8_t* addr, void* user_data);

#endif // _INSTRUCTION_TRACE_H_