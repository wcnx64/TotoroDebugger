#ifndef _VM_H_
#define _VM_H_

#include <vector>
#include <stdint.h>

#include "ArithmeticTree.h"

/// <summary>
/// Totoro VM for analyzing VMProtect
/// </summary>
namespace tvm {
	/// <summary>
	/// flags defined for Ins::flag
	/// </summary>
	enum INS_FLAG {
		INS_FLAG_CONTROL_FLOW = 1,
		INS_FLAG_JMP          = 2,
		INS_FLAG_CONDITIONAL  = 4,
		INS_FLAG_CALL         = 8,
		INS_FLAG_RET          = 16,
		INS_FLAG_WITH_REG     = 32,
		INS_FLAG_WITH_MEM     = 64,
		INS_FLAG_PUSH         = 128
	};
	/// <summary>
	/// assembly instruction
	/// </summary>
	typedef class Ins {
	public:
		uint64_t addr;         // instruction address
		uint32_t flag;         // combination of INS_FLAG
		uint64_t des_mem_addr; // destination memory address, 0 for unset
		uint64_t src_mem_addr; // src memory address, 0 for unset
		uint32_t code_len;     // length of instruction
		uint8_t  code[16];     // machine code of instructiion
	public:
		void Print(); // print readable assembly code
	} Ins, *PIns;

	/// <summary>
	/// position in a vm group
	/// </summary>
	typedef struct Position {
		uint64_t addr;
		uint64_t vm_ins_index;
		uint64_t block_index;
		uint64_t ins_index;
	} Position, * PPosition;

	/// <summary>
	/// to trace of a jmp, call, ret, etc.
	/// </summary>
	typedef struct JmpInfo {
		Position from;
		Position to;
	} JmpInfo, * PJmpInfo;

	/// <summary>
	/// block of continuous assembly instructions
	/// InsBlock contains a pointer, so only store PInsBlock in container
	/// </summary>
	typedef class InsBlock {
	public:
		uint64_t addr;          // start address
		uint32_t length;        // lengthW
		uint32_t ins_count;     // count of instructions
		uint32_t ins_index;     // index of the first instruction
		bool     sensitive;     // whether the code contains sensitive operations
		bool     patched;       // whether the code is patched
		uint8_t* code;          // machine code
		std::vector<JmpInfo> in;  // previous instruction addresses to this instruction
		std::vector<JmpInfo> out; // next insruction addresses from this instruction
	public:
		/// <summary>
		/// constructor
		/// </summary>
		InsBlock() : addr(0), length(0),
			ins_count(0), ins_index(0),
			sensitive(nullptr), patched(false), code(nullptr) {}
		/// <summary>
		/// reset
		/// </summary>
		void Reset() {
			addr = 0;
			length = 0;
			ins_count = 0;
			ins_index = 0;
			patched = false;
			code = nullptr;
		}
	} InsBlock, *PInsBlock;

	/// <summary>
	/// VM Instruction, which is a sequance of assembly instructions.
	/// Storing VMIns in vector is slow, especially when reallocting.
	/// </summary>
	typedef class VmIns {
	public:
		VmIns();
		virtual ~VmIns();
		// deep copy
		VmIns* DeepCopy();
		// deep copy
		bool DeepCopy(VmIns* vm_ins);
		// reset
		void Reset();
		// reset blocks
		void ResetBlocks();
		// add assembly instruction to the sequence
		void AddIns(
			uint64_t addr,         // instruction address
			uint32_t flag,         // combination of INS_FLAG
			uint64_t des_mem_addr, // destination memory address, 0 for unset
			uint64_t src_mem_addr, // src memory address, 0 for unset
			uint8_t* code,         // machine code of instructiion
			uint32_t code_len      // length of instruction
			);
		// generate ins blocks
		bool GenerateBlocks();
		// get an ins block that meets the given requirements
		PInsBlock GetBlock(uint32_t start_index, uint32_t min_length);
		// print
		void Print();
	public:
		uint64_t index; // the index in a vm group, set to 0 when not in any vm groups
		bool     deleted; // if it is deleted
		bool     loop; // if it is in a loop
		// sequence stands for the sequence of its components.
		// Other members are for analysis and utility.
		std::vector<Ins>       sequence; // assembly instruction sequence
		std::vector<PInsBlock> blocks;   // for analysis and finding space to rewrite
		                                 // InsBlock contains a pointer, so store PInsBlock
		std::vector<POpNode>   trees;    // deepcopied trees
	} VmIns, * PVmIns;

	/// <summary>
	/// VM Instruction Group, which is a sequance of vm instructions
	/// </summary>
	typedef class VmInsGroup {
	public:
		virtual ~VmInsGroup();
		// reset
		void Reset();
		// add deep copied vm instruction to the sequence
		uint64_t AddVmIns(PVmIns vm_ins);
		// find the VmIns that contain the Ins
		bool FindVmInsByInsAddr(uint64_t addr, Position& pos);
		// register a jump (jmp, call, ret, etc.) in the VmIns' relations
		bool RegisterJmp(uint64_t from, uint64_t to);
		// return reduced rate
		double GetReducedRate();
	public:
		// sequence stands for the sequence of its components.
		// Other members are for analysis.
		// Storing VMIns in vector is slow, especially when reallocting.
		std::vector<PVmIns> sequence;
	} *PVmInsGroup;
}

#endif // _VM_H_