#include <windows.h>
#include <vector>
#include <algorithm>
#include "InstructionTrace.h"
#include "ArithmeticTree.h"
#include "ForestReducer.h"
#include "MemoryTracer.h"
#define ZYDIS_STATIC_BUILD
extern "C" {
#include "zydis/Zydis.h"
}
#include "Op.h"
#include "IO.h"
#include "hack_aes.h"
#include "ImagePatcher.h"
#include "Assembler.h"
#include "snapshot.h"

// TODO: singleton analytical tookit wrapper
#define Tools AnalyticalToolkitWrapper::Instance()

static IArithmeticForest*    g_forest;              // for tracking and analyzing arithmetic operations
static INumberFilter*        g_filter;              // for reductions of forest
static IMemoryTracer*        g_input_tracer;        // for tracing input memory references
static IMemoryTracer*        g_output_tracer;       // for tracing output memory references
static std::vector<OpNode*>  g_io_path_trees;       // trees from the input to the output
static IMemoryBlockAnalyzer* g_mem_block_analyzer;  // for analyzing memory references
static ISnapshotMgr*         g_snapshot_mgr;        // for snapshot and repeating execution

#define SCENARIO_INIT   0
#define SCENARIO_TRACE  1
#define SCENARIO_REDUCE 2
#define SCENARIO_PATCH  3
#define SCENARIO_FINISH -1
static int                   g_scenario = SCENARIO_INIT;
static int                   g_snapshot_id;

static uint32_t              g_stack_reg;
static uint64_t              g_stack_base;

static uint64_t              g_vm_ins_group_starting_rsp; // the current vm instruction group starting rsp
static tvm::VmIns            g_vm_ins;                    // the current vm instruction
static tvm::VmInsGroup       g_vm_ins_group;              // the current vm instruction group
static tvm::Position         g_last_pos;                  // the last position


/// <summary>
/// initialize the trace facilities
/// </summary>
/// <returns>succeeded or not</returns>
bool InitTrace() {
	if (g_filter == nullptr) {
		g_filter = CreateNumberFilter();
		if (g_filter == nullptr)
			return false;
	}
	if (g_forest == nullptr) {
		g_forest = CreateArithmeticForest();
		if (g_forest == nullptr) {
			return false;
		}
	}
	if (g_input_tracer == nullptr) {
		g_input_tracer = CreateMemoryTracer();
		if (g_input_tracer == nullptr) {
			return false;
		}
	}
	if (g_output_tracer == nullptr) {
		g_output_tracer = CreateMemoryTracer();
		if (g_output_tracer == nullptr) {
			return false;
		}
	}
	if (g_mem_block_analyzer == nullptr) {
		g_mem_block_analyzer = CreateMemoryBlockAnalyzer();
		if (g_mem_block_analyzer == nullptr) {
			return false;
		}
	}
	if (g_snapshot_mgr == nullptr) {
		g_snapshot_mgr = CreateSnapshotMgr();
		if (g_snapshot_mgr == nullptr) {
			return false;
		}
	}
	return true;
}

/// <summary>
/// set the stack register used by VMP and
/// the current initial stack address
/// </summary>
/// <param name="stack_reg">the stack register used by VMP</param>
/// <param name="stack_addr">the current initial stack address</param>
void SetStackRegisterAndAddr(uint32_t stack_reg, uint64_t stack_addr) {
	g_stack_reg = stack_reg;
	g_stack_base = stack_addr;
}

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
	) {
	if (g_scenario == SCENARIO_TRACE) {
		g_vm_ins.AddIns(addr, flag, des_mem_addr, src_mem_addr, code, code_len);
	}
}

/// <summary>
/// trace loading memory to register
/// </summary>
/// <param name="ins_addr">the instruction address</param>
/// <param name="reg">the destination register</param>
/// <param name="addr">the source memory</param>
void TraceLoadMem(uint64_t ins_addr, uint32_t reg, uint64_t addr) {
	if (g_scenario == SCENARIO_TRACE) {
		uint64_t value = 0;
		IoReadProcessMemory(addr, &value, sizeof(value));
		value &= IoGetRegisterMask(reg);
		g_forest->AddNode(ins_addr, ZYDIS_MNEMONIC_MOV, ZYDIS_OPERAND_TYPE_REGISTER, IoGet64bitRegister(reg), 0,
			ZYDIS_OPERAND_TYPE_MEMORY, addr, value);
	}
}

/// <summary>
/// trace saving memory from register
/// </summary>
/// <param name="ins_addr">the instruction address</param>
/// <param name="addr">the destination memory</param>
/// <param name="reg">the source register</param>
void TraceSaveMem(uint64_t ins_addr, uint64_t addr, uint32_t reg) {
	if (g_scenario == SCENARIO_TRACE) {
		uint64_t value = IoReadRegister(reg);
		g_forest->AddNode(ins_addr, ZYDIS_MNEMONIC_MOV, ZYDIS_OPERAND_TYPE_MEMORY, addr, 0,
			ZYDIS_OPERAND_TYPE_REGISTER, IoGet64bitRegister(reg), value);
	}
	if (g_scenario == SCENARIO_TRACE) {
		g_snapshot_mgr->AddMem(g_snapshot_id, ins_addr);
	}
}

/// <summary>
/// trace saving memory from register,
/// also trace the memory reference details
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
	bool has_displacement, uint64_t displacement_value) {
	if (g_scenario == SCENARIO_TRACE) {
		g_forest->AddNode(ins_addr, ZYDIS_MNEMONIC_MOV, ZYDIS_OPERAND_TYPE_MEMORY, addr, 0,
			ZYDIS_OPERAND_TYPE_REGISTER, IoGet64bitRegister(src_reg), IoReadRegister(src_reg));
		g_forest->SetNodeMemRefSubTree(addr, base, IoReadRegister(base),
			has_index, index, IoReadRegister(index), scale,
			has_displacement, displacement_value);
	}
	if (g_scenario == SCENARIO_TRACE) {
		g_snapshot_mgr->AddMem(g_snapshot_id, ins_addr);
	}
}

/// <summary>
/// trace mov des_reg, src_reg
/// </summary>
/// <param name="ins_addr">the instruction address</param>
/// <param name="des_reg">the destination register</param>
/// <param name="src_reg">the source register</param>
void TraceMovRR(uint64_t ins_addr, uint32_t des_reg, uint32_t src_reg) {
	if (g_scenario == SCENARIO_TRACE) {
		uint64_t src_value = IoReadRegister(src_reg);
		g_forest->AddNode(ins_addr, ZYDIS_MNEMONIC_MOV, ZYDIS_OPERAND_TYPE_REGISTER, IoGet64bitRegister(des_reg), src_value,
			ZYDIS_OPERAND_TYPE_REGISTER, IoGet64bitRegister(src_reg), src_value);
	}
}

/// <summary>
/// trace unitary arithmetic operations which takes only one operand
/// </summary>
/// <param name="ins_addr">the instruction address</param>
/// <param name="op">operator</param>
/// <param name="reg">the register to operate on</param>
void TraceUnitaryArithmetic(uint64_t ins_addr, int op, uint32_t reg) {
	if (g_scenario == SCENARIO_TRACE) {
		uint64_t value = IoReadRegister(reg);
		g_forest->AddNode(ins_addr, op, reg, value);
	}
}

/// <summary>
/// trace op des_reg, src_reg
/// an binary arithmetic operation taking two operands
/// </summary>
/// <param name="ins_addr">the instruction address</param>
/// <param name="op">operator</param>
/// <param name="des_reg">the destination register</param>
/// <param name="src_reg">the source register</param>
void TraceBinaryArithmeticRR(uint64_t ins_addr, int op, uint32_t des_reg, uint32_t src_reg) {
	if (g_scenario == SCENARIO_TRACE) {
		uint64_t des_value = IoReadRegister(des_reg);
		uint64_t src_value = IoReadRegister(src_reg);
		g_forest->AddNode(ins_addr, op, ZYDIS_OPERAND_TYPE_REGISTER, IoGet64bitRegister(des_reg), des_value,
			ZYDIS_OPERAND_TYPE_REGISTER, IoGet64bitRegister(src_reg), src_value);
	}
}

/// <summary>
/// trace op reg, imm
/// </summary>
/// <param name="ins_addr">the instruction address</param>
/// <param name="op">operator</param>
/// <param name="reg">the destination register</param>
/// <param name="value">th immediate value</param>
void TraceBinaryArithmeticRI(uint64_t ins_addr, int op, uint32_t reg, uint64_t value) {
	if (g_scenario == SCENARIO_TRACE) {
		uint64_t reg_value = IoReadRegister(reg);
		g_forest->AddNode(ins_addr, op, ZYDIS_OPERAND_TYPE_REGISTER, IoGet64bitRegister(reg), reg_value,
			ZYDIS_OPERAND_TYPE_IMMEDIATE, 0, value);
	}
}

/// <summary>
/// multiply a register's value with a factor
/// </summary>
/// <param name="ins_addr">instruction address</param>
/// <param name="reg">the register whose value
/// is multiplied with the factor</param>
/// <param name="factor">the factor to multiply with</param>
void TraceMulFactor(uint64_t ins_addr, uint32_t reg, double factor) {
	if (g_scenario == SCENARIO_TRACE) {
		g_forest->SetNodeFactor(IoGet64bitRegister(reg), factor);
	}
}

void AssociateArithmeticMemories(
	OpNode*  node,
	uint64_t des_addr,
	int      des_layer,
	int      layer_of_associates,
	int      depth_remainded) {
	if (depth_remainded <= 0)
		return;
	if (node->type == ZYDIS_OPERAND_TYPE_MEMORY) {
		g_output_tracer->Associate(des_addr, des_layer, node->addr, layer_of_associates, node->ins_addr);
	}
	if (node->left)
		AssociateArithmeticMemories(node->left, des_addr, des_layer, layer_of_associates, depth_remainded - 1);
	if (node->right)
		AssociateArithmeticMemories(node->right, des_addr, des_layer, layer_of_associates, depth_remainded - 1);
}

// test and debug
void FinishVmInsGroupUnprotected(uint8_t* addr, void* user_data) {
	g_filter->SetDefault(false);
	// call    qword ptr [protected!_imp_memcpy]
	uint64_t rdx = IoReadRegister((uint32_t)ZYDIS_REGISTER_RDX);
	uint8_t cipher[16] = { 0 };
	IoReadProcessMemory(rdx, cipher, sizeof(cipher));
	for (int i = 0; i < 16; i++) {
		printf("%02x", cipher[i]);
	}
	putchar('\n');
	g_filter->AddRuleBetweenULL(true, rdx, true, rdx + 0x10, false);
	g_forest->ReduceByType(true, ZYDIS_OPERAND_TYPE_MEMORY);
	g_forest->ReduceByNumberFilter(ZYDIS_OPERAND_TYPE_MEMORY, g_filter);
	g_forest->ReduceByDepth(5);
	auto forest = g_forest->GetTrees();
	for (auto i = forest->begin(); i != forest->end(); i++) {
		int layer = 1;
		g_output_tracer->Add((*i)->addr, layer, (*i)->ins_addr);
		if ((*i)->left)
			AssociateArithmeticMemories((*i)->left, (*i)->addr, layer, layer + 1, 5);
		if ((*i)->right)
			AssociateArithmeticMemories((*i)->right, (*i)->addr, layer, layer + 1, 5);
	}
	//g_forest->Reduce();
	//g_forest->Print(forest);
	//forest->clear();
	//g_forest->Print();
	//g_output_tracer->Print(1, true);
	g_mem_block_analyzer->AnalyzeData(g_output_tracer, 0, NULL);
	g_mem_block_analyzer->Print();
	uint8_t partial_round_key[16] = { 0 };
	for (auto i = forest->begin(); i != forest->end(); i++) {
		partial_round_key[i - forest->begin()] = (uint8_t)(*i)->left->right->value;
	}
	ha_ctx* ctx = ha_build_aes_ctx(128);
	ha_set_roundkey(ctx, partial_round_key, 160, 16);
	uint8_t* key = ha_calulate_key(ctx);
	for (int i = 0; i < 16; i++) {
		printf("0x%02x, ", key[i]);
	}
	putchar('\n');
	printf("%s\n", key);
	g_forest->Reset();
	getchar();
}

// test for real case: VmP on inline cipher
void FinishVmInsGroupVmpInline(uint8_t* addr, void* user_data) {
	g_filter->SetDefault(false);
	// copy block result, copy(final_result + offset, current_block_result, 16)
	uint64_t rdx = IoReadRegister((uint32_t)ZYDIS_REGISTER_RDX);
	uint8_t cipher[16] = { 0 };
	IoReadProcessMemory(rdx, cipher, sizeof(cipher));
	for (int i = 0; i < 16; i++) {
		printf("%02x", cipher[i]);
	}
	putchar('\n');
	g_filter->AddRuleBetweenULL(true, rdx, true, rdx + 0x10, false);
	g_forest->ReduceByType(true, ZYDIS_OPERAND_TYPE_MEMORY);
	g_forest->ReduceByNumberFilter(ZYDIS_OPERAND_TYPE_MEMORY, g_filter);
	g_forest->ReduceByDepth(5);
	auto forest = g_forest->GetTrees();
	for (auto i = forest->begin(); i != forest->end(); i++) {
		int layer = 1;
		g_output_tracer->Add((*i)->addr, layer, (*i)->ins_addr);
		if ((*i)->left)
			AssociateArithmeticMemories((*i)->left, (*i)->addr, layer, layer + 1, 5);
		if ((*i)->right)
			AssociateArithmeticMemories((*i)->right, (*i)->addr, layer, layer + 1, 5);
	}
	//g_forest->Reduce();
	//g_forest->Print(forest);
	//forest->clear();
	//g_forest->Print();
	//g_output_tracer->Print(1, true);
	g_mem_block_analyzer->AnalyzeData(g_output_tracer, 0, NULL);
	g_mem_block_analyzer->Print();
	uint8_t partial_round_key[16] = { 0 };
	for (auto i = forest->begin(); i != forest->end(); i++) {
		partial_round_key[i - forest->begin()] = (uint8_t)(*i)->left->right->value;
	}
	ha_ctx* ctx = ha_build_aes_ctx(128);
	ha_set_roundkey(ctx, partial_round_key, 160, 16);
	uint8_t* key = ha_calulate_key(ctx);
	for (int i = 0; i < 16; i++) {
		printf("0x%02x, ", key[i]);
	}
	putchar('\n');
	printf("%s\n", key);
	g_forest->Reset();
	getchar();
}

void FinishVmInsAesVmpInline() {
	g_forest->ReduceByType(true, ZYDIS_OPERAND_TYPE_MEMORY);
	auto forest = g_forest->GetTrees();
	if (forest->size() > 0x60) {
		g_output_tracer->Clear();
		for (auto i = forest->begin(); i != forest->end(); i++)
			g_output_tracer->Add((*i)->addr, 1, (*i)->ins_addr);
		g_mem_block_analyzer->Clear();
		// distance threshold = 1
		// item count threshold = 8
		int   argc = 2;
		void* argv[] = { (void*)1, (void*)8 };
		g_mem_block_analyzer->AnalyzeData(g_output_tracer, argc, argv);
		g_mem_block_analyzer->Print();
		auto blocks = g_mem_block_analyzer->GetMemoryBlocks(1);
		if (blocks.size() > 0) {
			for (auto i = blocks.begin(); i != blocks.end(); i++) {
				g_filter->AddRuleBetweenULL(true, i->start_addr, true, i->end_addr, true);
			}
			g_forest->ReduceByNumberFilter(ZYDIS_OPERAND_TYPE_MEMORY, g_filter);
			forest = g_forest->GetTrees();
			g_output_tracer->Clear();
			for (auto i = forest->begin(); i != forest->end(); i++) {
				int layer = 1;
				g_output_tracer->Add((*i)->addr, layer, (*i)->ins_addr);
				if ((*i)->left)
					AssociateArithmeticMemories((*i)->left, (*i)->addr, layer, layer + 1, 256);
				if ((*i)->right)
					AssociateArithmeticMemories((*i)->right, (*i)->addr, layer, layer + 1, 256);
			}
			g_mem_block_analyzer->Clear();
			g_mem_block_analyzer->AnalyzeData(g_output_tracer, 0, NULL);
			g_mem_block_analyzer->Print();
			auto read_blocks = g_mem_block_analyzer->GetMemoryBlocks(2);
			for (auto i = read_blocks.begin(); i != read_blocks.end(); i++) {
				uint8_t print_mem[256] = { 0 };
				int           print_mem_length = (int)((i->end_addr - i->start_addr) < sizeof(print_mem) ?
					(i->end_addr - i->start_addr) : sizeof(print_mem));
				IoReadProcessMemory(i->start_addr, print_mem, print_mem_length);
				for (int j = 0; j < print_mem_length; j++) {
					printf("[0x%llx] 0x%lx, %c\n", i->start_addr + j, print_mem[j], print_mem[j]);
				}
			}
		}
		puts("Finish!");
		puts("Press Any Key to Exit...");
		getchar();
		exit(0);
	}
}

bool StartVmpPatch(uint64_t addr) {
	g_vm_ins.Reset();
	return StartVmInsGroup(addr);
}

void FinishVmpPatch(uint64_t addr) {
	auto& seq = g_vm_ins_group.sequence;
	for (auto i = seq.begin(); i != seq.end(); i++) {
		for (auto j = (*i)->blocks.begin(); j != (*i)->blocks.end(); j++) {
			if ((*j)->in.size() >= 2) {
				printf("[0x%lx, 0x%llx]", (*j)->ins_index, j - (*i)->blocks.begin());
				printf(" <- ");
				for (auto k = (*j)->in.begin() + 1; k != (*j)->in.end(); k++) {
					printf("[0x%llx, 0x%llx]", k->from.ins_index, k->from.block_index);
				}
				putchar('\n');
			}
		}
	}
	//PatchFile(&g_vm_ins_group);
	g_forest->Reset();
}

#define ASSEMBLE_ERROR(X, DO_STH) if (!X) { \
	printf("Error Generating Codes...\n"); \
	/*getchar();*/ DO_STH; \
	}

bool WriteCodeIntoBlocks(
	tvm::PInsBlock& cb, // current block
	uint32_t& cb_offset,
	uint32_t& cb_remainded_space,
	uint8_t*  code,
	uint32_t& offset,
	uint32_t& len) {
	if (cb_remainded_space < len + ASSEMBLE_JMP_SIZE) {
		// need a new block
		tvm::PInsBlock new_block = g_vm_ins.GetBlock(cb->ins_index + 1, len + ASSEMBLE_JMP_SIZE);
		if (new_block == nullptr) {
			printf("Can't find a big enough block!\n");
			return false;
		}
		// nop it
		if (new_block->length > 5)
			memset(new_block->code, 0x90, new_block->length - 5);
		// write code into the new block
		memcpy(new_block->code, code + offset, len);
		new_block->patched = true;
		// jmp from the current block to the new block
		uint32_t jmp_len = 0;
		AssembleJmp(cb->addr + cb_offset, new_block->addr,
			cb->code + cb_offset, cb_remainded_space, &jmp_len); // it won't fail
		// set new block as the current block and update parameters
		cb = new_block;
		cb_offset = len;
		cb_remainded_space = cb->length - len;
	}
	else {
		// use space in the current block
		memcpy(cb->code + cb_offset, code + offset, len);
		cb_offset += len;
		cb_remainded_space -= len;
	}
	return true;
}

void FinishVmInsPatch() {/*
	if (g_vm_ins.sequence.size() == 0) {
		printf("The Vm Instruction is empty!\n");
		return;
	}
	g_vm_ins.GenerateBlocks();
	g_forest->SetStackAddress(g_stack_base);
	//uint64_t rsp = IoReadRegister(ZYDIS_REGISTER_RSP);
	//uint64_t ret_addr = 0;
	//IoReadProcessMemory(rsp, &ret_addr, sizeof(ret_addr));
	//ReduceJunkCodesVmIns(g_forest, g_stack_base, rsp);
	printf("================ Vm Instruction [0x%llx]\n", g_vm_ins_group.sequence.size());
	// g_forest->Print();
	auto forest = g_forest->GetTrees();
	//g_forest->Print();
	// equilavently reduce the vm ins' assembly instruction number
	uint8_t code[1024] = { 0 };
	uint32_t offset = 0;
	uint32_t len = 0;
	bool          assemble_success = false;
	do {
		// push rcx
		assemble_success = AssemblePush(ZYDIS_REGISTER_RCX, code + offset, sizeof(code), &len);
		ASSEMBLE_ERROR(assemble_success, break);
		// reduced codes
		tvm::PInsBlock cb = g_vm_ins.GetBlock(0, len + ASSEMBLE_JMP_SIZE); // current block
		uint32_t  cb_offset = len;
		uint32_t  cb_remainded_space = cb ? cb->length - len : 0;
		if (cb == nullptr) {
			printf("Can't find a big enough block!\n");
			return;
		}
		// nop it
		if (cb->length > 5)
			memset(cb->code, 0x90, cb->length - 5);
		// write code into the new block
		memcpy(cb->code, code + offset, len);
		cb->patched = true;
		// update code offset
		offset += len;
		for (auto i = forest->begin(); i != forest->end(); i++) {
			assemble_success = AssembleTree(*i, g_vm_ins_starting_rsp, ZYDIS_REGISTER_RCX, code + offset, sizeof(code), &len);
			ASSEMBLE_ERROR(assemble_success, break);
			// write code into the blocks
			assemble_success = WriteCodeIntoBlocks(cb, cb_offset, cb_remainded_space, code, offset, len);
			ASSEMBLE_ERROR(assemble_success, break);
			// update code offset
			offset += len;
		}
		// pop rcx
		assemble_success = AssemblePop(ZYDIS_REGISTER_RCX, code + offset, sizeof(code), &len);
		ASSEMBLE_ERROR(assemble_success, break);
		// write code into the blocks
		assemble_success = WriteCodeIntoBlocks(cb, cb_offset, cb_remainded_space, code, offset, len);
		ASSEMBLE_ERROR(assemble_success, break);
		offset += len;
		// jmp to the end of vm ins
		assemble_success = AssembleJmp(cb->addr + cb_offset, ret_addr, code + offset, sizeof(code), &len);
		ASSEMBLE_ERROR(assemble_success, break);
		// write code into the blocks
		assemble_success = WriteCodeIntoBlocks(cb, cb_offset, cb_remainded_space, code, offset, len);
		ASSEMBLE_ERROR(assemble_success, break);
		offset += len;
		// patch the file
	} while (false);
	//g_vm_ins.Print();
	PatchFile(g_vm_ins, (g_vm_ins_group.sequence.size() == 0));
	// add vm instruction to vm instruction group
	g_vm_ins_group.AddVmIns(&g_vm_ins);
	g_vm_ins.Reset();
	g_forest->Reset();
	double reduced_rate = 0;
	//printf("================ Reduced Rate: %lf\n", reduced_rate);
	uint64_t stack_top = 0;
	rsp = IoReadRegister(ZYDIS_REGISTER_RSP);
	IoReadProcessMemory(rsp, &stack_top, sizeof(stack_top));
	printf("================ Stack Top: 0x%llx\n", stack_top);
	getchar();
	//g_snapshot_mgr->Restore(1);*/
}

bool StartVmInsTrace(uint64_t addr) {
	//g_snapshot_mgr->TakeSnapshot(&g_snapshot_id);
	return true;
}

bool AddSensitiveMemoryToInputTracor(OpNode* node, bool hit) {
	if (!hit) {
		if (g_input_tracer->Get(node->addr, 2)) {
			//printf("hit [0x%llx]\n", node->addr);
			return true;
		}
		g_input_tracer->Add(node->addr, 2, node->ins_addr);
		int64_t offset_from_rsp = (int64_t)node->addr - (int64_t)g_vm_ins_group_starting_rsp;
		printf("tracing [%c0x%llx]\n", offset_from_rsp ? '+' : '-', abs(offset_from_rsp));
		return true;
	}
	return false;
}

void FinishVmInsTrace(uint64_t addr) {
	if (g_vm_ins.sequence.size() == 0) {
		printf("The Vm Instruction is empty!\n");
		return;
	}
	// the forest
	bool sensitive_mem_hit = false;
	g_forest->ReduceByType(true, ZYDIS_OPERAND_TYPE_MEMORY);
	auto forest = g_forest->GetTrees();
	for (auto i = forest->begin(); i != forest->end();) {
		bool sensitive_tree = false;
		// check if the tree contains layer 1 memory
		int layer = 1;
		PMemoryItem mem = g_input_tracer->FirstMem(layer);
		while (mem) {
			bool hit = (*i)->SearchAddrUp(ZYDIS_OPERAND_TYPE_MEMORY, mem->addr,
				AddSensitiveMemoryToInputTracor);
			sensitive_tree |= hit;
			mem = g_input_tracer->NextMem(layer);
		}
		// check if the tree contains layer 2 memory
		layer = 2;
		mem = g_input_tracer->FirstMem(layer);
		while (mem) {
			bool hit = (*i)->SearchAddrUp(ZYDIS_OPERAND_TYPE_MEMORY, mem->addr,
				AddSensitiveMemoryToInputTracor);
			sensitive_tree |= hit;
			mem = g_input_tracer->NextMem(layer);
		}
		// whether or not the forest contains sensitive memory
		sensitive_mem_hit |= sensitive_tree;
		// update forest and go to next tree
		if (sensitive_tree) {
			i++;
		}
		else {
			g_forest->DeleteTree(*i);
		}
	}
	if (sensitive_mem_hit) {
		//g_forest->Reduce();
		//g_forest->Print();
		//getchar();
	}
	// instructions
	// if the current instruction is worth tracked
	if (sensitive_mem_hit) {
		g_vm_ins.GenerateBlocks();
		// add deep copied vm instruction to vm instruction group
		uint64_t vm_ins_index = g_vm_ins_group.AddVmIns(&g_vm_ins);
		if (vm_ins_index == g_vm_ins_group.sequence.size() - 1) { // new vm instruction
			auto& vm_ins = g_vm_ins_group.sequence[vm_ins_index];
			auto selected_forest = g_forest->GetTrees();
			for (auto i = selected_forest->begin(); i != selected_forest->end(); i++) {
				vm_ins->trees.push_back((*i)->DeepCopy());
			}
		}
		else {
			auto& vm_ins = g_vm_ins_group.sequence[vm_ins_index];
			vm_ins->loop = true;
			//printf("loop index 0x%llx\n", vm_ins_index);
		}
		// register jmp
		tvm::Position pos = { 0 };
		//bool ret = g_vm_ins_group.FindVmInsByInsAddr(addr, pos);
		pos.vm_ins_index = vm_ins_index;
		//if (ret) {
			tvm::JmpInfo jmp;
			jmp.from = g_last_pos;
			jmp.to = pos;
			auto& in_vm_ins = g_vm_ins_group.sequence[pos.vm_ins_index];
			//auto& in_block = in_vm_ins->blocks[pos.block_index];
			auto& in_block = in_vm_ins->blocks[0];
			bool duplicated = false;
			for (auto i = in_block->in.begin(); i != in_block->in.end(); i++) {
				if (i->from.vm_ins_index == jmp.from.vm_ins_index) {
					duplicated = true;
					break;
				}
			}
			if (!duplicated) {
				in_block->in.push_back(jmp);
				auto& out_vm_ins = g_vm_ins_group.sequence[g_last_pos.vm_ins_index];
				//auto& out_block = out_vm_ins->blocks[g_last_pos.block_index];
				auto& out_block = out_vm_ins->blocks[0];
				out_block->out.push_back(jmp);
			}
		//}
		// save current position
		g_last_pos.addr = addr;
		g_last_pos.ins_index = g_vm_ins.sequence.size() - 1;
		g_last_pos.block_index = g_vm_ins.blocks.size() - 1;
		g_last_pos.vm_ins_index = vm_ins_index;
		//printf("================ Vm Instruction [0x%llx]\n", vm_ins_index);
	}
	g_vm_ins.Reset();
	//getchar();
	//g_snapshot_mgr->Restore(1);
	g_forest->Reset();
}

bool StartVmInsReduce(uint64_t addr) {
	return true;
}

void FinishVmInsReduce(uint64_t addr) {
}

bool StartVmIns(uint64_t addr) {
	if (g_scenario == SCENARIO_TRACE) {
		return StartVmInsTrace(addr);
	}
	else if (g_scenario == SCENARIO_REDUCE) {
		return StartVmInsReduce(addr);
	}
	return false;
}

void FinishVmIns(uint64_t addr) {
	if (g_scenario == SCENARIO_TRACE) {
		FinishVmInsTrace(addr);
	}
	else if (g_scenario == SCENARIO_REDUCE) {
		FinishVmInsReduce(addr);
	}
}

bool StartVmInsGroupTrace(uint64_t addr) {
	g_vm_ins_group_starting_rsp = IoReadRegister(ZYDIS_REGISTER_RSP);
	//uint32_t mem_offsets[] = { 0x80, 0x88, // param1
	//                           -0x50, // param2, rdx is stored at this addr
	//                           -0x68, // param2, rax, which holds the value of rdx, is pushed into stack
	//                           0x90, 0x98 // param3
    //                         };
	int64_t input_offsets[] = { 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
		                        0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f };
	for (int i = 0; i < sizeof(input_offsets) / sizeof(input_offsets[0]); i++)
		g_input_tracer->Add(g_vm_ins_group_starting_rsp + input_offsets[i], 1, addr);
	int64_t output_offsets[] = { 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
		                         0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f };
	for (int i = 0; i < sizeof(output_offsets) / sizeof(output_offsets[0]); i++)
		g_output_tracer->Add(g_vm_ins_group_starting_rsp + output_offsets[i], 1, addr);
	g_forest->Reset();
	g_forest->SetStackAddress(g_vm_ins_group_starting_rsp);
	return true;
}

bool BuildNewIoPathTrees(OpNode* node, bool hit) {
	if (hit) {
		for (auto i = g_io_path_trees.begin(); i != g_io_path_trees.end(); i++) {
			if ((*i)->IsEqual(node, false)) {
				return true;
			}
		}
		g_io_path_trees.push_back(node->DeepCopy());
	}
	return true;
}

void FinishVmInsGroupTrace(uint64_t addr) {
	printf("Vm Ins Count: 0x%llx\n", g_vm_ins_group.sequence.size());
	auto& seq = g_vm_ins_group.sequence;
	for (auto i = seq.rbegin(); i != seq.rend(); i++) {
		// forest
		for (auto j = (*i)->trees.rbegin(); j != (*i)->trees.rend();) {
			//(*j)->Print();
			bool essential_tree = false;
			// check if the tree contains layer 1 memory
			int layer = 1;
			PMemoryItem mem = g_output_tracer->FirstMem(layer);
			while (mem) {
				bool hit = (*j)->SearchAddrDown(ZYDIS_OPERAND_TYPE_MEMORY, mem->addr,
					BuildNewIoPathTrees);
				essential_tree |= hit;
				mem = g_output_tracer->NextMem(layer);
			}
			// merge trees
			if (g_io_path_trees.size() > 0) {
				for (auto k = g_io_path_trees.begin(); k != g_io_path_trees.end(); k++) {
					essential_tree |= (*k)->Merge(*j);
					if ((*k)->refer)
						essential_tree |= (*k)->refer->Merge(*j);
				}
			}
			// remove untraced tree
			if (!essential_tree) {
				delete *j;
				j++;
				(*i)->trees.erase(j.base());
			}
			else {
				j++;
			}
		}
		// mark vm instruction with no trees as deleted
		if ((*i)->trees.size() == 0) {
			(*i)->deleted = true;
			continue;
		}
	}
	//for (auto i = seq.begin(); i != seq.end(); i++) {
	//	if (!(*i)->deleted) {
	//		// blocks
	//		for (auto j = (*i)->blocks.begin(); j != (*i)->blocks.end(); j++) {
	//			if ((*j)->in.size() >= 2) {
	//				printf("[0x%llx, 0x%llx]", (*i)->index, j - (*i)->blocks.begin());
	//				printf(" <- ");
	//				for (auto k = (*j)->in.begin() + 1; k != (*j)->in.end(); k++) {
	//					printf("[0x%llx, 0x%llx]", k->from.vm_ins_index, k->from.block_index);
	//				}
	//				putchar('\n');
	//			}
	//		}
	//		// trees
	//		for (auto j = (*i)->trees.begin(); j != (*i)->trees.end(); j++) {
	//			(*j)->Print(0, g_vm_ins_group_starting_rsp);
	//		}
	//	}
	//}
	for (auto i = g_io_path_trees.begin(); i != g_io_path_trees.end(); i++) {
		g_forest->Reduce(*i);
		(*i)->ReduceByDepth(10);
		if ((*i)->refer)
			(*i)->refer->ReduceByDepth(10);
	}
	printf("Reduced\n");
	for (auto i = g_io_path_trees.begin(); i != g_io_path_trees.end(); i++) {
		(*i)->Print(0, g_vm_ins_group_starting_rsp);
		(*i)->PrintRefer(0, g_vm_ins_group_starting_rsp);
		printf("0x%llx\n", g_vm_ins_group_starting_rsp);
	}
	putchar('\n');
}

bool StartVmInsGroup(uint64_t addr) {
	printf("====Enter Vm====\n");
	if (g_scenario == SCENARIO_INIT) {
		StartVmInsGroupTrace(addr);
		g_snapshot_mgr->TakeSnapshot(&g_snapshot_id, addr);
		g_scenario = SCENARIO_TRACE;
	}
	else if (g_scenario == SCENARIO_REDUCE) {
		;
	}
	return true;
}

void FinishVmInsGroup(uint64_t addr, bool* repeat) {
	printf("====Exit Vm====\n");
	//getchar();
	if (g_scenario == SCENARIO_TRACE) {
		FinishVmInsGroupTrace(addr);
		g_scenario = SCENARIO_REDUCE;
		g_snapshot_mgr->Restore(g_snapshot_id);
		*repeat = true;
	}
	else if (g_scenario == SCENARIO_REDUCE) {
		g_scenario = SCENARIO_PATCH;
		g_snapshot_mgr->Restore(g_snapshot_id);
		*repeat = true;
	}
	else if (g_scenario == SCENARIO_PATCH) {
		g_scenario = SCENARIO_FINISH;
		*repeat = false;
	}
	else {
		*repeat = false;
	}
	return;
	g_filter->SetDefault(false);
	g_filter->AddRuleEqualULL(true, ZYDIS_REGISTER_RDX); // 2nd parameter of printf
	g_forest->ReduceByType(true, ZYDIS_OPERAND_TYPE_REGISTER);
	g_forest->ReduceByNumberFilter(ZYDIS_OPERAND_TYPE_REGISTER, g_filter);
	g_forest->Reduce();
	//g_forest->Print(forest);
	//forest->clear();
	//g_forest->Print();
	//g_forest->Reset();
	//getchar();
}

/// <summary>
/// get the initial stack address of the vm ins group
/// </summary>
/// <returns>the initial stack address of the vm ins group</returns>
uint64_t GetVmInsGroupStackAddr() {
	return g_vm_ins_group_starting_rsp;
}
