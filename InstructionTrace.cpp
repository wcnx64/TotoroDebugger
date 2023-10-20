#include <windows.h>
#include <vector>
#include <algorithm>
#include "InstructionTrace.h"
#include "ArithmeticTree.h"
#include "MemoryTracer.h"
#define ZYDIS_STATIC_BUILD
extern "C" {
#include "Zydis.h"
}
#include "Op.h"
#include "IO.h"
#include "hack_aes.h"

static IArithmeticForest*    g_forest = nullptr;
static INumberFilter*        g_filter = nullptr;
static IMemoryTracer*        g_mem_tracer = nullptr;
static IMemoryBlockAnalyzer* g_mem_block_analyzer = nullptr;

static unsigned char* g_ExeBase = nullptr;

#define CHECK_RET() {if(!(g_forest && g_mem_tracer && g_mem_block_analyzer)) return;}
#define CHECK_RET_VALUE(X) {if(!(g_forest && g_mem_tracer && g_mem_block_analyzer)) return (X);}


void AssociateArithmeticMemories(
	OpNode*            node,
	unsigned long long des_addr,
	int                des_layer,
	int                layer_of_associates,
	int                depth_remainded);

bool InitTrace() {
	g_filter = MakeNumberFilter();
	if (g_filter == nullptr)
		return false;
	return true;
}

void TraceLoadMem(unsigned long long ins_addr, unsigned long reg, unsigned long long addr) {
	//CHECK_FOREST_RET();
	unsigned long long value = 0;
	IoReadProcessMemory(addr, &value, sizeof(value));
	value &= IoGetRegisterMask(reg);
	g_forest->AddNode(ins_addr, ZYDIS_MNEMONIC_MOV, ZYDIS_OPERAND_TYPE_REGISTER, IoGet64bitRegister(reg), 0,
		ZYDIS_OPERAND_TYPE_MEMORY, addr, value);
}

void TraceSaveMem(unsigned long long ins_addr, unsigned long long addr, unsigned long reg) {
	//CHECK_FOREST_RET();
	unsigned long long value = IoReadRegister(reg);
	g_forest->AddNode(ins_addr, ZYDIS_MNEMONIC_MOV, ZYDIS_OPERAND_TYPE_MEMORY, addr, 0,
		ZYDIS_OPERAND_TYPE_REGISTER, IoGet64bitRegister(reg), value);
}


void TraceMovRR(unsigned long long ins_addr, unsigned long des_reg, unsigned long src_reg) {
	//CHECK_FOREST_RET();
	unsigned long long src_value = IoReadRegister(src_reg);
	g_forest->AddNode(ins_addr, ZYDIS_MNEMONIC_MOV, ZYDIS_OPERAND_TYPE_REGISTER, IoGet64bitRegister(des_reg), src_value,
		ZYDIS_OPERAND_TYPE_REGISTER, IoGet64bitRegister(src_reg), src_value);
}

void TraceUnitaryArithmetic(unsigned long long ins_addr, int op, unsigned long long reg) {
	//CHECK_FOREST_RET();
	unsigned long long value = IoReadRegister((unsigned long)reg);
	g_forest->AddNode(ins_addr, op, reg, value);
}

void TraceBinaryArithmeticRR(unsigned long long ins_addr, int op, unsigned long long des_reg, unsigned long long src_reg) {
	//CHECK_FOREST_RET();
	unsigned long long des_value = IoReadRegister((unsigned long)des_reg);
	unsigned long long src_value = IoReadRegister((unsigned long)src_reg);
	g_forest->AddNode(ins_addr, op, ZYDIS_OPERAND_TYPE_REGISTER, IoGet64bitRegister((unsigned long)des_reg), des_value,
		ZYDIS_OPERAND_TYPE_REGISTER, IoGet64bitRegister((unsigned long)src_reg), src_value);
}

void TraceBinaryArithmeticRI(unsigned long long ins_addr, int op, unsigned long long reg, unsigned long long value) {
	//CHECK_FOREST_RET();
	unsigned long long reg_value = IoReadRegister((unsigned long)reg);
	g_forest->AddNode(ins_addr, op, ZYDIS_OPERAND_TYPE_REGISTER, IoGet64bitRegister((unsigned long)reg), reg_value,
		ZYDIS_OPERAND_TYPE_IMMEDIATE, 0, value);
}

void TraceMulFactor(unsigned long long ins_addr, unsigned long long reg, double factor) {
	UNREFERENCED_PARAMETER(ins_addr);
	g_forest->SetNodeFactor(IoGet64bitRegister((unsigned long)reg), factor);
}

bool StartVMInsGroup() {
	if (g_forest == nullptr) {
		g_forest = MakeArithmeticForest();
		if (g_forest == nullptr) {
			return false;
		}
	}
	if (g_mem_tracer == nullptr) {
		g_mem_tracer = MakeMemoryTracer();
		if (g_mem_tracer == nullptr) {
			return false;
		}
	}
	if (g_mem_block_analyzer == nullptr) {
		g_mem_block_analyzer = MakeMemoryBlockAnalyzer();
		if (g_mem_block_analyzer == nullptr) {
			return false;
		}
	}
	//g_forest.Clear();
	return true;
}

void FinishVMInsGroup() {
	CHECK_RET();
	g_filter->SetDefault(false);
	g_filter->AddRuleEqualULL(true, ZYDIS_REGISTER_RDX); // 2nd parameter of printf
	g_forest->ReduceByType(true, ZYDIS_OPERAND_TYPE_REGISTER);
	g_forest->ReduceByNumberFilter(ZYDIS_OPERAND_TYPE_REGISTER, g_filter);
	g_forest->Reduce();
	//g_forest->Print(forest);
	//forest->clear();
	g_forest->Print();
	g_forest->Clear();
	getchar();
}

// test and debug
void FinishVMInsGroupUnprotected(unsigned char* address, void* user_data) {
	CHECK_RET();
	g_filter->SetDefault(false);
	// call    qword ptr [protected!_imp_memcpy]
	unsigned long long rdx = IoReadRegister((unsigned long)ZYDIS_REGISTER_RDX);
	unsigned char cipher[16] = { 0 };
	IoReadProcessMemory(rdx, cipher, sizeof(cipher));
	for (int i = 0; i < 16; i++) {
		printf("%02x", cipher[i]);
	}
	putchar('\n');
	g_filter->AddRuleBetweenULL(true, rdx, true, rdx + 0x10, false);
	g_forest->ReduceByType(true, ZYDIS_OPERAND_TYPE_MEMORY);
	g_forest->ReduceByNumberFilter(ZYDIS_OPERAND_TYPE_MEMORY, g_filter);
	g_forest->ReduceByDepth(5);
	auto forest = g_forest->GetForest();
	for (auto i = forest.begin(); i != forest.end(); i++) {
		int layer = 1;
		g_mem_tracer->Add((*i)->addr, layer, (*i)->ins_addr);
		if ((*i)->left)
			AssociateArithmeticMemories((*i)->left, (*i)->addr, layer, layer + 1, 5);
		if ((*i)->right)
			AssociateArithmeticMemories((*i)->right, (*i)->addr, layer, layer + 1, 5);
	}
	//g_forest->Reduce();
	//g_forest->Print(forest);
	//forest->clear();
	//g_forest->Print();
	//g_mem_tracer->Print(1, true);
	g_mem_block_analyzer->AnalyzeData(g_mem_tracer, 0, NULL);
	g_mem_block_analyzer->Print();
	unsigned char partial_round_key[16] = { 0 };
	for (auto i = forest.begin(); i != forest.end(); i++) {
		partial_round_key[i - forest.begin()] = (unsigned char)(*i)->left->right->value;
	}
	ha_ctx* ctx = ha_build_aes_ctx(128);
	ha_set_roundkey(ctx, partial_round_key, 160, 16);
	unsigned char* key = ha_calulate_key(ctx);
	for (int i = 0; i < 16; i++) {
		printf("0x%02x, ", key[i]);
	}
	putchar('\n');
	printf("%s\n", key);
	g_forest->Clear();
	getchar();
}

// test for real case: VMP on inline cipher
void FinishVMInsGroupVmpInline(unsigned char* address, void* user_data) {
	CHECK_RET();
	g_filter->SetDefault(false);
	// copy block result, copy(final_result + offset, current_block_result, 16)
	unsigned long long rdx = IoReadRegister((unsigned long)ZYDIS_REGISTER_RDX);
	unsigned char cipher[16] = { 0 };
	IoReadProcessMemory(rdx, cipher, sizeof(cipher));
	for (int i = 0; i < 16; i++) {
		printf("%02x", cipher[i]);
	}
	putchar('\n');
	g_filter->AddRuleBetweenULL(true, rdx, true, rdx + 0x10, false);
	g_forest->ReduceByType(true, ZYDIS_OPERAND_TYPE_MEMORY);
	g_forest->ReduceByNumberFilter(ZYDIS_OPERAND_TYPE_MEMORY, g_filter);
	g_forest->ReduceByDepth(5);
	auto forest = g_forest->GetForest();
	for (auto i = forest.begin(); i != forest.end(); i++) {
		int layer = 1;
		g_mem_tracer->Add((*i)->addr, layer, (*i)->ins_addr);
		if ((*i)->left)
			AssociateArithmeticMemories((*i)->left, (*i)->addr, layer, layer + 1, 5);
		if ((*i)->right)
			AssociateArithmeticMemories((*i)->right, (*i)->addr, layer, layer + 1, 5);
	}
	//g_forest->Reduce();
	//g_forest->Print(forest);
	//forest->clear();
	//g_forest->Print();
	//g_mem_tracer->Print(1, true);
	g_mem_block_analyzer->AnalyzeData(g_mem_tracer, 0, NULL);
	g_mem_block_analyzer->Print();
	unsigned char partial_round_key[16] = { 0 };
	for (auto i = forest.begin(); i != forest.end(); i++) {
		partial_round_key[i - forest.begin()] = (unsigned char)(*i)->left->right->value;
	}
	ha_ctx* ctx = ha_build_aes_ctx(128);
	ha_set_roundkey(ctx, partial_round_key, 160, 16);
	unsigned char* key = ha_calulate_key(ctx);
	for (int i = 0; i < 16; i++) {
		printf("0x%02x, ", key[i]);
	}
	putchar('\n');
	printf("%s\n", key);
	g_forest->Clear();
	getchar();
}

bool StartVMIns() {
	CHECK_RET_VALUE(false);
	return true;
}

void FinishVMIns() {
	CHECK_RET();
	g_forest->ReduceByType(true, ZYDIS_OPERAND_TYPE_MEMORY);
	auto forest = g_forest->GetForest();
	if (forest.size() > 0x60) {
		g_mem_tracer->Clear();
		for (auto i = forest.begin(); i != forest.end(); i++)
			g_mem_tracer->Add((*i)->addr, 1, (*i)->ins_addr);
		g_mem_block_analyzer->Clear();
		// distance threshold = 1
		// item count threshold = 8
		int   argc = 2;
		void* argv[] = {(void*)1, (void*)8};
		g_mem_block_analyzer->AnalyzeData(g_mem_tracer, argc, argv);
		g_mem_block_analyzer->Print();
		auto blocks = g_mem_block_analyzer->GetMemoryBlocks(1);
		if (blocks.size() > 0) {
			for (auto i = blocks.begin(); i != blocks.end(); i++) {
				g_filter->AddRuleBetweenULL(true, i->start_addr, true, i->end_addr, true);
			}
			g_forest->ReduceByNumberFilter(ZYDIS_OPERAND_TYPE_MEMORY, g_filter);
			forest = g_forest->GetForest();
			g_mem_tracer->Clear();
			for (auto i = forest.begin(); i != forest.end(); i++) {
				int layer = 1;
				g_mem_tracer->Add((*i)->addr, layer, (*i)->ins_addr);
				if ((*i)->left)
					AssociateArithmeticMemories((*i)->left, (*i)->addr, layer, layer + 1, 256);
				if ((*i)->right)
					AssociateArithmeticMemories((*i)->right, (*i)->addr, layer, layer + 1, 256);
			}
			g_mem_block_analyzer->Clear();
			g_mem_block_analyzer->AnalyzeData(g_mem_tracer, 0, NULL);
			g_mem_block_analyzer->Print();
			auto read_blocks = g_mem_block_analyzer->GetMemoryBlocks(2);
			for (auto i = read_blocks.begin(); i != read_blocks.end(); i++) {
				unsigned char print_mem[256] = { 0 };
				int           print_mem_length = (i->end_addr - i->start_addr) < sizeof(print_mem) ?
					(i->end_addr - i->start_addr) : sizeof(print_mem);
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

void AssociateArithmeticMemories(
	OpNode*            node,
	unsigned long long des_addr,
	int                des_layer,
	int                layer_of_associates,
	int                depth_remainded) {
	if (depth_remainded <= 0)
		return;
	if (node->type == ZYDIS_OPERAND_TYPE_MEMORY) {
		g_mem_tracer->Associate(des_addr, des_layer, node->addr, layer_of_associates, node->ins_addr);
	}
	if (node->operand_count == 2) {
		if (node->left)
			AssociateArithmeticMemories(node->left, des_addr, des_layer, layer_of_associates, depth_remainded - 1);
		if (node->right)
			AssociateArithmeticMemories(node->right, des_addr, des_layer, layer_of_associates, depth_remainded - 1);
	}
	else if (node->operand_count == 1) {
		if (node->left)
			AssociateArithmeticMemories(node->left, des_addr, des_layer, layer_of_associates, depth_remainded - 1);
	}
}
