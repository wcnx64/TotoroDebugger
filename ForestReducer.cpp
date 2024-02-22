#include "ForestReducer.h"
#define ZYDIS_STATIC_BUILD
extern "C" {
#include "zydis/Zydis.h"
}


// reduce junk code trees from the arithmetic forest
bool ReduceJunkCodesVmIns(
	IArithmeticForest* forest,
	unsigned long long stack_base,
	unsigned long long current_stack_pos) {
	static INumberFilter* filter;
	if (filter == nullptr) {
		filter = CreateNumberFilter();
		if (filter == nullptr)
			return false;
	}
	// all operations are done on stack memory
	forest->ReduceByType(true, ZYDIS_OPERAND_TYPE_MEMORY);
	//forest->Print();
	// common junk codes
	// 1: push reg => tree A : reg -> [rsp]
	//    mov [rsp], something => tree A is overwritten. tree B : something -> [rsp]
	//    pop reg => tree C : something -> [rsp] -> reg, maybe overwritten afterwards
	//    when another such sequence appears => Tree D something -> [rsp] -> reg -> [rsp]
	filter->Reset();
	filter->AddRuleEqualULL(false, current_stack_pos);
	forest->ReduceByNumberFilter(ZYDIS_OPERAND_TYPE_MEMORY, filter);
	// math equivalent reduction
	forest->Reduce();
	return true;
}
