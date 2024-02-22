#ifndef _FOREST_REDUCER_H_
#define _FOREST_REDUCER_H_

#include "ArithmeticTree.h"

// reduce junk code trees from the arithmetic forest
bool ReduceJunkCodesVmIns(
	IArithmeticForest* forest,
	unsigned long long stack_base,
	unsigned long long current_stack_pos);

#endif // _FOREST_REDUCER_H_