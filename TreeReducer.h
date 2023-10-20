#ifndef _TREE_REDUCER_H_
#define _TREE_REDUCER_H_

// simplify nodes connected by mov operations
bool ReduceMov(OpNode* node);
// simplify nodes connected by unitary operations
bool ReduceUnitaryArithmeticNodes(OpNode* node);
// op reg; mov op mem -> pseudo op reg, mem
void ReduceUnitaryArithmeticNodesR2M(OpNode* node);
// transfrom fake binary nodes to simplified form
bool ReduceFakeBinaryNodes(OpNode* node);
// OR to AND
void ReduceOr2And(OpNode* node);
// match XOR operations
bool ReduceMatchXor(OpNode* node);

#endif // _TREE_REDUCER_H_
