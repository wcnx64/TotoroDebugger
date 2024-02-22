#include "ArithmeticTree.h"
#include "TreeReducer.h"
#include "alu.h"
#define ZYDIS_STATIC_BUILD
extern "C" {
#include "zydis/Zydis.h"
}

bool ReduceMov(OpNode* node, bool is_root) {
	bool modified = false;
	// recursion
	if (node->left)
		modified |= ReduceMov(node->left, false);
	if (node->right)
		modified |= ReduceMov(node->right, false);
	if (node->op == ZYDIS_MNEMONIC_MOV && node->left && node->right == nullptr) {
		// node->left will be removed, subtrees of node->left will be connected to node
		if (node->type == ZYDIS_OPERAND_TYPE_REGISTER) {
			node->ReplaceNodeWithLelfChild();
			modified = true;
		}
		else if (node->type == ZYDIS_OPERAND_TYPE_MEMORY && node->left->type == ZYDIS_OPERAND_TYPE_REGISTER) {
			node->ReplaceNodeWithLelfChild(true);
			modified = true;
		}
		else if (node->type == ZYDIS_OPERAND_TYPE_MEMORY && node->left->type == ZYDIS_OPERAND_TYPE_MEMORY) {
			if (node->left->left) { // non-leaf, mov A, B -> replace B with A
				node->ReplaceNodeWithLelfChild(true);
				modified = true;
			}
			else if (!is_root && node->left->left == nullptr) { // non-root and leaf, mov A, B -> replace A with B
				node->ReplaceNodeWithLelfChild();
				modified = true;
			}
			// do nothing with root and leaf
		}
		else if (node->left->type == ZYDIS_OPERAND_TYPE_IMMEDIATE) { // immediate value. don't reduce
		}
		else { // invalid case, discard the subtree
			node->type = ZYDIS_OPERAND_TYPE_UNUSED;
			node->left = nullptr;
			modified = true;
		}
		// remove node->left without affecting its subtrees
	}
	return modified;
}

bool ReduceMov(OpNode* node) {
	return ReduceMov(node, true);
}

// move not and neg to flag and factor
bool ReduceUnitaryArithmeticNodes(OpNode* node, bool is_root) {
	bool modified = false;
	// recursion
	if (node->left)
		modified |= ReduceUnitaryArithmeticNodes(node->left, false);
	if (node->right)
		modified |= ReduceUnitaryArithmeticNodes(node->right, false);
	if (node->left && node->right == nullptr) {
		if (node->op == ZYDIS_MNEMONIC_NOT || node->op == ZYDIS_MNEMONIC_NEG) {
			if (!is_root || node->left->left) { // do nothing when only a root and a leaf remaind
				// the node between node and node->left->left will be removed
				OpNode* to_free = node->left;
				// replace node with node->left
				int not_flag = (node->op == ZYDIS_MNEMONIC_NOT) ? 1 ^ node->left->not_flag : node->left->not_flag;
				double factor = (node->op == ZYDIS_MNEMONIC_NEG) ? -node->left->factor : node->left->factor;
				unsigned long long value = node->value;
				*node = *node->left;
				node->not_flag = not_flag;
				node->factor = factor;
				if (node->left->left)
					node->value = value;
				// remove the node between node and node->left->left
				to_free->left = nullptr;
				to_free->right = nullptr;
				delete to_free;
				modified = true;
			}
		}
	}
	return modified;
}

// simplify nodes connected by unitary operations
bool ReduceUnitaryArithmeticNodes(OpNode* node) {
	return ReduceUnitaryArithmeticNodes(node, true);
}

// op reg; mov op mem -> pseudo op reg, mem
// this operation doesn't affect tree height
void ReduceUnitaryArithmeticNodesR2M(OpNode* node) {
	// recursion
	if (node->left)
		ReduceUnitaryArithmeticNodesR2M(node->left);
	if (node->right)
		ReduceUnitaryArithmeticNodesR2M(node->right);
	if (node->left) {
		if (node->type == ZYDIS_OPERAND_TYPE_REGISTER &&
			node->left->type == ZYDIS_OPERAND_TYPE_MEMORY) {
			if (node->op == ZYDIS_MNEMONIC_NOT ||
				node->op == ZYDIS_MNEMONIC_NEG) {
				node->type = node->left->type;
				node->addr = node->left->addr;
			}
		}
	}
}

// transfrom fake binary nodes to simplified form
bool ReduceFakeBinaryNodes(OpNode* node) {
	bool modified = false;
	// recursion
	if (node->left)
		modified |= ReduceFakeBinaryNodes(node->left);
	if (node->right)
		modified |= ReduceFakeBinaryNodes(node->right);
	// only deal with leaves
	if (node->left && node->left->left == nullptr && node->left->right == nullptr &&
		node->right && node->right->left == nullptr && node->right->right == nullptr) {
		// simplify only when node->left and node->right both exist and are of the same value
		bool same_operands = false;
		if (node->left && node->right) {
			if (node->left->type == node->right->type && node->left->addr == node->right->addr) {
				same_operands = true;
			}
		}
		if (same_operands) {
			if (node->op == ZYDIS_MNEMONIC_AND ||
				node->op == ZYDIS_MNEMONIC_OR) {
				// node->right
				delete node->right;
				node->right = nullptr;
				// replace node with node->left
				node->ReplaceNodeWithLelfChild();
				modified = true;
			}
		}
	}
	return modified;
}

// OR to AND
    // this operation doesn't affect tree height
void ReduceOr2And(OpNode* node) {
	// recursion
	if (node->left)
		ReduceOr2And(node->left);
	if (node->right)
		ReduceOr2And(node->right);
	// A or B == not (not A and not B)
	// the reduced expression is unique for equilvalent formulas
	if (node->op == ZYDIS_MNEMONIC_OR && node->left && node->right) {
		node->op = ZYDIS_MNEMONIC_AND;
		node->not_flag ^= 1;
		node->left->not_flag ^= 1;
		node->right->not_flag ^= 1;
		node->value = ((node->left->not_flag) ? ~node->left->value : node->left->value) &
					  ((node->right->not_flag) ? ~node->right->value : node->right->value);
	}
}

// make the tree binary
bool ReduceMakeBinaryTree(OpNode* node) {
	bool modified = false;
	// recursion
	if (node->left)
		modified |= ReduceMakeBinaryTree(node->left);
	if (node->right)
		modified |= ReduceMakeBinaryTree(node->right);
	if (node->left && node->right == nullptr) {
		if (node->op == ZYDIS_MNEMONIC_NOT) {
			;
		}
		else if (node->op == ZYDIS_MNEMONIC_NOT) {
			;
		}
		else {
			node->left->type = ZYDIS_OPERAND_TYPE_IMMEDIATE;
			if (node->left)
				delete node->left->left;
			if (node->right)
				delete node->left->left;
		}
	}
	return modified;
}

void ReduceXor(OpNode* node) {
	OpNode* to_free_left = node->left;
	OpNode* to_free_right = node->right;
	node->right = node->left->right;
	node->left = node->left->left;
	node->op = ZYDIS_MNEMONIC_XOR;
	node->not_flag = 0;
	node->value = ~node->value;
	to_free_left->left = nullptr;
	to_free_left->right = nullptr;
	delete to_free_left;
	delete to_free_right;
}

bool ReduceMatchXor(OpNode* node) {
	bool modified = false;
	// recursion
	if (node->left)
		modified |= ReduceMatchXor(node->left);
	if (node->right)
		modified |= ReduceMatchXor(node->right);
	// A xor B == not (not (not A and B) and not (A and not A))
	if (node->left && node->right && node->op == ZYDIS_MNEMONIC_AND &&
		node->not_flag && node->factor == 1 &&
		node->left->left && node->left->right && node->left->op == ZYDIS_MNEMONIC_AND &&
		node->left->not_flag && node->left->factor == 1 &&
		node->right->left && node->right->right && node->right->op == ZYDIS_MNEMONIC_AND &&
		node->right->not_flag && node->right->factor == 1) {
		OpNode* A1 = nullptr;
		OpNode* A2 = nullptr;
		OpNode* B1 = nullptr;
		OpNode* B2 = nullptr;
		if (node->left->left->IsEqual(node->right->left, false) &&
			node->left->right->IsEqual(node->right->right, false)) {
			A1 = node->left->left;
			B1 = node->left->right;
			A2 = node->right->left;
			B2 = node->right->right;
		}
		else if (node->left->left->IsEqual(node->right->right, false) &&
			node->left->right->IsEqual(node->right->left, false)) {
			A1 = node->left->left;
			B1 = node->left->right;
			A2 = node->right->right;
			B2 = node->right->left;
		}
		if (A1 && B1 && A2 && B2 &&
			(A1->not_flag ^ B1->not_flag) &&
			(A2->not_flag ^ B2->not_flag) &&
			(A1->not_flag ^ A2->not_flag)) {
			ReduceXor(node);
			modified = true;
		}
	}
	return modified;
}
