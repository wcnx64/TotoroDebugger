#ifndef _ARITHMETIC_TREE_H_
#define _ARITHMETIC_TREE_H_

#include <vector>
#include "filter.h"

// The OpNode structure is the minimal basis to implementing the basic version of Arithmetic Tree algorithm.
// The Arithmetic Tree is designed to differ in Reduction techniques, which use Reduce interfaces.
// Extend the algorithm by inheriting the OpNode structure.
typedef struct OpNode {
    unsigned long long serial; // an auto increment variable, which indicates the time that the operation is done
    int                height; // tree height
    int                type; // ZYDIS_OPERAND_TYPE_MEMORY / ZYDIS_OPERAND_TYPE_REGISTER / ZYDIS_OPERAND_TYPE_IMMEDIATE
    unsigned long long ins_addr; // address of the corresponding instruction
    unsigned long long addr; // regard some registers as special addresses, the values of reg addresses are defined as in ZyDis
                             // -1 for immediate value
    unsigned long long value; // the value of the address when the operation is done
    // value = not_flag ? not factor * op(left, right) : factor * op(left, right);
    int                not_flag;
    double             factor;
    int                op; // operator (operator is a reserved name in C++)
    int                operand_count; // 0 for leaves.
    OpNode*            left; // left child
    OpNode*            right; // right child
    OpNode(int type, unsigned long long addr, unsigned long long value = 0);
    OpNode(unsigned long long serial, int type, unsigned long long addr, unsigned long long value = 0);
    ~OpNode();
    OpNode* DeepCopy();
    void Clear();
    void AddOp(int op, OpNode* left); // add new root and attach 'left' to it
    void Add2Op(int op, OpNode* left, OpNode* right); // add new root and attach 'left' and 'right' to it
    bool IsEqual(OpNode* node, bool compare_not_flag); // true if the tree node is equal to the parameter 'node' in (addr, type, value)
    void ReplaceNodeWithLelfChild(bool retain_addr = false); // replace the current the node by its left child to shorten the tree
    int  UpdateHeight(); // return the new height
    void ReduceByDepth(int depth); // reduce by depth, root is of depth 0
    void Print(int leading_spaces = 0); // print the tree recursively
    static bool IsEqual(OpNode* node1, OpNode* node2, bool compare_not_flag); // true if node1 and node2 are the same in (addr, type, value)
    static void ReplaceNodeWithLelfChild(OpNode* node, bool retain_addr = false); // replace the node by its left child to shorten the tree
    static const char* GetTypeName(int type); // to readable
    static const char* GetOpName(int op); // to readable
} OpNode, *POpNode;

class IArithmeticForest {
public:
    virtual ~IArithmeticForest() {}; // deconstructor
    virtual void Clear() = 0; // clear the forest
    virtual std::vector<OpNode*>& GetForest() = 0; // get the forest
    // get the trees whose root values are the parameter result
    virtual bool GetForestByResult(std::vector<OpNode*>& result_forest, unsigned long long result) = 0;
    // add a one register operation. {push, pop} are not one register operations, for they involves memory I/O.
    virtual bool AddNode(
        unsigned long long ins_addr,
        int                op,
        unsigned long long reg_addr,
        unsigned long long reg_value) = 0;
    // add a two register operation including {push, pop}
    virtual bool AddNode(
        unsigned long long ins_addr,
        int                op,
        int                des_type,
        unsigned long long des_addr,
        unsigned long long des_value,
        int src_type, unsigned long long src_addr, unsigned long long src_value) = 0;
    // set node factor
    virtual bool SetNodeFactor(unsigned long long reg, double factor) = 0;
    // delete a tree by node, return true if the tree to delete is found
    virtual bool DeleteTree(OpNode* node) = 0;
    // do reduction to the forest
    virtual void Reduce() = 0;
    // do reduction to a tree or tree node
    virtual void Reduce(OpNode* node) = 0;
    // do reduction by type
    virtual void ReduceByType(bool retain, int type) = 0;
    // do reduction with according to a number filter
    virtual void ReduceByNumberFilter(int type, INumberFilter* filter) = 0;
    // reduce by depth, root is of depth 0
    virtual void ReduceByDepth(int depth) = 0;
    // print the forest
    virtual void Print() = 0;
};

// build an arithmetic forest
IArithmeticForest* MakeArithmeticForest();
// destroy the forest
void DestroyArithmeticForest(IArithmeticForest* forest);

#endif // _ARITHMETIC_TREE_H_