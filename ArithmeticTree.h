#ifndef _ARITHMETIC_TREE_H_
#define _ARITHMETIC_TREE_H_

#include <vector>
#include <stdint.h>

#include "filter.h"

/// <summary>
/// extension of zydis operand and operator types
/// </summary>
const uint64_t OPNODE_OPERAND_TYPE_VIRTUAL = 0x80000000;

class OpNode;

/// <summary>
/// Callback for searching a node.
/// Passing user data in callbacks is not supported
/// to make the OpNode simple and fast to process.
/// </summary>
/// <param name="node">a node found in the search</param>
/// <param name="hit">equal to the addr being searched or not</param>
/// <returns>whether or not the target nodes are found</returns>
typedef bool (*OpNodeSearchCallback)(OpNode* node, bool hit);

/// <summary>
/// The OpNode structure is the minimal basis to implement
/// the basic version of Arithmetic Tree algorithm.
/// The Arithmetic Tree is designed to differ in Reduction techniques,
/// which use unified Reduce interfaces.
/// The tree is a binary tree, the member "refer" is not regarded
/// as a child tree, but part of the node content.
/// Extend the algorithm by inheriting the OpNode structure.
/// </summary>
typedef class OpNode {
public:
    /// <summary>
    /// constructor by (type, addr), value and ins_addr.
    /// serial is auto generated.
    /// </summary>
    OpNode(int type, uint64_t addr,
        uint64_t value, uint64_t ins_addr);
    /// <summary>
    /// constructor by serial, (type, addr), value and ins_addr.
    /// serial is set by input.
    /// </summary>
    OpNode(uint64_t serial, int type, uint64_t addr,
        uint64_t value, uint64_t ins_addr);
    /// <summary>
    /// destructor
    /// no inheritance is designed to exist, so it is not virtual
    /// </summary>
    ~OpNode();
    /// <summary>
    /// reset
    /// </summary>
    void Reset();
    /// <summary>
    /// deep copy a tree
    /// </summary>
    /// <returns>root of copied tree</returns>
    OpNode* DeepCopy();
    /// <summary>
    /// add new root and attach 'left' to it
    /// </summary>
    /// <param name="op">opcode</param>
    /// <param name="left">left child</param>
    void AddOp(int op, OpNode* left);
    /// <summary>
    /// add new root and attach 'left' and 'right' to it
    /// </summary>
    /// <param name="op">opcode</param>
    /// <param name="left">left child</param>
    /// <param name="right">right child</param>
    void AddOp(int op, OpNode* left, OpNode* right);
    /// <summary>
    /// check if the node is equal to "this" in (type, addr)
    /// </summary>
    /// <param name="node">the node to compare</param>
    /// <param name="compare_not_flag">compare "not“ flag or not</param>
    /// <returns>
    /// true if the tree node is equal to
    /// the parameter 'node' in (type, addr)
    /// </returns>
    bool IsEqual(OpNode* node, bool compare_not_flag);
    /// <summary>
    /// merge a tree into this tree
    /// </summary>
    /// <param name="node"></param>
    /// <returns>succeeded or not</returns>
    bool Merge(OpNode* node);
    /// <summary>
    /// search for a (type, addr) in the tree, and call callback along the tree route
    /// </summary>
    /// <param name="type">OpNode type to match</param>
    /// <param name="addr">OpNode addr to match</param>
    /// <param name="callback">callback called when matched</param>
    /// <returns></returns>
    bool SearchAddrUp(int type, uint64_t addr, OpNodeSearchCallback callback);
    /// <summary>
    /// search for a (type, addr) in the tree, and call callback along the tree route
    /// </summary>
    /// <param name="type">OpNode type to match</param>
    /// <param name="addr">OpNode addr to match</param>
    /// <param name="callback">callback called when matched</param>
    /// <returns></returns>
    bool SearchAddrDown(int type, uint64_t addr, OpNodeSearchCallback callback);
    /// <summary>
    /// Replace the this node by its left child to shorten the tree.
    /// This function won't be performed on roots.
    /// </summary>
    /// <param name="retain_addr">if true, the addr of this node is not replaced</param>
    void ReplaceNodeWithLelfChild(bool retain_addr = false);
    /// <summary>
    /// get the root or child node with given instruction address
    /// </summary>
    /// <param name="ins_addr">instruction address</param>
    /// <returns></returns>
    OpNode* GetNodeByInsAddr(uint64_t ins_addr);
    /// <summary>
    /// re-calculate the tree height and return the new height
    /// </summary>
    /// <returns>updated tree height</returns>
    int UpdateHeight();
    /// <summary>
    /// reduce by depth, root is of depth 0
    /// </summary>
    /// <param name="depth">max depth for reduction</param>
    void ReduceByDepth(int depth);
    /// <summary>
    /// print the tree recursively
    /// </summary>
    /// <param name="leading_spaces">the number of leading spaces</param>
    /// <param name="stack_addr">address of the stack</param>
    void Print(int leading_spaces = 0, uint64_t stack_addr = 0);
    /// <summary>
    /// print the tree's member "refer" recursively
    /// </summary>
    /// <param name="leading_spaces">the number of leading spaces</param>
    /// <param name="stack_addr">address of the stack</param>
    void PrintRefer(int leading_spaces = 0, uint64_t stack_addr = 0);

    ///
    /// static functions
    ///

    /// <summary>
    /// compare two nodes
    /// </summary>
    /// <param name="node1">the first of the two nodes for comparation</param>
    /// <param name="node2">the second of the two nodes for comparation</param>
    /// <param name="compare_not_flag">whether compare the "not flag" or not</param>
    /// <returns>true if node1 and node2 are the same in (type, addr)</returns>
    static bool IsEqual(OpNode* node1, OpNode* node2, bool compare_not_flag);
    /// <summary>
    /// Replace the node by its left child to shorten the tree.
    /// This function won't be performed on roots.
    /// </summary>
    /// <param name="node">the node that will be replaced by node->left</param>
    /// <param name="retain_addr">if true, the addr of node is not replaced</param>
    static void ReplaceNodeWithLelfChild(OpNode* node, bool retain_addr = false);
    /// <summary>
    /// type to readable
    /// </summary>
    /// <param name="type">OpNode type</param>
    /// <returns></returns>
    static const char* GetTypeName(int type);
    /// <summary>
    /// operator to readable
    /// </summary>
    /// <param name="op">OpNode operator (op)</param>
    /// <returns></returns>
    static const char* GetOpName(int op);
protected:
    /// <summary>
    /// search for a (type, addr) in the tree, and call callback along the tree route
    /// </summary>
    /// <param name="type">OpNode type to match</param>
    /// <param name="addr">OpNode addr to match</param>
    /// <param name="hit">if already hit</param>
    /// <param name="callback">callback called when matched</param>
    /// <returns>if some nodes are matched</returns>
    bool SearchAddrUpInternal(int type, uint64_t addr,
        bool hit, OpNodeSearchCallback callback);
    /// <summary>
    /// search for a (type, addr) in the tree, and call callback along the tree route
    /// </summary>
    /// <param name="type">OpNode type to match</param>
    /// <param name="addr">OpNode addr to match</param>
    /// <param name="hit">if already hit</param>
    /// <param name="callback">callback called when matched</param>
    /// <returns>if some nodes are matched</returns>
    bool SearchAddrDownInternal(int type, uint64_t addr,
        bool hit, OpNodeSearchCallback callback);
public:
    // basic info (serial, type, addr, value)
    uint64_t serial;   // an auto increment variable, which indicates the time that the operation is done
    int      type;     // ZYDIS_OPERAND_TYPE_MEMORY / ZYDIS_OPERAND_TYPE_REGISTER / ZYDIS_OPERAND_TYPE_IMMEDIATE
    uint64_t addr;     // regard some registers as special addresses, the values of reg addresses are defined as in ZyDis
                       // -1 for immediate value
    uint64_t value;    // the value of the address when the operation is done
                       // value = not_flag ? not factor * op(left, right) : factor * op(left, right);
    // additional info
    int      height;   // tree height
    uint64_t ins_addr; // address of the corresponding instruction
    bool     not_flag; // the calculation result should be flipped when true
    double   factor;   // the calculation result should be multiplied by "factor"
    OpNode*  refer;    // It is not a child tree. It is part of the value, indicating how it the memory is located.
    // relation with other nodes
    int      op;       // operator
    OpNode*  left;     // left child
    OpNode*  right;    // right child
} OpNode, * POpNode;

class IArithmeticForest {
public:
    /// <summary>
    /// destructor
    /// </summary>
    virtual ~IArithmeticForest() {};
    /// <summary>
    /// clear the forest
    /// </summary>
    virtual void Reset() = 0;
    /// <summary>
    /// get the trees as a vector
    /// </summary>
    /// <returns>the vector containing the trees</returns>
    virtual std::vector<OpNode*>* GetTrees() = 0;
    /// <summary>
    /// get the trees whose root values are the parameter result
    /// </summary>
    /// <param name="result_forest">the vector containing the matched trees</param>
    /// <param name="result">the calculation result of the tree to match</param>
    virtual void GetTreesByResult(std::vector<OpNode*>& result_forest, uint64_t result) = 0;
    /// <summary>
    /// add a one register operation. {push, pop} are not one register operations, for they involves memory I/O.
    /// </summary>
    /// <param name="ins_addr">instruction address</param>
    /// <param name="op">operator</param>
    /// <param name="reg_addr">the virtual address representing the register</param>
    /// <param name="reg_value">the value of the register</param>
    /// <returns>succeeded or not</returns>
    virtual bool AddNode(
        uint64_t ins_addr,
        int      op,
        uint64_t reg_addr,
        uint64_t reg_value) = 0;
    /// <summary>
    /// add a two register operation including {push, pop}
    /// </summary>
    /// <param name="ins_addr">instruction address</param>
    /// <param name="op">operator</param>
    /// <param name="des_type">the type of the destination</param>
    /// <param name="des_addr">the address / virtual address of the destination</param>
    /// <param name="des_value">the value of the destination</param>
    /// <param name="src_type">the type of the source</param>
    /// <param name="src_addr">the address / virtual address of the source</param>
    /// <param name="src_value">the value of the source</param>
    /// <returns>succeeded or not</returns>
    virtual bool AddNode(
        uint64_t ins_addr,
        int      op,
        int      des_type,
        uint64_t des_addr,
        uint64_t des_value,
        int      src_type,
        uint64_t src_addr,
        uint64_t src_value) = 0;
    /// <summary>
    /// set node factor
    /// </summary>
    /// <param name="reg">the register to operate on</param>
    /// <param name="factor">factor multiplied to the register</param>
    /// <returns></returns>
    virtual bool SetNodeFactor(uint64_t reg, double factor) = 0;
    /// <summary>
    /// set a memory reference subtree as the target node's member "refer"
    /// </summary>
    /// <param name="addr">the destination memory</param>
    /// <param name="base">the base register for memory reference</param>
    /// <param name="base_value">value of the base register</param>
    /// <param name="has_index">whether or not the index register is represent</param>
    /// <param name="index">the index register for memory reference</param>
    /// <param name="base_value">value of the index register</param>
    /// <param name="scale">the scale of the index register</param>
    /// <param name="has_displacement">whether or not the displacement is present</param>
    /// <param name="displacement_value">the value of the displacement</param>
    /// <returns>succeeded or not</returns>
    virtual bool SetNodeMemRefSubTree(uint64_t addr,
        uint32_t base, uint64_t base_value,
        bool has_index, uint32_t index, uint64_t index_value, uint32_t scale,
        bool has_displacement, uint64_t displacement_value) = 0;
    /// <summary>
    /// delete a tree by its root node
    /// </summary>
    /// <param name="node">the node to delete</param>
    /// <returns>true if the tree is found and deleted</returns>
    virtual bool DeleteTree(OpNode* node) = 0;
    /// <summary>
    /// do reduction to the forest
    /// </summary>
    virtual void Reduce() = 0;
    /// <summary>
    /// do reduction to a tree or tree node
    /// </summary>
    /// <param name="node"the node to do reduction on></param>
    virtual void Reduce(OpNode* node) = 0;
    /// <summary>
    /// do reduction by type
    /// </summary>
    /// <param name="retain">if true, retain the matched trees,
    /// if false, delete the matched trees.</param>
    /// <param name="type">the type to match</param>
    virtual void ReduceByType(bool retain, int type) = 0;
    /// <summary>
    /// do reduction with according to a number filter
    /// </summary>
    /// <param name="type">the type to match</param>
    /// <param name="filter">the number filter carrying the rules</param>
    virtual void ReduceByNumberFilter(int type, INumberFilter* filter) = 0;
    /// <summary>
    /// reduce by depth, root is of depth 0
    /// </summary>
    /// <param name="depth">the max depth for reduction</param>
    virtual void ReduceByDepth(int depth) = 0;
    /// <summary>
    /// set the base address of the process image
    /// </summary>
    /// <param name="addr">the base address of the prcess image</param>
    virtual void SetImageBaseAddress(uint64_t addr) = 0;
    /// <summary>
    /// set initial stack address in a period
    /// </summary>
    /// <param name="addr">the initial stack address for the current period</param>
    virtual void SetStackAddress(uint64_t addr) = 0;
    /// <summary>
    /// print the forest
    /// </summary>
    virtual void Print() = 0;
};

/// <summary>
/// build an arithmetic forest
/// </summary>
/// <returns>pointer to the implimentation</returns>
IArithmeticForest* CreateArithmeticForest();

/// <summary>
/// destroy the forest
/// </summary>
/// <param name="forest">pointer to the implimentation</param>
void DestroyArithmeticForest(IArithmeticForest* forest);

#endif // _ARITHMETIC_TREE_H_