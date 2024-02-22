#include "ArithmeticTree.h"

#include <math.h>

#include "TreeReducer.h"
#include "SerialGenerator.h"
#include "alu.h"
#define ZYDIS_STATIC_BUILD
extern "C" {
#include "zydis/Zydis.h"
}


/// <summary>
/// constructor by (type, addr), value and ins_addr.
/// serial is auto generated.
/// </summary>
OpNode::OpNode(int _type, uint64_t _addr,
    uint64_t _value, uint64_t _ins_addr) :
    type(_type), addr(_addr), value(_value),
    height(1), ins_addr(_ins_addr), not_flag(0), factor(1), refer(nullptr),
    op(0), left(nullptr), right(nullptr) {
    serial = IGlobalIntegerSerialGenerator::Generate(INTEGER_SERIAL_CLASS_VMP_BLOCK);
}

/// <summary>
/// constructor by serial, (type, addr), value and ins_addr.
/// serial is set by input.
/// </summary>
OpNode::OpNode(uint64_t _serial, int _type, uint64_t _addr,
    uint64_t _value, uint64_t _ins_addr) :
    serial(_serial), type(_type), addr(_addr), value(_value),
    height(1), ins_addr(_ins_addr), not_flag(0), factor(1), refer(nullptr),
    op(0), left(nullptr), right(nullptr) {
}

/// <summary>
/// destructor
/// no inheritance is designed to exist, so it is not virtual
/// </summary>
OpNode::~OpNode() {
    Reset();
}

/// <summary>
/// reset
/// </summary>
void OpNode::Reset() {
    if (this->left) {
        delete this->left;
        this->left = nullptr;
    }
    if (this->right) {
        delete this->right;
        this->right = nullptr;
    }
    if (this->refer) {
        delete this->refer;
        this->refer = nullptr;
    }
}

/// <summary>
/// deep copy a tree
/// </summary>
/// <returns>root of copied tree</returns>
OpNode* OpNode::DeepCopy() {
    OpNode* node = new(std::nothrow) OpNode(serial, type,
        addr, value, ins_addr);
    if (node == nullptr)
        return nullptr;
    node->height = this->height;
    node->not_flag = this->not_flag;
    node->factor = this->factor;
    node->op = this->op;
    if (this->left) {
        node->left = this->left->DeepCopy();
        if (node->left == nullptr) {
            delete node;
            return nullptr;
        }
    }
    if (this->right) {
        node->right = this->right->DeepCopy();
        if (node->right == nullptr) {
            delete node;
            return nullptr;
        }
    }
    if (this->refer) {
        node->refer = this->refer->DeepCopy();
        if (node->refer == nullptr) {
            delete node;
            return nullptr;
        }
    }
    return node;
}

/// <summary>
/// add new root and attach 'left' to it
/// </summary>
/// <param name="op">opcode</param>
/// <param name="left">left child</param>
void OpNode::AddOp(int op, OpNode* left) {
    this->op = op;
    this->left = left;
    this->right = nullptr;
    this->value = OpCalculate(op, left->value);
    this->height += left->height;
}

/// <summary>
/// add new root and attach 'left' and 'right' to it
/// </summary>
/// <param name="op">opcode</param>
/// <param name="left">left child</param>
/// <param name="right">right child</param>
void OpNode::AddOp(int op, OpNode* left, OpNode* right) {
    this->op = op;
    this->left = left;
    this->right = right;
    this->value = OpCalculate(op, left->value, right->value);
    this->height += (left->height > right->height) ? left->height : right->height;
}

/// <summary>
/// check if the node is equal to "this" in (type, addr)
/// </summary>
/// <param name="node">the node to compare</param>
/// <param name="compare_not_flag">compare "not“ flag or not</param>
/// <returns>
/// true if the tree node is equal to
/// the parameter 'node' in (type, addr)
/// </returns>
bool OpNode::IsEqual(OpNode* node, bool compare_not_flag) {
    return OpNode::IsEqual(this, node, compare_not_flag);
}

// true if node1 and node2 are the same in (type, addr)
bool OpNode::IsEqual(OpNode* node1, OpNode* node2, bool compare_not_flag) {
    if (node1->type == node2->type &&
        node1->addr == node2->addr) {
        if (compare_not_flag) {
            if (node1->not_flag == node2->not_flag) {
                return true;
            }
            return false;
        }
        return true;
    }
    return false;
}

/// <summary>
/// merge a tree into this tree
/// </summary>
/// <param name="node"></param>
/// <returns>succeeded or not</returns>
bool OpNode::Merge(OpNode* node) {
    // leaves can only be affected by previous operations
    if (node->serial >= this->serial)
        return false;
    bool merged = false;
    // replace leaves with node
    if (this->left) {
        if (this->left->left == nullptr &&
            this->left->right == nullptr) { // the left leaf
            if (this->left->IsEqual(node, false)) {
                // flip the not flag
                if (this->left->not_flag)
                    node->not_flag = !node->not_flag;
                delete this->left;
                this->left = node->DeepCopy();
                merged = true;
            }
        }
        else { // the left subtree
            merged |= this->left->Merge(node);
        }
    }
    if (this->right) {
        if (this->right->left == nullptr &&
            this->right->right == nullptr) { // the right leaf
            if (this->right->IsEqual(node, false)) {
                // flip the not flag
                if (this->right->not_flag)
                    node->not_flag = !node->not_flag;
                delete this->right;
                this->right = node->DeepCopy();
                merged = true;
            }
        }
        else { // the right subtree
            merged |= this->right->Merge(node);
        }
    }
    return merged;
}

// Replace the current the node by its left child to shorten the tree.
// This function won't be performed on roots.
void OpNode::ReplaceNodeWithLelfChild(bool retain_addr/*= false*/) {
    OpNode::ReplaceNodeWithLelfChild(this, retain_addr);
}

// get the root or child node with given instruction address
OpNode* OpNode::GetNodeByInsAddr(uint64_t ins_addr) {
    if (this->ins_addr == ins_addr)
        return this;
    OpNode* result = nullptr;
    if (this->left) {
        result = this->left->GetNodeByInsAddr(ins_addr);
        if (result)
            return result;
    }
    if (this->right) {
        result = this->right->GetNodeByInsAddr(ins_addr);
        if (result)
            return result;
    }
    return nullptr;
}

// re-calculate the tree height and return the new height
int OpNode::UpdateHeight() {
    int left_height = this->left ? this->left->UpdateHeight() : 0;
    int right_height = this->right ? this->right->UpdateHeight() : 0;
    this->height = ((left_height > right_height) ? left_height : right_height) + 1;
    return this->height;
}

// reduce by depth, root is of depth 0
void OpNode::ReduceByDepth(int depth) {
    if (depth == 0) {
        if (this->left) {
            delete this->left;
            this->left = nullptr;
        }
        if (this->right) {
            delete this->right;
            this->right = nullptr;
        }
    }
    else {
        if (this->left)
            this->left->ReduceByDepth(depth - 1);
        if (this->right)
            this->right->ReduceByDepth(depth - 1);
    }
}

// print the tree recursively
void OpNode::Print(int leading_spaces/*= 0*/, uint64_t stack_addr/*= 0*/) {
    // don't allocate stack in this function, in case the call stack is too deep to be hold in memory.
    for (int i = 0; i < leading_spaces; ++i) putchar(' ');
    int64_t offset_from_rsp = this->addr - stack_addr;
    if (this->addr > 0x10000) {
        printf("%s %s 0x%lf * [%c0x%llx] (0x%llx) %d [\n",
            this->GetTypeName(this->type), this->not_flag ? "not" : "",
            this->factor, (offset_from_rsp >= 0) ? '+' : '-', abs(offset_from_rsp),
            this->value, this->height);
    }
    else {
        printf("%s %s 0x%lf * 0x%llx (0x%llx) %d [\n",
            this->GetTypeName(this->type), this->not_flag ? "not" : "",
            this->factor, this->addr,
            this->value, this->height);
    }
    if (this->left) {
        for (int i = 0; i < leading_spaces + 2; ++i) putchar(' ');
        printf("%s\n", this->GetOpName(this->op));
    }
    if (this->left)
        this->left->Print(leading_spaces + 2, stack_addr);
    if (this->right)
        this->right->Print(leading_spaces + 2, stack_addr);
    for (int i = 0; i < leading_spaces; ++i) putchar(' ');
    printf("]\n");
}

/// print the tree's member "refer" recursively
void OpNode::PrintRefer(int leading_spaces/*= 0*/, uint64_t stack_addr/*= 0*/) {
    // don't allocate stack in this function, in case the call stack is too deep to be hold in memory.
    for (int i = 0; i < leading_spaces; ++i) putchar(' ');
    int64_t offset_from_rsp = this->addr - stack_addr;
    if (this->addr > 0x10000) {
        printf("%s %s 0x%lf * [%c0x%llx] (0x%llx) %d [\n",
            this->GetTypeName(this->type), this->not_flag ? "not" : "",
            this->factor, (offset_from_rsp >= 0) ? '+' : '-', abs(offset_from_rsp),
            this->value, this->height);
    }
    else {
        printf("%s %s 0x%lf * 0x%llx (0x%llx) %d [\n",
            this->GetTypeName(this->type), this->not_flag ? "not" : "",
            this->factor, this->addr,
            this->value, this->height);
    }
    if (this->refer)
        // printing the "refer" tree is the same as printing a normal tree
        this->refer->Print(leading_spaces + 2, stack_addr);
    for (int i = 0; i < leading_spaces; ++i) putchar(' ');
    printf("]\n");
}

// search for a (type, addr) in the tree, and call callback along the tree route
bool OpNode::SearchAddrUp(int type, uint64_t addr, OpNodeSearchCallback callback) {
    return SearchAddrUpInternal(type, addr, false, callback);
}

// search for a (type, addr) in the tree, and call callback along the tree route
bool OpNode::SearchAddrUpInternal(int type, uint64_t addr,
    bool hit, OpNodeSearchCallback callback) {
    // search in the left subtree
    bool found_on_left = false;
    if (this->left) {
        found_on_left = this->left->SearchAddrUpInternal(type, addr,
            hit, callback);
    }
    // search in the right subtree
    bool found_on_right = false;
    if (this->right) {
        found_on_right = this->right->SearchAddrUpInternal(type, addr,
            hit, callback);
    }
    if (this->type == type) {
        if (found_on_left || found_on_right) { // found in subtrees
            if (this->addr == addr) {
                callback(this, true); // hit
                return true;
            }
            else {
                return callback(this, false); // new
            }
        }
        else if (this->addr == addr) { // duplicated
            callback(this, true); // hit
            return true;
        }
    }
    // return true if subtrees contains target memory
    return found_on_left || found_on_right;
}

// search for a (type, addr) in the tree, and call callback along the tree route
bool OpNode::SearchAddrDown(int type, uint64_t addr, OpNodeSearchCallback callback) {
    return SearchAddrDownInternal(type, addr, false, callback);
}

// search for a (type, addr) in the tree, and call callback along the tree route
bool OpNode::SearchAddrDownInternal(int type, uint64_t addr,
    bool hit, OpNodeSearchCallback callback) {
    // if target node has been found
    if (hit || (this->type == type && this->addr == addr)) {
        // if the current node is the one being searched
        if (this->type == type && this->addr == addr) {
            callback(this, true); // hit
        }
        else {
            callback(this, false); // false
        }
        // search the subtrees with the info that the target has been found
        if (this->left) {
            this->left->SearchAddrDownInternal(type, addr, true, callback);
        }
        if (this->right) {
            this->right->SearchAddrDownInternal(type, addr, true, callback);
        }
        return true;
    }
    else {
        // search the subtrees
        bool found = false;
        if (this->left) {
            found |= this->left->SearchAddrDownInternal(type, addr, false, callback);
        }
        if (this->right) {
            found |= this->right->SearchAddrDownInternal(type, addr, false, callback);
        }
        return found;
    }
}

// Replace the node by its left child to shorten the tree.
// This function won't be performed on roots.
void OpNode::ReplaceNodeWithLelfChild(OpNode* node, bool retain_addr/*= false*/) {
    OpNode*  to_free = node->left;
    int      type = node->type;
    uint64_t addr = node->addr;
    uint64_t value = node->value;
    int      not_flag = node->not_flag ^ node->left->not_flag;
    double   factor = node->factor * node->left->factor;
    OpNode*  refer = node->refer;
    *node = *(node->left);
    if (retain_addr) {
        node->type = type;
        node->addr = addr;
        node->value = value;
    }
    node->not_flag = not_flag;
    node->factor = factor;
    node->ins_addr = 0; // the tree is reduced, ins_addr is meaningless now
    // refer of leaves are always retained
    if (node->left || node->right) { // not leaf
        if (node->refer)
            delete node->refer;
        node->refer = refer;
    }
    if (to_free) {
        to_free->left = nullptr;
        to_free->right = nullptr;
        to_free->refer = nullptr;
        delete to_free;
    }
}

// to readable
const char* OpNode::GetTypeName(int type) {
    switch (type) {
    case OPNODE_OPERAND_TYPE_VIRTUAL:
        return "virtual";
    case ZYDIS_OPERAND_TYPE_MEMORY:
        return "mem";
    case ZYDIS_OPERAND_TYPE_REGISTER:
        return "reg";
    case ZYDIS_OPERAND_TYPE_IMMEDIATE:
        return "imm";
    default:
        return "unknown";
    }
}

// to readable
const char* OpNode::GetOpName(int op) {
    switch (op) {
    case ZYDIS_MNEMONIC_MOV:
        return "MOV";
    case ZYDIS_MNEMONIC_LEA:
        return "LEA";
    case ZYDIS_MNEMONIC_NOT:
        return "NOT";
    case ZYDIS_MNEMONIC_NEG:
        return "NEG";
    case ZYDIS_MNEMONIC_AND:
        return "AND";
    case ZYDIS_MNEMONIC_OR:
        return "OR";
    case ZYDIS_MNEMONIC_XOR:
        return "XOR";
    case ZYDIS_MNEMONIC_ADD:
        return "+";
    case ZYDIS_MNEMONIC_SUB:
        return "-";
    case ZYDIS_MNEMONIC_MUL:
        return "*";
    case ZYDIS_MNEMONIC_DIV:
        return "/";
    default:
        return "unknown";
    }
}


/// <summary>
/// Implementation of ArithmeticForest
/// </summary>
class ArithmeticForest : public IArithmeticForest {
public:
    /// <summary>
    /// constructor
    /// </summary>
    ArithmeticForest();
    /// <summary>
    /// destructor
    /// </summary>
    virtual ~ArithmeticForest();
    /// <summary>
    /// clear the forest
    /// </summary>
    void Reset();
    /// <summary>
    /// get the trees as a vector
    /// </summary>
    /// <returns>the vector containing the trees</returns>
    std::vector<OpNode*>* GetTrees();
    /// <summary>
    /// get the trees whose root values are the parameter result
    /// </summary>
    /// <param name="result_forest">the vector containing the matched trees</param>
    /// <param name="result">the calculation result of the tree to match</param>
    void GetTreesByResult(std::vector<OpNode*>& result_forest, uint64_t result);
    /// <summary>
    /// add a one register operation. {push, pop} are not one register operations, for they involves memory I/O.
    /// </summary>
    /// <param name="ins_addr">instruction address</param>
    /// <param name="op">operator</param>
    /// <param name="reg_addr">the virtual address representing the register</param>
    /// <param name="reg_value">the value of the register</param>
    /// <returns>succeeded or not</returns>
    bool AddNode(
        uint64_t ins_addr,
        int                op,
        uint64_t reg_addr,
        uint64_t reg_value);
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
    bool AddNode(
        uint64_t ins_addr,
        int      op,
        int      des_type,
        uint64_t des_addr,
        uint64_t des_value,
        int      src_type,
        uint64_t src_addr,
        uint64_t src_value);
    /// <summary>
    /// set node factor
    /// </summary>
    /// <param name="reg">the register to operate on</param>
    /// <param name="factor">factor multiplied to the register</param>
    /// <returns></returns>
    bool SetNodeFactor(uint64_t reg, double factor);
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
    bool SetNodeMemRefSubTree(uint64_t addr,
        uint32_t base, uint64_t base_value,
        bool has_index, uint32_t index, uint64_t index_value, uint32_t scale,
        bool has_displacement, uint64_t displacement_value);
    /// <summary>
    /// delete a tree by its root node
    /// </summary>
    /// <param name="node">the node to delete</param>
    /// <returns>true if the tree is found and deleted</returns>
    bool DeleteTree(OpNode* node);
    /// <summary>
    /// do reduction to the forest
    /// </summary>
    void Reduce();
    /// <summary>
    /// do reduction to a tree or tree node
    /// </summary>
    /// <param name="node"the node to do reduction on></param>
    void Reduce(OpNode* node);
    /// <summary>
    /// do reduction by type
    /// </summary>
    /// <param name="retain">if true, retain the matched trees,
    /// if false, delete the matched trees.</param>
    /// <param name="type">the type to match</param>
    void ReduceByType(bool retain, int type);
    /// <summary>
    /// do reduction with according to a number filter
    /// </summary>
    /// <param name="type">the type to match</param>
    /// <param name="filter">the number filter carrying the rules</param>
    void ReduceByNumberFilter(int type, INumberFilter* filter);
    /// <summary>
    /// reduce by depth, root is of depth 0
    /// </summary>
    /// <param name="depth">the max depth for reduction</param>
    void ReduceByDepth(int depth);
    /// <summary>
    /// set the base address of the process image
    /// </summary>
    /// <param name="addr">the base address of the prcess image</param>
    void SetImageBaseAddress(uint64_t addr);
    /// <summary>
    /// set initial stack address in a period
    /// </summary>
    /// <param name="addr">the initial stack address for the current period</param>
    void SetStackAddress(uint64_t addr);
    /// <summary>
    /// print the forest
    /// </summary>
    void Print();
protected:
    // add a unitary operation node whose des and src are the same register, like not or neg
    bool AddNodeInternal(
        uint64_t ins_addr,
        int                op,
        uint64_t reg_addr,
        uint64_t reg_value);
    // add a unitary operation node whose des and src may be different, like mov
    bool AddNodeInternal(
        uint64_t ins_addr,
        int                op,
        int                des_type,
        uint64_t des_addr,
        int                src_type,
        uint64_t src_addr,
        uint64_t src_value);
    // add a binary operation node, like add or and
    bool AddNodeInternal(
        uint64_t ins_addr,
        int      op,
        int      des_type,
        uint64_t des_addr,
        int      src1_type,
        uint64_t src1_addr,
        uint64_t src1_value,
        int      src2_type,
        uint64_t src2_addr,
        uint64_t src2_value);
    // check if the node will be added as an immediate value
    bool CheckIsImmediateNode(int op, int des_type, uint64_t des_addr,
        int src_type, uint64_t src_addr, uint64_t src_value);
    // check if the node will be added as an immediate value for binary operation
    bool CheckIsFakeBinaryOperation(int op, int des_type, uint64_t des_addr,
        int src_type, uint64_t src_addr, uint64_t src_value, int* new_op);
    // find the tree of which the root is addr
    OpNode* FindAddr(int type, uint64_t addr, bool copy);
    // when addr is overwritten, the tree that has root address value equal to addr is outdated.
    void UpdateAddr(int type, uint64_t addr); // remove all trees that match the params
    // remove all trees that has a smaller serial than the serial param and match the following params
    void UpdateAddr(uint64_t serial, int type, uint64_t addr);
protected:
    std::vector<OpNode*> forest; // the forset under current analysis
    uint64_t image_base_addr; // image base of the process
    uint64_t stack_addr; // initial stack address in a period
};

ArithmeticForest::ArithmeticForest() :
    image_base_addr(0), stack_addr(0) {
}

ArithmeticForest::~ArithmeticForest() {
    Reset();
}

void ArithmeticForest::Reset() {
    for (auto i = forest.begin(); i != forest.end(); ++i) {
        delete (*i);
        (*i) = nullptr;
    }
    forest.clear();
}

std::vector<OpNode*>* ArithmeticForest::GetTrees() {
    return &forest;
}

// get the trees whose root values are the parameter result
void ArithmeticForest::GetTreesByResult(std::vector<OpNode*>& result_forest, uint64_t result) {
    for (auto i = forest.begin(); i != forest.end(); ++i) {
        if ((*i)->value == result || ((*i)->not_flag && (*i)->value == ~result)) {
            result_forest.push_back((*i)->DeepCopy());
        }
    }
}

// add a one register operation {push, pop} are not one register operations, for they involves memory I/O.
bool ArithmeticForest::AddNode(
    uint64_t ins_addr,
    int                op,
    uint64_t reg_addr,
    uint64_t reg_value) {
    if (op == ZYDIS_MNEMONIC_INC) { // inc
        return AddNode(ins_addr, ZYDIS_MNEMONIC_ADD, ZYDIS_OPERAND_TYPE_REGISTER, reg_addr, reg_value,
            ZYDIS_OPERAND_TYPE_IMMEDIATE, 0, 1);
    }
    else if (op == ZYDIS_MNEMONIC_DEC) { // dec
        return AddNode(ins_addr, ZYDIS_MNEMONIC_DEC, ZYDIS_OPERAND_TYPE_REGISTER, reg_addr, reg_value,
            ZYDIS_OPERAND_TYPE_IMMEDIATE, 0, 1);
    }
    return AddNodeInternal(ins_addr, op, reg_addr, reg_value);
}

// add a two register operation including {push, pop}
bool ArithmeticForest::AddNode(
    uint64_t ins_addr,
    int      op,
    int      des_type,
    uint64_t des_addr,
    uint64_t des_value,
    int      src_type,
    uint64_t src_addr,
    uint64_t src_value) {
    // check if the subtree is overwritten by immediate value equivalents.
    if (CheckIsImmediateNode(op, des_type, des_addr,
        src_type, src_addr, src_value)) {
        UpdateAddr(des_type, des_addr);
        return true;
    }
    else {
        int new_op = op;
        if (CheckIsFakeBinaryOperation(op, des_type, des_addr,
            src_type, src_addr, src_value, &new_op)) {
            op = new_op;
        }
    }
    // des <- src
    if (op == ZYDIS_MNEMONIC_MOV) {
        return AddNodeInternal(ins_addr, op, des_type, des_addr,
            src_type, src_addr, src_value);
    }
    // des <- src1 op src2
    else {
        return AddNodeInternal(ins_addr, op, des_type, des_addr,
            des_type, des_addr, des_value,
            src_type, src_addr, src_value);
    }
}

bool ArithmeticForest::AddNodeInternal(
    uint64_t ins_addr,
    int      op,
    uint64_t reg_addr,
    uint64_t reg_value) {
    OpNode* node = new(std::nothrow) OpNode(ZYDIS_OPERAND_TYPE_REGISTER, reg_addr, 0, ins_addr);
    if (node == nullptr)
        return false;
    // look up addr in existing trees
    OpNode* left = FindAddr(ZYDIS_OPERAND_TYPE_REGISTER, reg_addr, true);
    if (left) { // the operation must be on existing trees
        left->value = reg_value; // use real-time value
        node->AddOp(op, left); // update the existing tree
        // add new tree to the forest
        forest.push_back(node);
        // some trees are outdated (desitination overwritten)
        UpdateAddr(node->serial, ZYDIS_OPERAND_TYPE_REGISTER, reg_addr);
    }
    else { // // junk instruction
        // the instruction is junk doen't mean the operation has failed 
        delete node;
        node = nullptr;
    }
    return true;
}

bool ArithmeticForest::AddNodeInternal(
    uint64_t ins_addr,
    int      op,
    int      des_type,
    uint64_t des_addr,
    int      src_type,
    uint64_t src_addr,
    uint64_t src_value) {
    OpNode* node = new(std::nothrow) OpNode(des_type, des_addr, 0, ins_addr);
    if (node == nullptr)
        return false;
    // look up addr in existing trees
    OpNode* left = FindAddr(src_type, src_addr, true);
    if (left) { // the operation is on existing trees
        left->value = src_value;
        node->AddOp(op, left);
        forest.push_back(node);
    }
    else { // the operation is not on existing trees
        // allocate new left node
        int type = (src_type == ZYDIS_OPERAND_TYPE_REGISTER) ? ZYDIS_OPERAND_TYPE_IMMEDIATE : src_type;
        left = new(std::nothrow) OpNode(node->serial, type, src_addr, src_value, ins_addr);
        if (left == nullptr)
            return false;
        node->AddOp(op, left);
        forest.push_back(node);
    }
    // some trees are outdated (desitination overwritten)
    UpdateAddr(node->serial, des_type, des_addr);
    return true;
}

bool ArithmeticForest::AddNodeInternal(
    uint64_t ins_addr,
    int      op,
    int      des_type,
    uint64_t des_addr,
    int      src1_type,
    uint64_t src1_addr,
    uint64_t src1_value,
    int      src2_type,
    uint64_t src2_addr,
    uint64_t src2_value) {
    OpNode* node = new(std::nothrow) OpNode(des_type, des_addr, 0, ins_addr);
    if (node == nullptr)
        return false;
    node->ins_addr = ins_addr;
    // look up addr in existing trees
    OpNode* left = FindAddr(src1_type, src1_addr, true);
    if (left == nullptr) { // the operation is not on existing trees
        // allocate new left node
        int type = (src1_type == ZYDIS_OPERAND_TYPE_REGISTER) ? ZYDIS_OPERAND_TYPE_IMMEDIATE : src1_type;
        left = new(std::nothrow) OpNode(node->serial, type, src1_addr, src1_value, ins_addr);
        if (left == nullptr)
            return false;
    }
    left->value = src1_value;
    // look up addr in existing trees
    OpNode* right = FindAddr(src2_type, src2_addr, true);
    if (right == nullptr) { // the operation is not on existing trees
        // allocate new left node
        int type = (src2_type == ZYDIS_OPERAND_TYPE_REGISTER) ? ZYDIS_OPERAND_TYPE_IMMEDIATE : src2_type;
        right = new(std::nothrow) OpNode(node->serial, type, src2_addr, src2_value, ins_addr);
        if (right == nullptr) {
            delete left; // allocated by deepcopy or local new
            return false;
        }
    }
    right->value = src2_value;
    node->AddOp(op, left, right);
    // add new tree to the forest
    forest.push_back(node);
    // some trees are outdated (desitination overwritten)
    UpdateAddr(node->serial, des_type, des_addr);
    return true;
}

bool ArithmeticForest::CheckIsImmediateNode(int op, int des_type, uint64_t des_addr,
    int src_type, uint64_t src_addr, uint64_t src_value) {
    if (op == ZYDIS_MNEMONIC_MOV) { // mov reg, imm
        if (src_type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
            return true;
    }
    else if (op == ZYDIS_MNEMONIC_LEA) { // lea reg, [addr]
        return true;
    }
    else {
        if (op == ZYDIS_MNEMONIC_XOR) { // xor to 0
            if (des_type == ZYDIS_OPERAND_TYPE_REGISTER && src_type == ZYDIS_OPERAND_TYPE_REGISTER &&
                des_addr == src_addr)
                return true;
        }
        // look up addr in existing trees
        OpNode* des = FindAddr(des_type, des_addr, false);
        if (des == nullptr) {
            if (src_type == ZYDIS_OPERAND_TYPE_IMMEDIATE) { // // op reg1(non-root), imm
                return true;
            }
            OpNode* src = FindAddr(des_type, des_addr, false);
            if (src == nullptr) { // op reg1(non-root), reg2(non-root)
                return true;
            }
        }
    }
    return false;
}

bool ArithmeticForest::CheckIsFakeBinaryOperation(int op, int des_type, uint64_t des_addr,
    int src_type, uint64_t src_addr, uint64_t src_value, int* new_op) {
    if (des_type == ZYDIS_OPERAND_TYPE_REGISTER && src_type == ZYDIS_OPERAND_TYPE_REGISTER &&
        des_addr == src_addr) {
        // XOR on the same register is handled by CheckIsImmediateNode
        if (op == ZYDIS_MNEMONIC_AND) {
            if (new_op)
                *new_op = ZYDIS_MNEMONIC_MOV;
            return true;
        }
        else if (op == ZYDIS_MNEMONIC_OR) {
            if (new_op)
                *new_op = ZYDIS_MNEMONIC_MOV;
            return true;
        }
    }
    return false;
}

// find the tree of which the root is addr
OpNode* ArithmeticForest::FindAddr(int type, uint64_t addr, bool copy) {
    for (auto i = forest.begin(); i != forest.end(); ++i) {
        if ((*i)->type == type && (*i)->addr == addr) {
            if (copy)
                return (*i)->DeepCopy();
            else
                return (*i);
        }
    }
    return nullptr;
}

// when addr is overwritten, the tree that has root address value equal to addr is outdated.
// remove all trees that match the params
void ArithmeticForest::UpdateAddr(int type, uint64_t addr) {
    for (auto i = forest.begin(); i != forest.end();) {
        if ((*i)->type == type && (*i)->addr == addr)
            i = forest.erase(i);
        else
            ++i;
    }
}

// when addr is overwritten, the tree that has root address value equal to addr is outdated.
    // remove all trees that has a smaller serial than the serial param and match the following params
void ArithmeticForest::UpdateAddr(uint64_t serial, int type, uint64_t addr) {
    for (auto i = forest.begin(); i != forest.end();) {
        if ((*i)->serial < serial && (*i)->type == type && (*i)->addr == addr)
            i = forest.erase(i);
        else
            ++i;
    }
}

// set node factor
bool ArithmeticForest::SetNodeFactor(uint64_t reg, double factor) {
    // look up reg in existing trees
    OpNode* node = FindAddr(ZYDIS_OPERAND_TYPE_REGISTER, reg, false);
    if (node) { // the operation must be on existing trees
        return true;
    }
    return false;
}

// set a memory reference subtree as the target node's member "refer"
bool ArithmeticForest::SetNodeMemRefSubTree(uint64_t addr,
    uint32_t base, uint64_t base_value,
    bool has_index, uint32_t index, uint64_t index_value, uint32_t scale,
    bool has_displacement, uint64_t displacement_value) {
    // look up addr in existing trees
    OpNode* node = FindAddr(ZYDIS_OPERAND_TYPE_MEMORY, addr, false);
    if (node) { // the operation must be on existing trees
        // build memory reference subtree
        if (node->refer) {
            delete node->refer;
            node->refer = nullptr;
        }
        uint64_t serial = node->serial;
        uint64_t ins_addr = node->ins_addr;
        if (has_index && has_displacement) {
            // virtual node == base + index * scale + displacement
            node->refer = new(std::nothrow) OpNode(serial,
                OPNODE_OPERAND_TYPE_VIRTUAL, 0,
                base_value + index_value * scale + displacement_value, ins_addr);
            if (node->refer == nullptr)
                return false;
            // virtual node == base + index * scale
            node->refer->left = new(std::nothrow) OpNode(serial,
                OPNODE_OPERAND_TYPE_VIRTUAL, 0,
                base_value + index_value * scale, ins_addr);
            if (node->refer->left == nullptr) {
                delete node->refer;
                node->refer = nullptr;
                return false;
            }
            // base
            node->refer->left->left = new(std::nothrow) OpNode(serial,
                ZYDIS_OPERAND_TYPE_REGISTER, base,
                base_value, ins_addr);
            if (node->refer->left->left == nullptr) {
                delete node->refer; // it also deletes all its subtrees
                node->refer = nullptr;
                return false;
            }
            // index * scale
            node->refer->left->right = new(std::nothrow) OpNode(serial,
                ZYDIS_OPERAND_TYPE_REGISTER, index,
                index_value, ins_addr);
            if (node->refer->left->right == nullptr) {
                delete node->refer; // it also delete all its subtrees
                node->refer = nullptr;
                return false;
            }
            node->refer->left->right->factor = scale;
            // displacement
            node->refer->right = new(std::nothrow) OpNode(serial,
                ZYDIS_OPERAND_TYPE_IMMEDIATE, displacement_value,
                index_value, ins_addr);
            if (node->refer->right == nullptr) {
                delete node->refer; // it also delete all its subtrees
                node->refer = nullptr;
                return false;
            }
        }
        else if (has_index) {
            // virtual node == base + index * scale
            node->refer = new(std::nothrow) OpNode(serial,
                OPNODE_OPERAND_TYPE_VIRTUAL, 0,
                base_value + index_value * scale, ins_addr);
            if (node->refer == nullptr)
                return false;
            // base
            node->refer->left = new(std::nothrow) OpNode(serial,
                ZYDIS_OPERAND_TYPE_REGISTER, base,
                base_value, ins_addr);
            if (node->refer->left == nullptr) {
                delete node->refer;
                node->refer = nullptr;
                return false;
            }
            // index * scale
            node->refer->right = new(std::nothrow) OpNode(serial,
                ZYDIS_OPERAND_TYPE_REGISTER, index,
                index_value, ins_addr);
            if (node->refer->right == nullptr) {
                delete node->refer; // it also delete node->refer->left
                node->refer = nullptr;
                return false;
            }
            node->refer->right->factor = scale;
        }
        else if (has_displacement) {
            // virtual node == base + displacement
            node->refer = new(std::nothrow) OpNode(serial,
                OPNODE_OPERAND_TYPE_VIRTUAL, 0,
                base_value + displacement_value, ins_addr);
            if (node->refer == nullptr)
                return false;
            // base
            node->refer->left = new(std::nothrow) OpNode(serial,
                ZYDIS_OPERAND_TYPE_REGISTER, base,
                base_value, ins_addr);
            if (node->refer->left == nullptr) {
                delete node->refer;
                node->refer = nullptr;
                return false;
            }
            // displacement
            node->refer->right = new(std::nothrow) OpNode(serial,
                ZYDIS_OPERAND_TYPE_IMMEDIATE, displacement_value,
                index_value, ins_addr);
            if (node->refer->right == nullptr) {
                delete node->refer; // it also delete node->refer->left
                node->refer = nullptr;
                return false;
            }
        }
        else { // !has_index && !has_displacement
            // virtual node == base, a virtual node must be there to simplify the analysis
            node->refer = new(std::nothrow) OpNode(serial,
                OPNODE_OPERAND_TYPE_VIRTUAL, 0,
                base_value, ins_addr);
            if (node->refer == nullptr)
                return false;
            node->refer->left = new(std::nothrow) OpNode(serial,
                ZYDIS_OPERAND_TYPE_REGISTER, base,
                base_value, ins_addr);
            if (node->refer->left == nullptr) {
                delete node->refer;
                node->refer = nullptr;
                return false;
            }
        }
        // merge, replace the new leaves with existing trees
        for (auto i = forest.rbegin() + 1; i != forest.rend(); i++) {
            node->refer->Merge(*i);
        }
        return true;
    }
    return false;
}

// delete a tree by node, return true if the tree to delete is found
bool ArithmeticForest::DeleteTree(OpNode* node) {
    bool found = false;
    for (auto i = forest.begin(); i != forest.end(); ++i) {
        if ((*i) == node) {
            delete* i;
            *i = nullptr;
            forest.erase(i);
            found = true;
            break;
        }
    }
    if (!found) {
        for (auto i = forest.begin(); i != forest.end(); ++i) {
            if ((*i)->IsEqual(node, true)) {
                delete* i;
                *i = nullptr;
                forest.erase(i);
                found = true;
            }
        }
    }
    return found;
}

// do reduction to the forest
void ArithmeticForest::Reduce() {
    // reduce per tree
    for (auto i = forest.begin(); i != forest.end(); ++i) {
        Reduce(*i);
    }
}

// do reduction to a tree or tree node
void ArithmeticForest::Reduce(OpNode* node) {
    bool modified = false;
    bool current_step_modified = false;
    // simplify nodes connected by unitary operations
    current_step_modified = ReduceUnitaryArithmeticNodes(node);
    modified = modified || current_step_modified;
    // simplify mov operations
    current_step_modified |= ReduceMov(node);
    modified = modified || current_step_modified;
    // op reg; mov op mem -> pseudo op reg, mem
    // this operation doesn't affect tree height
    ReduceUnitaryArithmeticNodesR2M(node);
    // transfrom fake binary nodes to simplified form
    current_step_modified = ReduceFakeBinaryNodes(node);
    modified = modified || current_step_modified;
    // OR to AND
    // this operation doesn't affect tree height
    ReduceOr2And(node);
    // match XOR operations
    current_step_modified = ReduceMatchXor(node);
    modified = modified || current_step_modified;
    // update tree height if needed
    if (modified)
        node->UpdateHeight();
}

// do reduction by type
void ArithmeticForest::ReduceByType(bool retain, int type) {
    for (auto i = forest.begin(); i != forest.end();) {
        if (retain) {
            if ((*i)->type != type)
                i = forest.erase(i);
            else
                ++i;
        }
        else {
            if ((*i)->type == type)
                i = forest.erase(i);
            else
                ++i;
        }
    }
}

// do reduction with according to a number filter
void ArithmeticForest::ReduceByNumberFilter(int type, INumberFilter* filter) {
    for (auto i = forest.begin(); i != forest.end();) {
        if ((*i)->type == type && filter->IsDropULL((*i)->addr))
            i = forest.erase(i);
        else
            ++i;
    }
}

// reduce by depth, root is of depth 0
void ArithmeticForest::ReduceByDepth(int depth) {
    for (auto i = forest.begin(); i != forest.end();i ++) {
        (*i)->ReduceByDepth(depth);
    }
}

void ArithmeticForest::Print() {
    for (auto i = forest.begin(); i != forest.end(); ++i) {
        (*i)->Print(0, stack_addr);
    }
}

// set image base address
void ArithmeticForest::SetImageBaseAddress(uint64_t addr) {
    this->image_base_addr = addr;
}

// set stack address
void ArithmeticForest::SetStackAddress(uint64_t addr) {
    this->stack_addr = addr;
}


// make an arithmetic forest
IArithmeticForest* CreateArithmeticForest() {
    return (new(std::nothrow) ArithmeticForest());
}

// destroy the forest
void DestroyArithmeticForest(IArithmeticForest* forest) {
    if (forest)
        delete forest;
}


class ArithmeticForestTest {
public:
    ArithmeticForestTest() {
        uint8_t stack_mem[0x200] = { 0 };
        for (int i = 0; i < sizeof(stack_mem); ++i) {
            stack_mem[i] = i;
        }
        IArithmeticForest& forest = *CreateArithmeticForest();
        if (&forest == nullptr)
            return;
        // mov rsp, 200h
        // ZYDIS_REGISTER_MAX_VALUE is 265, address above 0x200 won't cause conflicts
        uint64_t rsp = 0x200;
        uint64_t rax = 0;
        uint64_t rcx = 0;
        uint64_t rdx = 0;
        uint64_t rbx = 0;
        // mov rax, [rsp - 8h] ; build tree only when loading memory
        // add rax, 10h
        // mov [rsp - 10h], rax
        forest.AddNode(0, ZYDIS_MNEMONIC_MOV, ZYDIS_OPERAND_TYPE_REGISTER, ZYDIS_REGISTER_RAX, 0,
            ZYDIS_OPERAND_TYPE_MEMORY, rsp - 0x8, stack_mem[rsp - 0x8]);
        rax = *(uint64_t*)&stack_mem[rsp - 0x8];
        forest.AddNode(0, ZYDIS_MNEMONIC_ADD, ZYDIS_OPERAND_TYPE_REGISTER, ZYDIS_REGISTER_RAX, rax,
            ZYDIS_OPERAND_TYPE_IMMEDIATE, 0, 0x10);
        rax += 0x10;
        forest.AddNode(0, ZYDIS_MNEMONIC_MOV, ZYDIS_OPERAND_TYPE_MEMORY, rsp - 0x10, 0,
            ZYDIS_OPERAND_TYPE_REGISTER, ZYDIS_REGISTER_RAX, rax); // always prefer realtime values to internal calculations
        *(uint64_t*)&stack_mem[rsp - 0x10] = rax; // we calculate rax also for this step
        // mov rax, [rsp - 18h] ; build tree when loading memory
        // add rax, 10h
        // xor rax, rax         ; previous operations are cleared. the tree will clear the operations only when ArithmeticForest::Reduce is called
        // inc rax              ; it will be recorded as "add rax, 1"
        // mov rcx, [rsp - 20h] ; build tree when loading memory
        // add rax, rcx
        // not rax
        // mov [rsp - 28h], rax
        forest.AddNode(0, ZYDIS_MNEMONIC_MOV, ZYDIS_OPERAND_TYPE_REGISTER, ZYDIS_REGISTER_RAX, 0,
            ZYDIS_OPERAND_TYPE_MEMORY, rsp - 0x18, stack_mem[rsp - 0x18]);
        rax = *(uint64_t*)&stack_mem[rsp - 0x18];
        forest.AddNode(0, ZYDIS_MNEMONIC_ADD, ZYDIS_OPERAND_TYPE_REGISTER, ZYDIS_REGISTER_RAX, rax,
            ZYDIS_OPERAND_TYPE_IMMEDIATE, 0, 0x10);
        rax += 0x10;
        forest.AddNode(0, ZYDIS_MNEMONIC_XOR, ZYDIS_OPERAND_TYPE_REGISTER, ZYDIS_REGISTER_RAX, rax,
            ZYDIS_OPERAND_TYPE_REGISTER, ZYDIS_REGISTER_RAX, rax);
        rax = 0;
        forest.AddNode(0, ZYDIS_MNEMONIC_ADD, ZYDIS_OPERAND_TYPE_REGISTER, ZYDIS_REGISTER_RAX, rax,
            ZYDIS_OPERAND_TYPE_IMMEDIATE, 0, 0x1);
        rax += 0x1;
        forest.AddNode(0, ZYDIS_MNEMONIC_MOV, ZYDIS_OPERAND_TYPE_REGISTER, ZYDIS_REGISTER_RCX, 0,
            ZYDIS_OPERAND_TYPE_MEMORY, rsp - 0x20, stack_mem[rsp - 0x20]);
        rcx = *(uint64_t*)&stack_mem[rsp - 0x20];
        forest.AddNode(0, ZYDIS_MNEMONIC_ADD, ZYDIS_OPERAND_TYPE_REGISTER, ZYDIS_REGISTER_RAX, rax,
            ZYDIS_OPERAND_TYPE_REGISTER, ZYDIS_REGISTER_RCX, 0x1);
        rax += rcx;
        forest.AddNode(0, ZYDIS_MNEMONIC_NOT, ZYDIS_REGISTER_RAX, rax);
        rax = (uint64_t)(0 - rax);
        forest.AddNode(0, ZYDIS_MNEMONIC_MOV, ZYDIS_OPERAND_TYPE_MEMORY, rsp - 0x28, 0,
            ZYDIS_OPERAND_TYPE_REGISTER, ZYDIS_REGISTER_RAX, rax);
        *(uint64_t*)&stack_mem[rsp - 0x28] = rax;
        // mov rax, [rsp - 28h] ; build tree when loading memory
        // inc rax              ; it will be recorded as "add rax, 1"
        // mov rcx, [rsp - 30h] ; build tree when loading memory
        // add rax, rcx
        // not rax
        // mov [rsp - 38h], rax
        forest.AddNode(0, ZYDIS_MNEMONIC_MOV, ZYDIS_OPERAND_TYPE_REGISTER, ZYDIS_REGISTER_RAX, 0,
            ZYDIS_OPERAND_TYPE_MEMORY, rsp - 0x28, stack_mem[rsp - 0x28]);
        rax = *(uint64_t*) & stack_mem[rsp - 0x28];
        forest.AddNode(0, ZYDIS_MNEMONIC_ADD, ZYDIS_OPERAND_TYPE_REGISTER, ZYDIS_REGISTER_RAX, rax,
            ZYDIS_OPERAND_TYPE_IMMEDIATE, 0, 0x1);
        rax += 0x1;
        forest.AddNode(0, ZYDIS_MNEMONIC_MOV, ZYDIS_OPERAND_TYPE_REGISTER, ZYDIS_REGISTER_RCX, 0,
            ZYDIS_OPERAND_TYPE_MEMORY, rsp - 0x30, stack_mem[rsp - 0x30]);
        rcx = *(uint64_t*) & stack_mem[rsp - 0x30];
        forest.AddNode(0, ZYDIS_MNEMONIC_ADD, ZYDIS_OPERAND_TYPE_REGISTER, ZYDIS_REGISTER_RAX, rax,
            ZYDIS_OPERAND_TYPE_REGISTER, ZYDIS_REGISTER_RCX, 0x1);
        rax += rcx;
        forest.AddNode(0, ZYDIS_MNEMONIC_NOT, ZYDIS_REGISTER_RAX, rax);
        rax = (uint64_t)(0 - rax);
        forest.AddNode(0, ZYDIS_MNEMONIC_MOV, ZYDIS_OPERAND_TYPE_MEMORY, rsp - 0x38, 0,
            ZYDIS_OPERAND_TYPE_REGISTER, ZYDIS_REGISTER_RAX, rax);
        *(uint64_t*)& stack_mem[rsp - 0x38] = rax;
        // reduce the effectless nodes
        forest.Reduce();
        forest.Print();
        DestroyArithmeticForest(&forest);
    }
};
//static ArithmeticForestTest g_ArithmeticForestTest;
