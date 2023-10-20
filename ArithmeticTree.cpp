#include "ArithmeticTree.h"
#include "TreeReducer.h"
#include "SerialGenerator.h"
#include "alu.h"
#define ZYDIS_STATIC_BUILD
extern "C" {
#include "Zydis.h"
}

//#define DEBUG_OPNODE_MEM

OpNode::OpNode(int _type, unsigned long long _addr, unsigned long long _value/*= 0*/) :
    type(_type), addr(_addr), value(_value),
    not_flag(0), factor(1), ins_addr(0),
    left(nullptr), right(nullptr), height(1), op(0), operand_count(0) {
    this->serial = IGlobalIntegerSerialGenerator::Generate(INTEGER_SERIAL_CLASS_VMP_BLOCK);
}

OpNode::OpNode(unsigned long long _serial, int _type, unsigned long long _addr, unsigned long long _value/*= 0*/) :
    serial(_serial), type(_type), addr(_addr), value(_value),
    not_flag(0), factor(1), ins_addr(0),
    left(nullptr), right(nullptr), height(1), op(0), operand_count(0) {
}

OpNode* OpNode::DeepCopy() {
    OpNode* node = new(std::nothrow)OpNode(this->serial, this->type, this->addr, this->value);
    if (node == nullptr)
        return nullptr;
    node->height = this->height;
    node->not_flag = this->not_flag;
    node->factor = this->factor;
    node->op = this->op;
    node->operand_count = this->operand_count;
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
            delete node->left;
            delete node;
            return nullptr;
        }
    }
    return node;
}

OpNode::~OpNode() { // no inheritance exists, so it is not virtual
    this->Clear();
}

void OpNode::Clear() {
    if (this->left) {
#ifdef DEBUG_OPNODE_MEM
        printf("delete 0x%llx\n", this->left);
#endif // DEBUG_OPNODE_MEM
        delete this->left;
        this->left = nullptr;
    }
    if (this->right) {
#ifdef DEBUG_OPNODE_MEM
        printf("delete 0x%llx\n", this->right);
#endif // DEBUG_OPNODE_MEM
        delete this->right;
        this->right;
    }
}

void OpNode::AddOp(int op, OpNode* left) {
    this->op = op;
    this->operand_count = 1;
    this->left = left;
    this->value = OpCalculate(op, left->value);
    this->height += left->height;
}

void OpNode::Add2Op(int op, OpNode* left, OpNode* right) {
    this->op = op;
    this->operand_count = 2;
    this->left = left;
    this->right = right;
    this->value = OpCalculate(op, left->value, right->value);
    this->height += (left->height > right->height) ? left->height : right->height;
}

bool OpNode::IsEqual(OpNode* node, bool compare_not_flag) {
    return OpNode::IsEqual(this, node, compare_not_flag);
}

void OpNode::ReplaceNodeWithLelfChild(bool retain_addr/*= false*/) {
    OpNode::ReplaceNodeWithLelfChild(this, retain_addr);
}

int OpNode::UpdateHeight() {
    int left_height = this->left ? this->left->UpdateHeight() : 0;
    int right_height = this->right ? this->right->UpdateHeight() : 0;
    this->height = ((left_height > right_height) ? left_height : right_height) + 1;
    return this->height;
}

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

void OpNode::Print(int leading_spaces/*= 0*/) {
    // don't allocate stack in this function, in case the call stack is too deep to be hold in memory.
#ifdef DEBUG_OPNODE_MEM
    for (int i = 0; i < leading_spaces; i++) putchar(' ');
    printf("Address 0x%llx\n", this);
#endif // DEBUG_OPNODE_MEM
    for (int i = 0; i < leading_spaces; i++) putchar(' ');
    printf("%s %s 0x%lf * 0x%llx (0x%llx) %d [\n",
        this->GetTypeName(this->type), this->not_flag ? "not" : "",
        this->factor, this->addr, this->value, this->height);
    if (this->operand_count > 0) {
        for (int i = 0; i < leading_spaces + 2; i++) putchar(' ');
        printf("%s\n", this->GetOpName(this->op));
    }
    if (this->left)
        this->left->Print(leading_spaces + 2);
    if (this->right)
        this->right->Print(leading_spaces + 2);
    for (int i = 0; i < leading_spaces; i++) putchar(' ');
    printf("]\n");
}

bool OpNode::IsEqual(OpNode* node1, OpNode* node2, bool compare_not_flag) {
    if (node1->type == node2->type &&
        node1->addr == node2->addr &&
        node1->factor == node2->factor) {
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

void OpNode::ReplaceNodeWithLelfChild(OpNode* node, bool retain_addr/*= false*/) {
    OpNode*            to_free = node->left;
    int                type = node->type;
    unsigned long long addr = node->addr;
    unsigned long long value = node->value;
    int                not_flag = node->not_flag ^ node->left->not_flag;
    double             factor = node->factor * node->left->factor;
    *node = *(node->left);
    if (retain_addr) {
        node->type = type;
        node->addr = addr;
        node->value = value;
    }
    node->not_flag = not_flag;
    node->factor = factor;
    if (to_free) {
        to_free->left = nullptr;
        to_free->right = nullptr;
        delete to_free;
    }
}

const char* OpNode::GetTypeName(int type) {
    switch (type) {
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


class ArithmeticForest : public IArithmeticForest {
public:
    virtual ~ArithmeticForest(); // deconstructor
    void Clear(); // clear the forest
    std::vector<OpNode*>& GetForest(); // get the forest
    // get the trees whose root values are the parameter result
    bool GetForestByResult(std::vector<OpNode*>& result_forest, unsigned long long result);
    // add a one register operation {push, pop} are not one register operations, for they involves memory I/O.
    bool AddNode(
        unsigned long long ins_addr,
        int                op,
        unsigned long long reg_addr,
        unsigned long long reg_value);
    // add a two register operation including {push, pop}
    bool AddNode(
        unsigned long long ins_addr,
        int                op,
        int                des_type,
        unsigned long long des_addr,
        unsigned long long des_value,
        int                src_type,
        unsigned long long src_addr,
        unsigned long long src_value);
    // delete a tree by node, return true if the tree to delete is found
    bool DeleteTree(OpNode* node);
    // set node factor
    bool SetNodeFactor(unsigned long long reg, double factor);
    // do reduction to the forest
    void Reduce();
    // do reduction to a tree or tree node
    void Reduce(OpNode* node);
    // do reduction by type
    void ReduceByType(bool retain, int type);
    // do reduction with according to a number filter
    void ReduceByNumberFilter(int type, INumberFilter* filter);
    // reduce by depth, root is of depth 0
    void ReduceByDepth(int depth);
    // print the forest
    void Print();
protected:
    // add a unitary operation node whose des and src are the same register, like not or neg
    bool AddNodeInternal(
        unsigned long long ins_addr,
        int                op,
        unsigned long long reg_addr,
        unsigned long long reg_value);
    // add a unitary operation node whose des and src may be different, like mov
    bool AddNodeInternal(
        unsigned long long ins_addr,
        int                op,
        int                des_type,
        unsigned long long des_addr,
        int                src_type,
        unsigned long long src_addr,
        unsigned long long src_value);
    // add a binary operation node, like add or and
    bool AddNodeInternal(
        unsigned long long ins_addr,
        int                op,
        int                des_type,
        unsigned long long des_addr,
        int                src1_type,
        unsigned long long src1_addr,
        unsigned long long src1_value,
        int                src2_type,
        unsigned long long src2_addr,
        unsigned long long src2_value);
    // check if the node will be added as an immediate value
    bool CheckIsImmediateNode(int op, int des_type, unsigned long long des_addr,
        int src_type, unsigned long long src_addr, unsigned long long src_value);
    // check if the node will be added as an immediate value for binary operation
    bool CheckIsFakeBinaryOperation(int op, int des_type, unsigned long long des_addr,
        int src_type, unsigned long long src_addr, unsigned long long src_value, int* new_op);
    // find the tree of which the root is addr
    OpNode* FindAddr(int type, unsigned long long addr, bool copy);
    // when addr is overwritten, the tree that has root address value equal to addr is outdated.
    void UpdateAddr(int type, unsigned long long addr); // remove all trees that match the params
    // remove all trees that has a smaller serial than the serial param and match the following params
    void UpdateAddr(unsigned long long serial, int type, unsigned long long addr);
protected:
    std::vector<OpNode*> forest;
};

ArithmeticForest::~ArithmeticForest() {
    this->Clear();
}

void ArithmeticForest::Clear() {
    for (auto i = forest.begin(); i != forest.end(); i++) {
        delete (*i);
        (*i) = nullptr;
    }
    this->forest.clear();
}

std::vector<OpNode*>& ArithmeticForest::GetForest() {
    return forest;
}

// get the trees whose root values are the parameter result
bool ArithmeticForest::GetForestByResult(std::vector<OpNode*>& result_forest, unsigned long long result) {
    for (auto i = forest.begin(); i != forest.end(); i++) {
        if ((*i)->value == result || ((*i)->not_flag && (*i)->value == ~result)) {
            try {
                result_forest.push_back((*i)->DeepCopy());
            }
            catch (...) {
                result_forest.clear();
                return false;
            }
        }
    }
    return true;
}

// add a one register operation {push, pop} are not one register operations, for they involves memory I/O.
bool ArithmeticForest::AddNode(
    unsigned long long ins_addr,
    int                op,
    unsigned long long reg_addr,
    unsigned long long reg_value) {
    if (op == ZYDIS_MNEMONIC_PUSH) { // push
        throw;
        return false;
    }
    else if (op == ZYDIS_MNEMONIC_POP) { // pop
        throw;
        return false;
    }
    else if (op == ZYDIS_MNEMONIC_INC) { // inc
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
    unsigned long long ins_addr,
    int                op,
    int                des_type,
    unsigned long long des_addr,
    unsigned long long des_value,
    int                src_type,
    unsigned long long src_addr,
    unsigned long long src_value) {
    // check if the subtree is overwritten by immediate value equivalents.
    if (CheckIsImmediateNode(op, des_type, des_addr,
        src_type, src_addr, src_value)) {
        this->UpdateAddr(des_type, des_addr);
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

// set node factor
bool ArithmeticForest::SetNodeFactor(unsigned long long reg, double factor) {
    // look up addr in existing trees
    OpNode* left = this->FindAddr(ZYDIS_OPERAND_TYPE_REGISTER, reg, false);
    if (left) { // the operation must be on existing trees
        left->factor = left->factor * factor; // use real-time value
        return true;
    }
    return false;
}

// delete a tree by node, return true if the tree to delete is found
bool ArithmeticForest::DeleteTree(OpNode* node) {
    bool found = false;
    for (auto i = forest.begin(); i != forest.end(); i++) {
        if ((*i) == node) {
            delete* i;
            *i = nullptr;
            forest.erase(i);
            found = true;
            break;
        }
    }
    if (!found) {
        for (auto i = forest.begin(); i != forest.end(); i++) {
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

bool ArithmeticForest::AddNodeInternal(
    unsigned long long ins_addr,
    int                op,
    unsigned long long reg_addr,
    unsigned long long reg_value) {
    OpNode* node = new(std::nothrow)OpNode(ZYDIS_OPERAND_TYPE_REGISTER, reg_addr);
    if (node == nullptr)
        return false;
    node->ins_addr;
    bool ret = false;
    // look up addr in existing trees
    OpNode* left = this->FindAddr(ZYDIS_OPERAND_TYPE_REGISTER, reg_addr, true);
    if (left) { // the operation must be on existing trees
        left->value = reg_value; // use real-time value
        node->AddOp(op, left); // update the existing tree
        // add new tree to the forest
        try {
            this->forest.push_back(node);
            ret = true;
        }
        catch (...) {
            delete left;
            delete node;
            ret = false;
        }
        // some trees are outdated (desitination overwritten)
        this->UpdateAddr(node->serial, ZYDIS_OPERAND_TYPE_REGISTER, reg_addr);
    }
    else { // // junk instruction
        delete node;
        node = nullptr;
        ret = true;
    }
    return ret;
}

bool ArithmeticForest::AddNodeInternal(
    unsigned long long ins_addr,
    int                op,
    int                des_type,
    unsigned long long des_addr,
    int                src_type,
    unsigned long long src_addr,
    unsigned long long src_value) {
    OpNode* node = new(std::nothrow)OpNode(des_type, des_addr);
    if (node == nullptr)
        return false;
    node->ins_addr = ins_addr;
    bool ret = false;
    // look up addr in existing trees
    OpNode* left = this->FindAddr(src_type, src_addr, true);
    if (left) { // the operation is on existing trees
        left->value = src_value;
        node->AddOp(op, left);
        try {
            this->forest.push_back(node);
            ret = true;
        }
        catch (...) {
            delete left; // allocated by deepcopy
            delete node;
            ret = false;
        }
    }
    else { // the operation is not on existing trees
        // allocate new left node
        int type = (src_type == ZYDIS_OPERAND_TYPE_REGISTER) ? ZYDIS_OPERAND_TYPE_IMMEDIATE : src_type;
        left = new(std::nothrow)OpNode(node->serial, type, src_addr, src_value);
        if (left == nullptr)
            return false;
        node->AddOp(op, left);
        try {
            this->forest.push_back(node);
            ret = true;
        }
        catch (...) {
            delete left;
            delete node;
            ret = false;
        }
    }
    // some trees are outdated (desitination overwritten)
    if (ret)
        this->UpdateAddr(node->serial, des_type, des_addr);
    return ret;
}

bool ArithmeticForest::AddNodeInternal(
    unsigned long long ins_addr,
    int                op,
    int                des_type,
    unsigned long long des_addr,
    int                src1_type,
    unsigned long long src1_addr,
    unsigned long long src1_value,
    int                src2_type,
    unsigned long long src2_addr,
    unsigned long long src2_value) {
    OpNode* node = new(std::nothrow)OpNode(des_type, des_addr);
    if (node == nullptr)
        return false;
    node->ins_addr = ins_addr;
    // look up addr in existing trees
    OpNode* left = this->FindAddr(src1_type, src1_addr, true);
    if (left == nullptr) { // the operation is not on existing trees
        // allocate new left node
        int type = (src1_type == ZYDIS_OPERAND_TYPE_REGISTER) ? ZYDIS_OPERAND_TYPE_IMMEDIATE : src1_type;
        left = new(std::nothrow)OpNode(node->serial, type, src1_addr, src1_value);
        if (left == nullptr)
            return false;
    }
    left->value = src1_value;
    // look up addr in existing trees
    OpNode* right = this->FindAddr(src2_type, src2_addr, true);
    if (right == nullptr) { // the operation is not on existing trees
        // allocate new left node
        int type = (src2_type == ZYDIS_OPERAND_TYPE_REGISTER) ? ZYDIS_OPERAND_TYPE_IMMEDIATE : src2_type;
        right = new(std::nothrow)OpNode(node->serial, type, src2_addr, src2_value);
        if (right == nullptr) {
            delete left; // allocated by deepcopy or local new
            return false;
        }
    }
    right->value = src2_value;
    node->Add2Op(op, left, right);
    // add new tree to the forest
    bool ret = false;
    try {
        this->forest.push_back(node);
        ret = true;
    }
    catch (...) {
        delete node;
        delete left; // allocated by deepcopy or local new
        delete right; // allocated by deepcopy or local new
        ret = false;
    }
    // some trees are outdated (desitination overwritten)
    if (ret)
        this->UpdateAddr(node->serial, des_type, des_addr);
    return ret;
}

bool ArithmeticForest::CheckIsImmediateNode(int op, int des_type, unsigned long long des_addr,
    int src_type, unsigned long long src_addr, unsigned long long src_value) {
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
        OpNode* des = this->FindAddr(des_type, des_addr, false);
        if (des == nullptr) {
            if (src_type == ZYDIS_OPERAND_TYPE_IMMEDIATE) { // // op reg1(non-root), imm
                return true;
            }
            OpNode* src = this->FindAddr(des_type, des_addr, false);
            if (src == nullptr) { // op reg1(non-root), reg2(non-root)
                return true;
            }
        }
    }
    return false;
}

bool ArithmeticForest::CheckIsFakeBinaryOperation(int op, int des_type, unsigned long long des_addr,
    int src_type, unsigned long long src_addr, unsigned long long src_value, int* new_op) {
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
OpNode* ArithmeticForest::FindAddr(int type, unsigned long long addr, bool copy) {
    for (auto i = forest.begin(); i != forest.end(); i++) {
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
void ArithmeticForest::UpdateAddr(int type, unsigned long long addr) {
    for (auto i = forest.begin(); i != forest.end();) {
        if ((*i)->type == type && (*i)->addr == addr)
            i = forest.erase(i);
        else
            i++;
    }
}

// when addr is overwritten, the tree that has root address value equal to addr is outdated.
    // remove all trees that has a smaller serial than the serial param and match the following params
void ArithmeticForest::UpdateAddr(unsigned long long serial, int type, unsigned long long addr) {
    for (auto i = forest.begin(); i != forest.end();) {
        if ((*i)->serial < serial && (*i)->type == type && (*i)->addr == addr)
            i = forest.erase(i);
        else
            i++;
    }
}

void ArithmeticForest::Reduce() {
    // reduce per tree
    for (auto i = forest.begin(); i != forest.end(); i++) {
        this->Reduce(*i);
    }
}

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
                i++;
        }
        else {
            if ((*i)->type == type)
                i = forest.erase(i);
            else
                i++;
        }
    }
}

// do reduction with according to a number filter
void ArithmeticForest::ReduceByNumberFilter(int type, INumberFilter* filter) {
    for (auto i = forest.begin(); i != forest.end();) {
        if ((*i)->type == type && filter->IsDropULL((*i)->addr))
            i = forest.erase(i);
        else
            i++;
    }
}

// reduce by depth, root is of depth 0
void ArithmeticForest::ReduceByDepth(int depth) {
    for (auto i = forest.begin(); i != forest.end();i ++) {
        (*i)->ReduceByDepth(depth);
    }
}

void ArithmeticForest::Print() {
    for (auto i = forest.begin(); i != forest.end(); i++) {
        (*i)->Print();
    }
}


// make an arithmetic forest
IArithmeticForest* MakeArithmeticForest() {
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
        char stack_mem[0x200] = { 0 };
        for (int i = 0; i < sizeof(stack_mem); i++) {
            stack_mem[i] = i;
        }
        IArithmeticForest& forest = *MakeArithmeticForest();
        if (&forest == nullptr)
            return;
        // mov rsp, 200h
        // ZYDIS_REGISTER_MAX_VALUE is 265, address above 0x200 won't cause conflicts
        unsigned long long rsp = 0x200;
        unsigned long long rax = 0;
        unsigned long long rcx = 0;
        unsigned long long rdx = 0;
        unsigned long long rbx = 0;
        // mov rax, [rsp - 8h] ; build tree only when loading memory
        // add rax, 10h
        // mov [rsp - 10h], rax
        forest.AddNode(0, ZYDIS_MNEMONIC_MOV, ZYDIS_OPERAND_TYPE_REGISTER, ZYDIS_REGISTER_RAX, 0,
            ZYDIS_OPERAND_TYPE_MEMORY, rsp - 0x8, stack_mem[rsp - 0x8]);
        rax = *(unsigned long long*)&stack_mem[rsp - 0x8];
        forest.AddNode(0, ZYDIS_MNEMONIC_ADD, ZYDIS_OPERAND_TYPE_REGISTER, ZYDIS_REGISTER_RAX, rax,
            ZYDIS_OPERAND_TYPE_IMMEDIATE, 0, 0x10);
        rax += 0x10;
        forest.AddNode(0, ZYDIS_MNEMONIC_MOV, ZYDIS_OPERAND_TYPE_MEMORY, rsp - 0x10, 0,
            ZYDIS_OPERAND_TYPE_REGISTER, ZYDIS_REGISTER_RAX, rax); // always prefer realtime values to internal calculations
        *(unsigned long long*)&stack_mem[rsp - 0x10] = rax; // we calculate rax also for this step
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
        rax = *(unsigned long long*)&stack_mem[rsp - 0x18];
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
        rcx = *(unsigned long long*)&stack_mem[rsp - 0x20];
        forest.AddNode(0, ZYDIS_MNEMONIC_ADD, ZYDIS_OPERAND_TYPE_REGISTER, ZYDIS_REGISTER_RAX, rax,
            ZYDIS_OPERAND_TYPE_REGISTER, ZYDIS_REGISTER_RCX, 0x1);
        rax += rcx;
        forest.AddNode(0, ZYDIS_MNEMONIC_NOT, ZYDIS_REGISTER_RAX, rax);
        rax = (unsigned long long)(0 - rax);
        forest.AddNode(0, ZYDIS_MNEMONIC_MOV, ZYDIS_OPERAND_TYPE_MEMORY, rsp - 0x28, 0,
            ZYDIS_OPERAND_TYPE_REGISTER, ZYDIS_REGISTER_RAX, rax);
        *(unsigned long long*)&stack_mem[rsp - 0x28] = rax;
        // mov rax, [rsp - 28h] ; build tree when loading memory
        // inc rax              ; it will be recorded as "add rax, 1"
        // mov rcx, [rsp - 30h] ; build tree when loading memory
        // add rax, rcx
        // not rax
        // mov [rsp - 38h], rax
        forest.AddNode(0, ZYDIS_MNEMONIC_MOV, ZYDIS_OPERAND_TYPE_REGISTER, ZYDIS_REGISTER_RAX, 0,
            ZYDIS_OPERAND_TYPE_MEMORY, rsp - 0x28, stack_mem[rsp - 0x28]);
        rax = *(unsigned long long*) & stack_mem[rsp - 0x28];
        forest.AddNode(0, ZYDIS_MNEMONIC_ADD, ZYDIS_OPERAND_TYPE_REGISTER, ZYDIS_REGISTER_RAX, rax,
            ZYDIS_OPERAND_TYPE_IMMEDIATE, 0, 0x1);
        rax += 0x1;
        forest.AddNode(0, ZYDIS_MNEMONIC_MOV, ZYDIS_OPERAND_TYPE_REGISTER, ZYDIS_REGISTER_RCX, 0,
            ZYDIS_OPERAND_TYPE_MEMORY, rsp - 0x30, stack_mem[rsp - 0x30]);
        rcx = *(unsigned long long*) & stack_mem[rsp - 0x30];
        forest.AddNode(0, ZYDIS_MNEMONIC_ADD, ZYDIS_OPERAND_TYPE_REGISTER, ZYDIS_REGISTER_RAX, rax,
            ZYDIS_OPERAND_TYPE_REGISTER, ZYDIS_REGISTER_RCX, 0x1);
        rax += rcx;
        forest.AddNode(0, ZYDIS_MNEMONIC_NOT, ZYDIS_REGISTER_RAX, rax);
        rax = (unsigned long long)(0 - rax);
        forest.AddNode(0, ZYDIS_MNEMONIC_MOV, ZYDIS_OPERAND_TYPE_MEMORY, rsp - 0x38, 0,
            ZYDIS_OPERAND_TYPE_REGISTER, ZYDIS_REGISTER_RAX, rax);
        *(unsigned long long*)& stack_mem[rsp - 0x38] = rax;
        // reduce the effectless nodes
        forest.Reduce();
        forest.Print();
        DestroyArithmeticForest(&forest);
    }
};
//static ArithmeticForestTest g_ArithmeticForestTest;
