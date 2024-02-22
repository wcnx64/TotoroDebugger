#include "vm.h"
#define ZYDIS_STATIC_BUILD
extern "C" {
#include "zydis/Zydis.h"
}

// print readable assembly code
void tvm::Ins::Print() {
	ZydisDisassembledInstruction readable_ins;
	ZyanStatus ZStatus = ZydisDisassembleIntel(
		ZYDIS_MACHINE_MODE_LONG_64,
		this->addr,
		this->code,
		this->code_len,
		&readable_ins);
	if (ZYAN_SUCCESS(ZStatus)) {
		printf("%s", readable_ins.text);
	}
}


///
/// VmIns
///

tvm::VmIns::VmIns() : index(0), deleted(false), loop(false) {
}

tvm::VmIns::~VmIns() {
	this->Reset();
}

// deep copy
tvm::VmIns* tvm::VmIns::DeepCopy() {
	// allocate memory
	tvm::VmIns* vm_ins = new(std::nothrow) tvm::VmIns();
	if (vm_ins == nullptr)
		return nullptr;
	// deep copy
	this->DeepCopy(vm_ins);
	return vm_ins;
}

// deep copy
bool tvm::VmIns::DeepCopy(tvm::VmIns* vm_ins) {
	// copy members except for vectors
	memcpy(vm_ins, this, sizeof(*this) -
		sizeof(this->sequence) - sizeof(this->blocks) - sizeof(this->trees));
	// copy ins sequence
	for (auto i = this->sequence.begin(); i != this->sequence.end(); ++i)
		vm_ins->sequence.push_back(*i);
	// deep copy blocks
	bool success = true;
	uint64_t new_block_index = 0;
	for (auto i = this->blocks.begin(); i != this->blocks.end(); ++i) {
		vm_ins->blocks.push_back(*i);
		// allocate and copy "code"
		if ((*i)->code && (*i)->length > 0) {
			uint8_t* code_mem = new(std::nothrow) uint8_t[(*i)->length];
			if (code_mem == nullptr) {
				// allocation failed
				success = false;
				break;
			}
			vm_ins->blocks[new_block_index]->code = code_mem;
			memcpy(code_mem, (*i)->code, (*i)->length);
		}
	}
	if (!success) {
		// rollback transaction
		vm_ins->Reset();
		memset(vm_ins, 0, sizeof(*this) -
			sizeof(this->sequence) - sizeof(this->blocks) - sizeof(this->trees));
	}
	return success;
}

// reset
void tvm::VmIns::Reset() {
	this->sequence.clear();
	this->ResetBlocks();
}

// reset blocks
void tvm::VmIns::ResetBlocks() {
	for (auto i = blocks.begin(); i != blocks.end(); ++i) {
		if ((*i) && (*i)->code) {
			delete (*i)->code;
			(*i)->code = nullptr;
		}
	}
	this->blocks.clear();
}

// add assembly instruction to the sequence
void tvm::VmIns::AddIns(
	uint64_t addr,         // instruction address
	uint32_t flag,         // combination of INS_FLAG
	uint64_t des_mem_addr, // destination memory address, 0 for unset
	uint64_t src_mem_addr, // src memory address, 0 for unset
	uint8_t* code,         // machine code of instructiion
	uint32_t code_len      // length of instruction
) {
	// build assembly instruction record
	tvm::Ins ins;
	ins.addr = addr;
	ins.flag = flag;
	ins.des_mem_addr = des_mem_addr;
	ins.src_mem_addr = src_mem_addr;
	ins.code_len = (code_len > sizeof(ins.code)) ? sizeof(ins.code) : code_len;
	memcpy(ins.code, code, ins.code_len);
	// add assembly instruction to the sequence
	this->sequence.push_back(ins);
	if (this->sequence.size() > 2) {
		// update control flow
		if ((flag & tvm::INS_FLAG_CONTROL_FLOW) && (flag && tvm::INS_FLAG_CONDITIONAL)) { // conditional jmp
			this->sequence.rbegin()->flag |= tvm::INS_FLAG_CONTROL_FLOW;
		}
		else if ((flag & tvm::INS_FLAG_CONTROL_FLOW) && (flag && tvm::INS_FLAG_RET)) { // ret
			for (auto i = sequence.rbegin(); i != sequence.rend(); ++i) {
				if (i->flag & tvm::INS_FLAG_PUSH) {
					this->sequence.rbegin()->flag |= tvm::INS_FLAG_CONTROL_FLOW;
					break;
				}
			}
		}
	}
}

// generate ins blocks
bool tvm::VmIns::GenerateBlocks() {
	if (this->sequence.size() == 0)
		return false;
	tvm::PInsBlock block = new(std::nothrow) InsBlock();
	if (block == nullptr)
		return false;
	// the first block
	block->addr = this->sequence[0].addr;
	block->length = this->sequence[0].code_len;
	block->ins_count = 1;
	// grow the block or generate other blocks
	bool success = true;
	auto prev = sequence.begin();
	if (sequence.size() >= 2) {
		for (auto i = sequence.begin() + 1; i != sequence.end(); ++i) {
			prev = i - 1;
			if (prev->addr + prev->code_len == i->addr) { // in the same block
				// grow the block
				block->length += i->code_len;
				block->ins_count++;
			}
			else { // a new block
				// register the existing block
				this->blocks.push_back(block);
				// start a new block
				block = new(std::nothrow) InsBlock();
				if (block == nullptr) {
					success = false;
					break;
				}
				block->addr = i->addr;
				block->length = i->code_len;
				block->ins_index = (uint32_t)(i - this->sequence.begin());
				block->ins_count = 1;
			}
		}
	}
	if (success) {
		// the last block
		this->blocks.push_back(block);
	}
	else {
		this->ResetBlocks(); // rollback
	}
	return success;
}

// get an ins block that meets the given requirements
tvm::PInsBlock tvm::VmIns::GetBlock(uint32_t start_index, uint32_t min_length) {
	for (auto i = blocks.begin(); i != blocks.end(); ++i) {
		if ((*i)->ins_index >= start_index && (*i)->length >= min_length) {
			return *i;
		}
	}
	return nullptr;
}

// print
void tvm::VmIns::Print() {
	for (auto i = sequence.begin(); i != sequence.end(); ++i) {
		i->Print();
		putchar('\n');
	}
}


///
/// VmInsGroup
///

tvm::VmInsGroup::~VmInsGroup() {
	this->Reset();
}

// reset
void tvm::VmInsGroup::Reset() {
	this->sequence.clear();
}

// add deep copied vm instruction to the sequence
uint64_t tvm::VmInsGroup::AddVmIns(tvm::PVmIns vm_ins) {
	// check duplication
	for (auto i = sequence.begin(); i != sequence.end(); i++) {
		if ((*i)->sequence.size() == vm_ins->sequence.size() &&
			(*i)->sequence.size() > 0 &&
			(*i)->sequence[0].addr == vm_ins->sequence[0].addr) {
			// already registered
			// update
			this->sequence.erase(i);
		}
	}
	// add deep copied vm instruction
	auto vm_ins_to_add = vm_ins->DeepCopy();
	vm_ins_to_add->index = sequence.size();
	this->sequence.push_back(vm_ins_to_add);
	return vm_ins_to_add->index;
}

// find the VmIns that contain the Ins
bool tvm::VmInsGroup::FindVmInsByInsAddr(uint64_t addr, tvm::Position& pos) {
	bool ret = false;
	// traverse the sequence and blocks
	for (auto i = sequence.begin(); i != sequence.end(); ++i) {
		for (auto j = (*i)->blocks.begin(); j != (*i)->blocks.end(); ++j) {
			// if add is in [(*i)->addr, (*j)->addr + (*j)->length)
			if (addr >= (*j)->addr && addr < (*j)->addr + (*j)->length) {
				// The position is found. Set output parameter "pos"
				pos.addr = addr;
				pos.vm_ins_index = (*i)->index;
				pos.block_index = j - (*i)->blocks.begin();
				pos.ins_index = (*j)->ins_index;
				ret = true;
				break;
			}
		}
	}
	return ret;
}

// register a jump (jmp, call, ret, etc.) in the VmIns' relations
bool tvm::VmInsGroup::RegisterJmp(uint64_t from, uint64_t to) {
	// find the positions of the origin and destination
	Position from_pos = { 0 };
	Position to_pos = { 0 };
	bool ret = FindVmInsByInsAddr(from, from_pos);
	if (!ret) return false;
	ret = FindVmInsByInsAddr(from, to_pos);
	if (!ret) return false;
	// build jmp info
	tvm::JmpInfo jmp_info = { from_pos, to_pos };
	// register the jmp relation to the blocks of the origin and destination
	tvm::InsBlock* from_vm_ins =
		this->sequence[from_pos.vm_ins_index]->blocks[from_pos.block_index];
	from_vm_ins->out.push_back(jmp_info);
	tvm::InsBlock* to_vm_ins =
		this->sequence[to_pos.vm_ins_index]->blocks[to_pos.block_index];
	to_vm_ins->in.push_back(jmp_info);
	return true;
}

// return reduced rate
double tvm::VmInsGroup::GetReducedRate() {
	return 0;
}
