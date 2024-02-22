#include <algorithm>
#include "MemoryTracer.h"

// Layered Memory Item
typedef struct LMemItem : MemoryItem {
	std::vector<LMemItem*> associated;
	LMemItem(unsigned long long _addr) {
		this->addr = _addr;
		this->layer = 0;
		this->ins_addr = 0;
		this->enabled_callback = false;
		this->callback = nullptr;
		this->callback_user_data = nullptr;
	}
	~LMemItem() {}
	bool AddAssociated(LMemItem* mem) {
		// check duplication
		for (auto i = associated.begin(); i != associated.end(); i++)
			if (*i == mem)
				return true; // already associated
		try {
			// associated by new mem
			associated.push_back(mem);
		}
		catch (...) { return false; }
		return true;
	}
	void Print() {
		printf("0x%llx\n", addr);
	}
	void PrintAssociated() {
		printf("  [");
		for (auto i = associated.begin(); i != associated.end(); i++)
			printf("0x%llx, ", (*i)->addr);
		printf("]\n");
	}
} LMemItem, *PLMemItem;

// a layer of memories
typedef struct MemoryLayer {
	int                    layer;
	std::vector<PLMemItem> mems;
	int                    enum_mem_pos;
	MemoryLayer() : layer(0), enum_mem_pos(0) {}
} MemoryLayer, *PMemoryLayer;

class MemoryTracer : public IMemoryTracer {
public:
	MemoryTracer();
	virtual ~MemoryTracer();
	// add layer
	bool Add(int layer);
	// add memory
	bool Add(
		unsigned long long addr,
		int                layer,
		bool               enable_callback,
		MemoryCallback     callback,
		void*              callback_user_data);
	// add memory
	bool Add(
		unsigned long long addr,
		int                layer,
		bool               ins_addr);
	// delete layer
	bool Delete(int layer);
	// delete memory in given layer
	bool Delete(unsigned long long addr, int layer);
	// clear all
	void Clear();
	// clear layer
	void Clear(int layer);
	// modify
	// you can modify the item after get the pointer
	PMemoryItem Get(unsigned long long addr, int layer);
	// enumerate layers - first
	bool FirstLayer(int& layer);
	// enumerate layers - next
	bool MextLayer(int& layer);
	// enumerate mems in the layer - first
	PMemoryItem FirstMem(int layer);
	// enumerate mems in the layer - next
	PMemoryItem NextMem(int layer);
	// get callback assocaited with addr
	// return (false, nullptr) if the addr is not registered or
	// it doesn't have a callback.
	std::pair<bool, MemoryCallback> GetCallback(unsigned long long addr, int layer);
	// easy interface for callback, use Get for altering more things including callback address and user data
	bool EnableCallback(unsigned long long addr, int layer);
	// easy interface for callback, use Get for altering more things including callback address and user data
	bool DisableCallback(unsigned long long addr, int layer);
	// important for algorithms. associate memories to build data structures for algorithms
	// {des_addr, des_layer} must be an existing MemoryItem's address.
	// if {src_addr, src_layer} has been registered, the existing record is used and src_in_addr is ignored.
	// a new MemoryItem without callback will be built if {src_addr, src_layer} doesn't belong to an existing MemoryItem.
	bool Associate(
		unsigned long long des_addr,
		int                des_layer,
		unsigned long long src_addr,
		int                src_layer,
		unsigned long long src_ins_addr);
	// print a layer
	void Print(int layer, bool print_associates);

	// Non IMemoryTracer functions

	// add a new memory to layer, if layer is nullptr, add a new layer with the mem
	bool AddNewMem(PLMemItem mem, PMemoryLayer layer);
	// get layer
	PMemoryLayer GetLayer(int layer);
	// get memory in the given layer
	PLMemItem GetMem(unsigned long long addr, PMemoryLayer layer);
	// get memory
	PLMemItem GetMem(unsigned long long addr, int layer);
protected:
	// registered memories
	std::vector<PMemoryLayer> layers;
	// for enumeration
	int enum_layer_pos;
};

MemoryTracer::MemoryTracer() : enum_layer_pos(0) {
}

MemoryTracer::~MemoryTracer() {
	Clear();
}

// add layer
bool MemoryTracer::Add(int layer) {
	// avoid duplication
	if (GetLayer(layer)) {
		return false;
	}
	PMemoryLayer new_layer = new(std::nothrow) MemoryLayer();
	if (new_layer == nullptr) {
		return false;
	}
	new_layer->layer = layer;
	layers.push_back(new_layer);
	return true;
}

// add memory
bool MemoryTracer::Add(
	unsigned long long addr,
	int                layer,
	bool               enable_callback,
	MemoryCallback     callback,
	void* callback_user_data) {
	auto target_layer = GetLayer(layer);
	// avoid duplication
	if (target_layer) {
		if (GetMem(addr, target_layer))
			return false;
	}
	// add a new item in transaction
	PLMemItem mem = new(std::nothrow) LMemItem(addr);
	if (mem == nullptr)
		return false;
	mem->layer = layer;
	mem->enabled_callback = enable_callback;
	mem->callback = callback;
	return AddNewMem(mem, target_layer);
}

// add memory
bool MemoryTracer::Add(
	unsigned long long addr,
	int                layer,
	bool               ins_addr) {
	auto target_layer = GetLayer(layer);
	// avoid duplication
	if (target_layer) {
		if (GetMem(addr, target_layer))
			return false;
	}
	// add a new item in transaction
	PLMemItem mem = new(std::nothrow) LMemItem(addr);
	if (mem == nullptr)
		return false;
	mem->layer = layer;
	mem->ins_addr = ins_addr;
	return AddNewMem(mem, target_layer);
}

// delete layer
bool MemoryTracer::Delete(int layer) {
	for (auto i = layers.begin(); i != layers.end();) {
		if ((*i)->layer == layer) {
			(*i)->mems.clear();
			i = layers.erase(i);
			return true;
		}
		else { i++; }
	}
	return false;
}

// delete memory in given layer
bool MemoryTracer::Delete(unsigned long long addr, int layer) {
	auto target_layer = GetLayer(layer);
	if (target_layer) {
		for (auto i = target_layer->mems.begin(); i != target_layer->mems.end();) {
			if ((*i)->addr == addr) {
				i = target_layer->mems.erase(i);
				return true;
			}
			else { i++; }
		}
	}
	return false;
}

// clear all
void MemoryTracer::Clear() {
	for (auto i = layers.begin(); i != layers.end(); i++) {
		(*i)->mems.clear();
	}
	layers.clear();
}

// clear layer
void MemoryTracer::Clear(int layer) {
	for (auto i = layers.begin(); i != layers.end(); i++) {
		if ((*i)->layer == layer) {
			(*i)->mems.clear();
			break;
		}
	}
}

// modify
// you can modify the item after get the pointer
PMemoryItem MemoryTracer::Get(unsigned long long addr, int layer) {
	auto target_layer = GetLayer(layer);
	// avoid duplication
	if (target_layer) {
		return GetMem(addr, target_layer);
	}
	return nullptr;
}

// enumerate layers - first
bool MemoryTracer::FirstLayer(int& layer) {
	enum_layer_pos = 0;
	if (enum_layer_pos >= layers.size()) {
		return false;
	}
	layer = layers[enum_layer_pos]->layer;
	return true;
}

// enumerate layers - next
bool MemoryTracer::MextLayer(int& layer) {
	enum_layer_pos++;
	if (enum_layer_pos >= layers.size()) {
		return false;
	}
	layer = layers[enum_layer_pos]->layer;
	return true;
}

// enumerate mems in the layer - first
PMemoryItem MemoryTracer::FirstMem(int layer) {
	auto target_layer = GetLayer(layer);
	if (target_layer == nullptr)
		return nullptr;
	target_layer->enum_mem_pos = 0;
	if (target_layer->enum_mem_pos >= target_layer->mems.size()) {
		return nullptr;
	}
	return target_layer->mems[target_layer->enum_mem_pos];
}

// enumerate mems in the layer - next
PMemoryItem MemoryTracer::NextMem(int layer) {
	auto target_layer = GetLayer(layer);
	if (target_layer == nullptr)
		return nullptr;
	target_layer->enum_mem_pos++;
	if (target_layer->enum_mem_pos >= target_layer->mems.size()) {
		return nullptr;
	}
	return target_layer->mems[target_layer->enum_mem_pos];
}

// get callback assocaited with addr
// return (false, nullptr) if the addr is not registered or
// it doesn't have a callback.
std::pair<bool, MemoryCallback> MemoryTracer::GetCallback(unsigned long long addr, int layer) {
	auto mem = Get(addr, layer);
	if (mem == nullptr)
		return std::pair<bool, MemoryCallback>(false, nullptr);
	return std::pair<bool, MemoryCallback>(mem->enabled_callback, mem->callback);
}

// easy interface for callback, use Get for altering more things including callback address and user data
bool MemoryTracer::EnableCallback(unsigned long long addr, int layer) {
	auto mem = Get(addr, layer);
	if (mem == nullptr)
		return false;
	if (mem->callback == nullptr)
		return false;
	mem->enabled_callback = true;
	return true;
}

// easy interface for callback, use Get for altering more things including callback address and user data
bool MemoryTracer::DisableCallback(unsigned long long addr, int layer) {
	auto mem = Get(addr, layer);
	if (mem == nullptr)
		return false;
	if (mem->callback == nullptr)
		return false;
	mem->enabled_callback = false;
	return true;
}

// important for algorithms. associate memories to build data structures for algorithms
// {des_addr, des_layer} must be an existing MemoryItem's address.
// if {src_addr, src_layer} has been registered, the existing record is used and src_in_addr is ignored.
// a new MemoryItem without callback will be built if {src_addr, src_layer} doesn't belong to an existing MemoryItem.
bool MemoryTracer::Associate(
	unsigned long long des_addr,
	int                des_layer,
	unsigned long long src_addr,
	int                src_layer,
	unsigned long long src_ins_addr) {
	// get destination memory item. the des mem must already exist
	auto des_mem = GetMem(des_addr, des_layer);
	if (des_mem == nullptr)
		return false;
	do {
		// check if the source memory is new
		auto src_mem = GetMem(src_addr, src_layer);
		if (src_mem == nullptr)
			break;
		// associate existing src mem to des mem
		return des_mem->AddAssociated(src_mem);
	} while (false);
	// register new mem
	bool ret = Add(src_addr, src_layer, src_ins_addr);
	if (ret == false)
		return false;
	// get the registered one
	auto src_mem = GetMem(src_addr, src_layer);
	if (src_mem == nullptr)
		return false;
	// associate new src mem to des mem
	return des_mem->AddAssociated(src_mem);
}

// print a layer
void MemoryTracer::Print(int layer, bool print_associates) {
	auto layer_ptr = GetLayer(layer);
	if (layer_ptr == nullptr)
		return;
	for (auto i = layer_ptr->mems.begin(); i != layer_ptr->mems.end(); i++) {
		(*i)->Print();
		if (print_associates)
			(*i)->PrintAssociated();
	}
}

// non-IMemoryTracer functions

// add a new memory to layer, if layer is nullptr, add a new layer with the mem
bool MemoryTracer::AddNewMem(PLMemItem mem, PMemoryLayer layer) {
	// add a new item in transaction
	bool build_new_layer = false;
	// add a new layer
	if (layer == nullptr) {
		PMemoryLayer new_layer = new(std::nothrow) MemoryLayer();
		if (new_layer == nullptr)
			return false;
		new_layer->layer = mem->layer;
		layers.push_back(new_layer);
		build_new_layer = true;
		layer = new_layer;
	}
	// add a mem item to its layer
	layer->mems.push_back(mem);
	return true;
}

// get layer
PMemoryLayer MemoryTracer::GetLayer(int layer) {
	for (auto i = layers.begin(); i != layers.end(); i++) {
		if ((*i)->layer == layer) {
			return *i;
		}
	}
	return nullptr;
}

// get memory in the given layer
PLMemItem MemoryTracer::GetMem(unsigned long long addr, PMemoryLayer layer) {
	for (auto i = layer->mems.begin(); i != layer->mems.end(); i++) {
		if ((*i)->addr == addr) {
			return *i;
		}
	}
	return nullptr;
}

// get memory
PLMemItem MemoryTracer::GetMem(unsigned long long addr, int layer) {
	auto layer_ptr = GetLayer(layer);
	if (layer_ptr == nullptr)
		return nullptr;
	auto mem = GetMem(addr, layer_ptr);
	return mem;
}

// make a memory tracer and return the interface
IMemoryTracer* CreateMemoryTracer() {
	return new MemoryTracer();
}

// destroy the memory tracer made by CreateMemoryTracer
void DestoryMemoryTracer(IMemoryTracer* tracer) {
	if (tracer)
		delete tracer;
}

// for array access analysis
class MemoryBlockAnalyzer : public IMemoryBlockAnalyzer {
public:
	MemoryBlockAnalyzer();
	virtual ~MemoryBlockAnalyzer();
	// clear
	void Clear();
	// feed data
	void AnalyzeData(void* data, int argc, void* argv[]);
	// get memory blocks
	std::vector<MemoryBlock> GetMemoryBlocks(int layer);
	// print memory blocks
	void Print();
protected:
	std::vector<MemoryBlock> blocks;
	int distance_threshold; // threshold value included
	int item_number_threshold; // threshold value included
};

MemoryBlockAnalyzer::MemoryBlockAnalyzer() {
	this->distance_threshold = 16;
	this->item_number_threshold = 4;
}

MemoryBlockAnalyzer::~MemoryBlockAnalyzer() {
	Clear();
}

// clear
void MemoryBlockAnalyzer::Clear() {
	this->blocks.clear();
}

void MemoryBlockAnalyzer::AnalyzeData(void* data, int argc, void* argv[]) {
	if (argc >= 1)
		distance_threshold = (int)(unsigned long long)argv[0];
	if (argc >= 2)
		item_number_threshold = (int)(unsigned long long)argv[1];
	MemoryTracer* tracer = (MemoryTracer*)data;
	int layer = 1;
	while (true) {
		auto layer_ptr = tracer->GetLayer(layer);
		if (layer_ptr == nullptr)
			break;
		// sort
		std::sort(layer_ptr->mems.begin(), layer_ptr->mems.end(),
			[](PLMemItem left, PLMemItem right) {return left->addr < right->addr; });
		// look for memory blocks according to thresholds
		unsigned long long cur_start_addr = 0;
		int                cur_mem_count = 0;
		for (auto i = layer_ptr->mems.begin(); i != layer_ptr->mems.end() - 1; i++) {
			if (cur_mem_count == 0) // // no close mems are found
				cur_start_addr = (*i)->addr;
			// check distance
			if (((*i) + 1)->addr - (*i)->addr <= distance_threshold) {
				if (cur_mem_count == 0) // the first pair of the current potential block
					cur_mem_count = 2;
				else // the current potential block grows
					cur_mem_count++;
			}
			// check if it is the end of a block, as the distance is not within the threshold
			else if (cur_mem_count >= item_number_threshold) {
				// a new block is found
				MemoryBlock block;
				block.layer = layer;
				block.start_addr = cur_start_addr;
				block.end_addr = (*i)->addr;
				block.addr_count = cur_mem_count;
				block.asoociated_to = layer - 1;
				this->blocks.push_back(block);
				cur_mem_count = 0;
			}
			else {
				cur_mem_count = 0;
			}
		}
		// the right most block
		if (cur_mem_count >= item_number_threshold) {
			// a new block is found
			MemoryBlock block;
			block.layer = layer;
			block.start_addr = cur_start_addr;
			block.end_addr = (*(layer_ptr->mems.end() - 1))->addr;
			block.addr_count = cur_mem_count;
			block.asoociated_to = layer - 1;
			this->blocks.push_back(block);
		}
		// next layer
		layer++;
	}
}

// get memory blocks
std::vector<MemoryBlock> MemoryBlockAnalyzer::GetMemoryBlocks(int layer) {
	std::vector<MemoryBlock> blocks;
	for (auto i = blocks.begin(); i != blocks.end(); i++) {
		if (i->layer == layer) {
			try {
				blocks.push_back(*i);
			}
			catch (...) {}
		}
	}
	return blocks;
}

// print memory blocks
void MemoryBlockAnalyzer::Print() {
	for (auto i = blocks.begin(); i != blocks.end(); i++) {
		printf("[0x%llx, 0x%llx] #0x%lx  0x%lx -> 0x%lx\n",
			i->start_addr, i->end_addr, i->addr_count, i->layer, i->asoociated_to);
	}
}

// make a memory block analyzer and return the interface
IMemoryBlockAnalyzer* CreateMemoryBlockAnalyzer() {
	return new MemoryBlockAnalyzer();
}

// destroy the memory block analyzer made by CreateMemoryBlockTracer
void DestoryMemoryBlockAnalyzer(IMemoryBlockAnalyzer* analyzer) {
	if (analyzer)
		delete analyzer;
}
