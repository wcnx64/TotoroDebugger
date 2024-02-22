#ifndef _MEMORY_TRACER_H_
#define _MEMORY_TRACER_H_

#include <vector>

// memory item used by MemoryTracer
struct MemoryItem;

// mainly used by memory breakpoint
typedef int(__stdcall* MemoryCallback)(MemoryItem* mem, void* user_data);

// memory item used by MemoryTracer
// These are the basic structures containing only the common necessary members.
// The Layered Memory Tracing algorithm is implemented by
// using much more complicated structures that inherit these basic ones.
// The memory tracer is a fundamental infrastructure,
// so we can't assume too much about the data structures and relations.
typedef struct MemoryItem {
	// key: {addr, layer}
	unsigned long long addr; // memory address
	int                layer; // the layer of the memory
	unsigned long long ins_addr; // instruction address that accessed the memory address
	bool               enabled_callback; // whether the callback is enabled, debuggers switch callback states rather than removing / re-adding them
	MemoryCallback     callback; // callback, usually used by a breakpoint
	void*              callback_user_data; // transfer data to callback
} MemoryItem, *PMemoryItem;

// an infrastructure of memory tracing, supporting the Layered Memory Tracing algorithm
class IMemoryTracer {
public:
	virtual ~IMemoryTracer() {};
	// add layer
	virtual bool Add(int layer) = 0;
	// add memory
	virtual bool Add(
		unsigned long long addr,
		int                layer,
		bool               enable_callback,
		MemoryCallback     callback,
		void*              callback_user_data) = 0;
	// add memory
	virtual bool Add(
		unsigned long long addr,
		int                layer,
		bool               ins_addr) = 0;
	// delete layer
	virtual bool Delete(int layer) = 0;
	// delete memory in given layer
	virtual bool Delete(unsigned long long addr, int layer) = 0;
	// clear all
	virtual void Clear() = 0;
	// clear layer
	virtual void Clear(int layer) = 0;
	// modify
	// you can modify the item after get the pointer
	virtual PMemoryItem Get(unsigned long long addr, int layer) = 0;
	// enumerate layers - first
	virtual bool FirstLayer(int& layer) = 0;
	// enumerate layers - next
	virtual bool MextLayer(int& layer) = 0;
	// enumerate mems in the layer - first
	virtual PMemoryItem FirstMem(int layer) = 0;
	// enumerate mems in the layer - next
	virtual PMemoryItem NextMem(int layer) = 0;
	// get callback assocaited with addr
	// return (false, nullptr) if the addr is not registered or
	// it doesn't have a callback.
	virtual std::pair<bool, MemoryCallback> GetCallback(unsigned long long addr, int layer) = 0;
	// easy interface for callback, use Get for altering more things including callback address and user data
	virtual bool EnableCallback(unsigned long long addr, int layer) = 0;
	// easy interface for callback, use Get for altering more things including callback address and user data
	virtual bool DisableCallback(unsigned long long addr, int layer) = 0;
	// important for algorithms. associate memories to build data structures for algorithms
	// {des_addr, des_layer} must be an existing MemoryItem's address.
	// if {src_addr, src_layer} has been registered, the existing record is used and src_in_addr is ignored.
	// a new MemoryItem without callback will be built if {src_addr, src_layer} doesn't belong to an existing MemoryItem.
	virtual bool Associate(
		unsigned long long des_addr,
		int                des_layer,
		unsigned long long src_addr,
		int                src_layer,
		unsigned long long src_ins_addr) = 0;
	// print a layer
	virtual void Print(int layer, bool print_associates) = 0;
};

// make a memory tracer and return the interface
IMemoryTracer* CreateMemoryTracer();
// destroy the memory tracer made by CreateMemoryTracer
void DestoryMemoryTracer(IMemoryTracer* tracer);


// for MemoryBlockAnalyzer
typedef struct MemoryBlock {
	int                layer;
	unsigned long long start_addr;
	unsigned long long end_addr;
	int                addr_count;
	int                asoociated_to;
} MemoryBlock, *PMemoryBlock;

// for array access analysis
class IMemoryBlockAnalyzer {
public:
	virtual ~IMemoryBlockAnalyzer() {};
	// clear
	virtual void Clear() = 0;
	// feed data
	virtual void AnalyzeData(void* data, int argc, void* argv[]) = 0;
	// get memory blocks
	virtual std::vector<MemoryBlock> GetMemoryBlocks(int layer) = 0;
	// print memory blocks
	virtual void Print() = 0;
};

// make a memory block analyzer and return the interface
IMemoryBlockAnalyzer* CreateMemoryBlockAnalyzer();
// destroy the memory block analyzer made by CreateMemoryBlockTracer
void DestoryMemoryBlockAnalyzer(IMemoryBlockAnalyzer* analyzer);

#endif // _MEMORY_TRACER_H_