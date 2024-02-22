#include "snapshot.h"

#include <vector>
#include <list>
#include <windows.h>

#define ZYDIS_STATIC_BUILD
extern "C" {
#include "zydis/Zydis.h"
}
#include "io.h"

/// <summary>
/// memory record for snapshot, always 8-byte aligned and 8 bytes long
/// </summary>
typedef struct SnapshotMem {
	uint64_t addr;  // memory address
	uint64_t value; // the value when the snapshot is taken
} SnapshotMem, * PSnapshotMem;

/// <summary>
/// data structure of the snapshot
/// </summary>
typedef class Snapshot {
public:
	int     id; // primary key
	HANDLE  process_handle;
	HANDLE  thread_handle;
	CONTEXT thread_ctx; // thread context, including values of all registers
	std::list<SnapshotMem> mems; // memories, sorted from low to high
public:
	Snapshot() : id(0), process_handle(nullptr), thread_handle(nullptr) {
		memset(&thread_ctx, 0, sizeof(thread_ctx));
	}
} Snapshot, * PSnapshot;

/// <summary>
/// implementation class for ISnapshotMgr
/// </summary>
class SnapshotMgr : public ISnapshotMgr {
public:
	/// <summary>
	/// constructor
	/// </summary>
	SnapshotMgr();
	/// <summary>
	/// destructor
	/// </summary>
	virtual ~SnapshotMgr();
	/// <summary>
	/// reset
	/// </summary>
	void Reset();
	/// <summary>
	/// take snapshot
	/// </summary>
	/// <param name="ins_addr">assembly instruction address</param>
	/// <returns>succeeded or not</returns>
	bool TakeSnapshot(int* id, uint64_t ins_addr);
	/// <summary>
	/// restore snapshot
	/// </summary>
	/// <param name="id">snapshot id, returned by TakeSnapshot method</param>
	/// <returns>succeeded or not</returns>
	bool Restore(int id);
	/// <summary>
	/// delete snapshot
	/// </summary>
	/// <param name="id">snapshot id, returned by TakeSnapshot method</param>
	/// <returns>succeeded or not</returns>
	bool DeleteSnapshot(int id);
	/// <summary>
	/// Add memory to the snapshot.
	/// If addr is 8-bytes aligned, [addr, addr + 8) is added to snapshot.
	/// If addr is not 8-bytes aligned, two adjacent 8 bytes aligned memories
	/// that contain the range [addr, addr + 8) range are added.
	/// It is designed to be called on write.
	/// </summary>
	/// <param name="id">snapshot id</param>
	/// <param name="addr">memory address</param>
	/// <returns>succeeded or not</returns>
	bool AddMem(int id, uint64_t addr);
	/// <summary>
	/// add 8-byte aligned memory to the snapshot
	/// </summary>
	/// <param name="snapshot">target snapshot</param>
	/// <param name="addr">memory address</param>
	/// <returns>succeeded or not</returns>
	bool AddAlignedMem(Snapshot& snapshot, uint64_t addr);
protected:
	std::vector<Snapshot> snapshots; // there won't be many snapshots,
	                                 // and it is reallocated by 128 in class constructor,
	                                 // so store Snapshot though it contains a vector
	int available_snapshot_id; // starts at 1
};

/// <summary>
/// constructor
/// </summary>
SnapshotMgr::SnapshotMgr() : available_snapshot_id(1) {
	snapshots.resize(128);
	snapshots.clear();
}

/// <summary>
/// destructor
/// </summary>
SnapshotMgr::~SnapshotMgr() {
	// reset
	Reset();
}

/// <summary>
/// reset
/// </summary>
void SnapshotMgr::Reset() {
	for (auto i = snapshots.begin(); i != snapshots.end(); ++i) {
		i->mems.clear();
	}
	snapshots.clear();
}

/// <summary>
/// take snapshot
/// </summary>
/// <param name="id">snapshot id, used for restoration</param>
/// <param name="ins_addr">assembly instruction address</param>
/// <returns>succeeded or not</returns>
bool SnapshotMgr::TakeSnapshot(int* id, uint64_t ins_addr) {
	Snapshot snapshot;
	// set handles
	snapshot.process_handle = IoGetProcessHandle();
	snapshot.thread_handle = IoGetThreadHandle();
	// take snapshot of the thread context, including registers
	snapshot.thread_ctx.ContextFlags = CONTEXT_ALL;
	bool ret = GetThreadContext(snapshot.thread_handle, &snapshot.thread_ctx);
	if (!ret)
		return false;
	snapshot.thread_ctx.Rip = ins_addr;
	// the memory records will be added afterwards on write
	// set snapshot id and increase the available one
	snapshot.id = (int)this->available_snapshot_id;
	this->available_snapshot_id++;
	// register the snapshot
	snapshots.push_back(snapshot);
	// add stack top to snapshot
	uint64_t rsp = IoReadRegister(ZYDIS_REGISTER_RSP);
	for (int i = 0; i < 0x100; i += 8) {
		AddMem(snapshot.id, rsp + i);
	}
	// set output parameters
	*id = snapshot.id;
	return true;
}

/// <summary>
/// restore snapshot
/// </summary>
/// <param name="id">snapshot id, returned by Take method</param>
/// <returns>succeeded or not</returns>
bool SnapshotMgr::Restore(int id) {
	// search for the snapshot
	PSnapshot snapshot = nullptr;
	for (auto i = snapshots.begin(); i != snapshots.end(); ++i)
		if (i->id == id) {
			snapshot = &*i;
			break;
		}
	if (snapshot == nullptr)
		return false;
	// restore the thread context, including registers
	snapshot->thread_ctx.ContextFlags = CONTEXT_ALL;
	BOOL ret = SetThreadContext(snapshot->thread_handle, &snapshot->thread_ctx);
	if (!ret)
		return false;
	// restore the memory
	for (auto i = snapshot->mems.begin(); i != snapshot->mems.end(); ++i) {
		IoWriteProcessMemory(i->addr, &i->value, sizeof(i->value));
	}
	return true;
}

/// <summary>
/// delete snapshot
/// </summary>
/// <param name="id">snapshot id, returned by TakeSnapshot method</param>
/// <returns>succeeded or not</returns>
bool SnapshotMgr::DeleteSnapshot(int id) {
	// search for the snapshot
	for (auto i = snapshots.begin(); i != snapshots.end(); ++i)
		if (i->id == id) {
			// delete the snapshot
			i->mems.clear();
			snapshots.erase(i);
			return true;
		}
	return false;
}

/// <summary>
/// Add memory to the snapshot.
/// If addr is 8-bytes aligned, [addr, addr + 8) is added to snapshot.
/// If addr is not 8-bytes aligned, two adjacent 8 bytes aligned memories
/// that contain the range [addr, addr + 8) range are added.
/// It is designed to be called on write.
/// </summary>
/// <param name="id">snapshot id</param>
/// <param name="addr">memory address</param>
/// <returns>succeeded or not</returns>
bool SnapshotMgr::AddMem(int id, uint64_t addr) {
	// search for the snapshot
	PSnapshot snapshot = nullptr;
	for (auto i = snapshots.begin(); i != snapshots.end(); ++i)
		if (i->id == id) {
			snapshot = &*i;
			break;
		}
	if (snapshot == nullptr)
		return false;
	// check alignment
	if (!(addr % 8)) { // 8-byte aligned
		AddAlignedMem(*snapshot, addr);
	}
	else {
		// align the memory address
		// and add two pieces of memory to cover the range
		uint64_t aligned_addr = addr / 8 * 8;
		AddAlignedMem(*snapshot, aligned_addr);
		AddAlignedMem(*snapshot, aligned_addr + 8);
	}
	return true;
}

/// <summary>
/// add 8-byte aligned memory to the snapshot
/// </summary>
/// <param name="snapshot">target snapshot</param>
/// <param name="addr">memory address</param>
/// <returns>succeeded or not</returns>
bool SnapshotMgr::AddAlignedMem(Snapshot& snapshot, uint64_t addr) {
	// build the memory record
	SnapshotMem mem;
	mem.addr = addr;
	bool ret = IoReadProcessMemory(mem.addr, &mem.value, sizeof(mem.value));
	if (!ret)
		return false;
	// find the right position to insert the new memory record
	for (auto i = snapshot.mems.begin(); i != snapshot.mems.end(); ++i) {
		if (i->addr < addr)
			continue;
		else if (i->addr == addr)
			return true; // already in snapshot
		// i->addr > addr
		// insert the new memory record
		snapshot.mems.insert(i, mem);
		return true;
	}
	// add the first memory record
	snapshot.mems.push_back(mem);
	return true;
}


/// <summary>
/// create a SnapshotMgr
/// </summary>
/// <returns>the interface of created SnapshotMgr</returns>
ISnapshotMgr* CreateSnapshotMgr() {
	return new(std::nothrow) SnapshotMgr();
}

/// <summary>
/// destroy a SnapshotMgr
/// </summary>
/// <param name="mgr">the interface of the SnapshotMgr to destroy</param>
void DestroySnapshotMgr(ISnapshotMgr* mgr) {
	if (mgr)
		delete mgr;
}
