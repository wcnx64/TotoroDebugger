#ifndef _SNAPSHOT_H_
#define _SNAPSHOT_H_

#include <stdint.h>

/// <summary>
/// interface class for snapshot
/// </summary>
class ISnapshotMgr {
public:
	/// <summary>
	/// destructor
	/// </summary>
	virtual ~ISnapshotMgr() {};
	/// <summary>
	/// reset
	/// </summary>
	virtual void Reset() = 0;
	/// <summary>
	/// take snapshot
	/// </summary>
	/// <param name="id">snapshot id</param>
	/// <param name="ins_addr">assembly instruction address</param>
	/// <returns>succeeded or not</returns>
	virtual bool TakeSnapshot(int* id, uint64_t ins_addr) = 0;
	/// <summary>
	/// restore snapshot
	/// </summary>
	/// <param name="id">snapshot id, returned by TakeSnapshot method</param>
	/// <returns>succeeded or not</returns>
	virtual bool Restore(int id) = 0;
	/// <summary>
	/// delete snapshot
	/// </summary>
	/// <param name="id">snapshot id, returned by TakeSnapshot method</param>
	/// <returns>succeeded or not</returns>
	virtual bool DeleteSnapshot(int id) = 0;
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
	virtual bool AddMem(int id, uint64_t addr) = 0;
};

/// <summary>
/// create a SnapshotMgr
/// </summary>
/// <returns>the interface of the SnapshotMgr</returns>
ISnapshotMgr* CreateSnapshotMgr();

/// <summary>
/// destroy a SnapshotMgr
/// </summary>
/// <param name="mgr">the interface of the SnapshotMgr</param>
void DestroySnapshotMgr(ISnapshotMgr* mgr);

#endif // _SNAPSHOT_H_