#ifndef _DEBUG_H_
#define _DEBUG_H_

// initialize and uninitialize modules
bool TDbgInit();
void TDbgUninit();

// load config file
bool TDbgLoadConfig(const WCHAR* config_file_name);
// load config file and debug the target file in config
bool TDbgLoadConfigAndRun(const WCHAR* config_file_name);
// debug the app
bool TDbgDebugProcess(const WCHAR* app_name, WCHAR* cmd_line);
// set if do patch while analyzing. return old value
bool TDbgSetPatch(bool patch);
// set if save patch result after analyzing. return old value
bool TDbgSetSavePatch(bool save);

namespace tcr {
	// breakpoint callback return types
	enum TDBG_CALLBACK_RET {
		CONTINUE = 1,
		REPEAT = 2,
		ABORT = 3
	};
	// breakpoint callback return flags that can be combined with other values
	enum TDBG_CALLBACK_RET_FLAG {
		NOFLAG_MASK = 0x0f,
		ENTER_SINGLE_STEP = 0x10,
		EXIT_SINGLE_STEP = 0x20,
		REMOVE_BREAKPOINT = 0x100,
		ENABLE_BREAKPOINT = 0x200,
		DISABLE_BREAKPOINT = 0x400
	};
}

// callback when a breakpoint is hit
typedef int (__stdcall *TDbgBreakpointCallback)(unsigned char* addr, void* user_data);

// callback when single stepping.
// the bp_addr and user_data are the ones of the associated breakpoint.
// return true if the event is completely processed, then the default single step tracing callback won't be called
// return false if the event processing is not completed, then the default single step tracing callback will be called.
typedef bool (__stdcall *TDbgSingleStepTraceCallback)(
	unsigned char* addr,
	unsigned char* bp_addr,
	void*          bp_user_data);

// the addr is the relative address from the image base
bool TDbgAddBreakpoint(
	unsigned long long          addr,
	TDbgBreakpointCallback      callback,
	void*                       user_data,
	TDbgSingleStepTraceCallback trace_callback);

// delete breakpoint with addr as key
// the addr is an updated address, which is the real memory address
void TDbgDeleteBreakpoint(unsigned char* addr, void* user_data);

#endif // _DEBUG_H_