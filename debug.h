#ifndef _BREAKPOINT_H_
#define _BREAKPOINT_H_

#define BREAKPOINT_CALLBACK_RETURN_CONTINUE                1
#define BREAKPOINT_CALLBACK_RETURN_SINGLE_STEP             2
#define BREAKPOINT_CALLBACK_RETURN_CONTINUE_NO_SINGLE_STEP 3
#define BREAKPOINT_CALLBACK_RETURN_REMOVE                  4
#define BREAKPOINT_CALLBACK_RETURN_ABORT                   0xf
// callback when a breakpoint is hit
typedef int (__stdcall *BreakpointCallback)(unsigned char* address, void* user_data);

// callback when single stepping
// the bp_address and user_data are the ones of the associated breakpoint
typedef void (__stdcall *SingleStepTraceCallback)(
	unsigned char* address,
	unsigned char* bp_address,
	void*          bp_user_data);

bool AddBreakpoint(unsigned char* address,
	BreakpointCallback callback,
	void* user_data,
	SingleStepTraceCallback trace_callback);
void DeleteBreakpoint(unsigned char* address, void* user_data);
void OnDebugEvent(unsigned char* address);

#endif // _BREAKPOINT_H_