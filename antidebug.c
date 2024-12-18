#include <Windows.h>
#include <stdio.h>

#include "Structs.h"
#include "antidebug.h"

#define FLG_HEAP_ENABLE_TAIL_CHECK   0x10
#define FLG_HEAP_ENABLE_FREE_CHECK   0x20
#define FLG_HEAP_VALIDATE_PARAMETERS 0x40

BOOL IsDebuggerPresent3() {

#ifdef _WIN64
	PPEB					pPeb = (PEB*)(__readgsqword(0x60));
#elif _WIN32
	PPEB					pPeb = (PEB*)(__readfsdword(0x30));
#endif

	if (pPeb->NtGlobalFlag & (FLG_HEAP_ENABLE_TAIL_CHECK | FLG_HEAP_ENABLE_FREE_CHECK | FLG_HEAP_VALIDATE_PARAMETERS))
		return TRUE;

	return FALSE;
}

typedef NTSTATUS(WINAPI* fnNtQueryInformationProcess)(
	HANDLE           ProcessHandle,
	PROCESSINFOCLASS ProcessInformationClass,
	PVOID            ProcessInformation,
	ULONG            ProcessInformationLength,
	PULONG           ReturnLength
	);


BOOL NtQIPDebuggerCheck() {

	NTSTATUS						STATUS = NULL;
	fnNtQueryInformationProcess		pNtQueryInformationProcess = NULL;
	DWORD64							dwIsDebuggerPresent = NULL;
	DWORD64							hProcessDebugObject = NULL;

	// getting NtQueryInformationProcess address
	pNtQueryInformationProcess = (fnNtQueryInformationProcess)GetProcAddress(GetModuleHandle(TEXT("NTDLL.DLL")), "NtQueryInformationProcess");
	if (pNtQueryInformationProcess == NULL) {
		printf("\n\t[!] GetProcAddress Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// calling NtQueryInformationProcess with the 'ProcessDebugPort' flag
	STATUS = pNtQueryInformationProcess(
		GetCurrentProcess(),
		ProcessDebugPort,
		&dwIsDebuggerPresent,
		sizeof(DWORD64),
		NULL
	);

	// if STATUS is not
	if (STATUS != 0x0) {
		printf("\n\t[!] NtQueryInformationProcess [1] Failed With Status : 0x%0.8X \n", STATUS);
		return FALSE;
	}

	// if NtQueryInformationProcess returned a non-zero value, the handle is valid, which means we are being debugged
	if (dwIsDebuggerPresent != NULL) {
		//printf("\n\t[i] NtQueryInformationProcess [1] - ProcessDebugPort Detected A Debugger \n");
		return TRUE;
	}

	// calling NtQueryInformationProcess with the 'ProcessDebugObjectHandle' flag
	STATUS = pNtQueryInformationProcess(
		GetCurrentProcess(),
		ProcessDebugObjectHandle,
		&hProcessDebugObject,
		sizeof(DWORD64),
		NULL
	);

	// if STATUS is not 0 and not 0xC0000353 (that is 'STATUS_PORT_NOT_SET')
	if (STATUS != 0x0 && STATUS != 0xC0000353) {
		printf("\n\t[!] NtQueryInformationProcess [2] Failed With Status : 0x%0.8X \n", STATUS);
		return FALSE;
	}

	// if NtQueryInformationProcess returned a non-zero value, the handle is valid, which means we are being debugged
	if (hProcessDebugObject != NULL) {
		//printf("\n\t[i] NtQueryInformationProcess [w] - hProcessDebugObject Detected A Debugger \n");
		return TRUE;
	}

	return FALSE;
}


BOOL HardwareBpCheck() {

	CONTEXT		Ctx = { .ContextFlags = CONTEXT_DEBUG_REGISTERS };

	if (!GetThreadContext(GetCurrentThread(), &Ctx)) {
		printf("\n\t[!] GetThreadContext Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// if one of these registers is not '0', then a hardware bp is installed
	if (Ctx.Dr0 != NULL || Ctx.Dr1 != NULL || Ctx.Dr2 != NULL || Ctx.Dr3 != NULL)
		return TRUE;

	return FALSE;
}

