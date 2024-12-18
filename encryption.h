#pragma once

typedef struct _AES {
	PBYTE   pPlainText;             // base address of the plain text data
	DWORD   dwPlainSize;            // size of the plain text data

	PBYTE   pCipherText;            // base address of the encrypted data
	DWORD   dwCipherSize;           // size of it (this can change from dwPlainSize in case there was padding)

	PBYTE   pKey;                   // the 32 byte key
	PBYTE   pIv;                    // the 16 byte iv
}AES, * PAES;



BOOL InstallAesDecryption(PAES pAes);

BOOL SimpleDecryption(IN PVOID pCipherTextData, IN DWORD sCipherTextSize, IN PBYTE pKey, IN PBYTE pIv, OUT PVOID* pPlainTextData, OUT DWORD* sPlainTextSize);
