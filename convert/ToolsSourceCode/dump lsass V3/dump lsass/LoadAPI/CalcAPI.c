#include <Windows.h>
#include <winternl.h>
#include <stdio.h>

void HashChr(DWORD* hash, unsigned char charData) {
	if (charData >= 'a') // toupper
		charData -= 0x20;
	*hash ^= charData;
	*hash *= 16777619;
}
DWORD __forceinline Fnv32(const void *input) {
	const unsigned char *data = (const unsigned char *)input;
	DWORD hash = 2166136261;

	while (*data != 0) {
		HashChr(&hash, *data);
		++data;
	}
	return hash;
}
DWORD __forceinline Fnv32Size(const void *input, UINT32 len) {
	const unsigned char *data = (const unsigned char *)input;
	DWORD hash = 2166136261;

	while ((UINT32)(data - (const unsigned char *)input) < len) {
		if (*data != 0) {
			HashChr(&hash, *data);
		}
		++data;
	}
	return hash;
}

PIMAGE_DATA_DIRECTORY get_data_dir(LPBYTE lpBaseAddress, WORD wIndex){
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)lpBaseAddress;
	PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)(lpBaseAddress + pDosHeader->e_lfanew);
	return &pNtHeaders->OptionalHeader.DataDirectory[wIndex];
}

LPBYTE find_module(PPEB pPeb, DWORD dwModuleHash){
	LIST_ENTRY *pListEntry = pPeb->Ldr->InMemoryOrderModuleList.Flink;
	do{
		LDR_DATA_TABLE_ENTRY *pLdrDataTableEntry = (PLDR_DATA_TABLE_ENTRY)pListEntry;
		UNICODE_STRING dllName = pLdrDataTableEntry->FullDllName;

		if (Fnv32Size(dllName.Buffer, dllName.Length) == dwModuleHash)
			return (LPBYTE)pLdrDataTableEntry->Reserved2[0];
		pListEntry = pListEntry->Flink;
	} while (pListEntry != pPeb->Ldr->InMemoryOrderModuleList.Flink);

	return 0;
}

FARPROC find_api(PPEB pPeb, DWORD dwModuleHash, DWORD dwProcHash){
	LPBYTE lpBaseAddress = find_module(pPeb, dwModuleHash);
	if (lpBaseAddress != NULL) {
		PIMAGE_DATA_DIRECTORY pDataDir = get_data_dir(lpBaseAddress, IMAGE_DIRECTORY_ENTRY_EXPORT);
		PIMAGE_EXPORT_DIRECTORY pExportDir = (PIMAGE_EXPORT_DIRECTORY)(lpBaseAddress + pDataDir->VirtualAddress);
		LPDWORD pNames = (LPDWORD)(lpBaseAddress + pExportDir->AddressOfNames);
		LPWORD pOrdinals = (LPWORD)(lpBaseAddress + pExportDir->AddressOfNameOrdinals);

		for (DWORD i = 0; i < pExportDir->NumberOfNames; ++i) {
			char *szName = (char *)lpBaseAddress + (DWORD_PTR)pNames[i];
			if (Fnv32(szName) == dwProcHash)
				return (FARPROC)(lpBaseAddress + ((DWORD *)(lpBaseAddress + pExportDir->AddressOfFunctions))[pOrdinals[i]]);
		}
	}

	return NULL;
}

PPEB get_peb() {
#ifdef _M_IX86 
	return (PPEB)__readfsdword(0x30);
#elif defined(_M_AMD64)
	return (PPEB)__readgsqword(0x60);
#endif
}