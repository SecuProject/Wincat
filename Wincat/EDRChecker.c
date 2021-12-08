#include <Windows.h>
#include <stdio.h>
#include <stdint.h>
#include <tlhelp32.h>

#include "Message.h"
#include "EDRNameHash.h"
#include "Tools.h"

uint32_t crc32(const char* buf, size_t len) {
	static uint32_t table[256];
	static int have_table = 0;
	const char* p, * q;
	uint32_t crc = 0;

	/* This check is not thread safe; there is no mutex. */
	if (have_table == 0) {
		/* Calculate CRC table. */
		for (int i = 0; i < 256; i++) {
			uint32_t rem = i;  /* remainder from polynomial division */
			for (int j = 0; j < 8; j++) {
				if (rem & 1) {
					rem >>= 1;
					rem ^= 0xedb88320;
				} else
					rem >>= 1;
			}
			table[i] = rem;
		}
		have_table = 1;
	}

	crc = ~crc;
	q = buf + len;
	for (p = buf; p < q; p++) {
		uint8_t octet = *p;  /* Cast to unsigned octet. */
		crc = (crc >> 8) ^ table[(crc & 0xff) ^ octet];
	}
	return ~crc;
}

BOOL EDRChecker() {
	HANDLE hProcessSnap;
	PROCESSENTRY32 pe32;


	hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcessSnap == INVALID_HANDLE_VALUE) {
		printMsg(STATUS_ERROR, LEVEL_DEFAULT, "ERROR: CreateToolhelp32Snapshot");
		return FALSE;
	}

	pe32.dwSize = sizeof(PROCESSENTRY32);
	if (!Process32First(hProcessSnap, &pe32)) {
		printMsg(STATUS_ERROR, LEVEL_DEFAULT, "ERROR: Process32First");
		CloseHandle(hProcessSnap);
		return FALSE;
	}

	do {
		for (UINT j = 0; j < sizeof(processNameHash) / sizeof(const uint32_t); j++) {
			char buffer[1024];
			size_t outputSize = strlen(pe32.szExeFile);

			ToLower(pe32.szExeFile, outputSize, buffer);
			if (crc32(buffer, outputSize) == processNameHash[j])
				printMsg(STATUS_WARNING, LEVEL_DEFAULT, "EDR Detected: %s (%i)\n", pe32.szExeFile, pe32.th32ProcessID);
		}
	} while (Process32Next(hProcessSnap, &pe32));

	CloseHandle(hProcessSnap);
	return TRUE;
}