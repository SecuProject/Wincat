//#include <Message.h>
#include <windows.h>
#include <stdio.h>
#include "MgDownload.h"
#include "Message.h"

#define IP_ADDRESS_SIZE 16

/*
- Detects compressed malware

	http://amtso.eicar.org/eicar.lzh		-> LZH Format
	http://amtso.eicar.org/eicar.zip
	http://amtso.eicar.org/eicar.zipx
	http://amtso.eicar.org/eicar.7z
	http://amtso.eicar.org/eicar.rar
	http://amtso.eicar.org/eicar.tgz
	http://amtso.eicar.org/eicar.ace
	http://amtso.eicar.org/eicar.cab
	http://amtso.eicar.org/eicar.exe		-> RAR-SFX format
	http://amtso.eicar.org/eicar_zip.exe    -> ZIP-SFX format
	http://amtso.eicar.org/eicar.jar

- Detects HTTPS malware

	https://secure.eicar.org/eicar.com
	https://secure.eicar.org/eicar.com.txt
	https://secure.eicar.org/eicar_com.zip
	https://secure.eicar.org/eicarcom2.zip


- Testing Web Reputation [TODO]

(Use a test client machine to access the following website twice.)

	http://wr21.winshipway.com
	http://ca06-3.winshipway.com
*/

BOOL CheckAccessDomain(const char* domainName) {
	char* ipAddress = (char*)malloc(IP_ADDRESS_SIZE);
	if (ipAddress != NULL) {

		InitMgDownload();
		if (GetIp(domainName, ipAddress)) {
			printf("\t[INFO]\tServer ip address: %s\n", ipAddress);
			free(ipAddress);
			CleanMgDownload();
			return TRUE;
		}
		CleanMgDownload();
		MsgError2("Fail to retive the server ip address ('%s')\n", domainName);
		free(ipAddress);
	}
	return FALSE;
}

BOOL TestCompressedMalware(char* dropPath) {
	const char domainName[] = "amtso.eicar.org";
	const char* urlPath[] = {
		//"/eicar.lzh",
		"/eicar.zip",
		"/eicar.zipx",
		"/eicar.7z",
		"/eicar.rar",
		"/eicar.tgz",
		"/eicar.ace",
		"/eicar.cab",
		"/eicar.exe",
		"/eicar_zip.exe",
		"/eicar.jar"
	};
	const int nbFiles = sizeof(urlPath) / sizeof(char*);

	printf("\n[-] Test Compressed Malware\n");

	if (!CheckAccessDomain(domainName))
		return FALSE;

	for (int i = 0; i < nbFiles; i++) {
		DWORD fileSize = 0;
		if (MainMgDownload(domainName, urlPath[i], dropPath, &fileSize, FALSE)) {
			char* filename = (char*)urlPath[i] + 1;
			size_t fileFullPathSize = strlen(dropPath) + strlen(filename) + 1 + 1;
			char* fileFullPath = (char*)malloc(fileFullPathSize);
			if (fileFullPath != NULL) {
				sprintf_s(fileFullPath, fileFullPathSize, "%s\\%s", dropPath, urlPath[i] + 1);
				if (IsFileExist(fileFullPath)) {
					if (TestReadFile(fileFullPath))
						MsgPass2("%s - File size: %ld\n", filename, fileSize);
					else
						MsgBlock2("%s - File was remove by the EDR (2)!\n", filename);
				}
				else
					MsgBlock2("%s - File was remove by the EDR (1)!\n", filename);
				free(fileFullPath);
			}
		}
	}
	return TRUE;
}
BOOL TestHttpsMalware(char* dropPath) {
	const char domainName[] = "secure.eicar.org";
	const char* urlPath[] = {
		"/eicar.com",
		"/eicar.com.txt",
		"/eicar_com.zip",
		"/eicarcom2.zip"
	};
	const int nbFiles = sizeof(urlPath) / sizeof(char*);
	printf("\n[-] Test HTTPS Malware\n");
	if (!CheckAccessDomain(domainName))
		return FALSE;
	for (int i = 0; i < nbFiles; i++) {
		DWORD fileSize = 0;
		if (MainMgDownload(domainName, urlPath[i], dropPath, &fileSize, TRUE)) {
			char* filename = (char*)urlPath[i] + 1;
			size_t fileFullPathSize = strlen(dropPath) + strlen(filename) + 1 + 1;
			char* fileFullPath = (char*)malloc(fileFullPathSize);
			if (fileFullPath != NULL) {
				sprintf_s(fileFullPath, fileFullPathSize, "%s\\%s", dropPath, urlPath[i] + 1);
				if (IsFileExist(fileFullPath)) {
					if (TestReadFile(fileFullPath))
						MsgPass2("%s - File size: %ld\n", filename, fileSize);
					else
						MsgBlock2("%s - File was remove by the EDR (2)!\n", filename);
				}
				else
					MsgBlock2("%s - File was remove by the EDR (1)!\n", filename);
				free(fileFullPath);
			}
			Sleep(100);
		}
	}
	return TRUE;
}

int main() {
	printf("-------------------------------------------------\n");
	printf("------------------- HIDS test -------------------\n");
	printf("-------------------------------------------------\n\n");

	char* tempPath = (char*)malloc(MAX_PATH+1);
	if (tempPath != NULL) {
		if (GetTempPathA(MAX_PATH + 1, tempPath) > 0) {

			TestCompressedMalware(tempPath);
			TestHttpsMalware(tempPath);

		}else
			MsgError("Fail to get the temp path: %ld\n", GetLastError());
		free(tempPath);
	}else
		MsgError("Fail to Malloc !\n");

	//system("pause");
	return FALSE;
}