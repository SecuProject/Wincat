#include <Windows.h>
#include <stdio.h>


void strToupper(char* name){
	for(char* s = name; *s; s++)
		*s = toupper((unsigned char)*s);
}

BOOL createFile(char* fileBuffer, DWORD fileSize, char* outputStrArg, char* nameStrArg) {
	FILE* pFile;
	if (fopen_s(&pFile, outputStrArg, "w") == 0) {
		size_t defVarSize = strlen(nameStrArg);
		char* defVar = (char*)calloc(defVarSize + 1, sizeof(char));
		if (defVar != NULL) {
			strcpy_s(defVar, defVarSize +1, nameStrArg);
			strToupper(defVar);
			fprintf(pFile, "#define FILE_SIZE_%s  %i\n\n", defVar, fileSize);
			free(defVar);
		}
		
		fprintf(pFile, "const char %s[] = {\n", nameStrArg);

		fprintf(pFile, "\t0x%.2X,", (unsigned char)fileBuffer[0]);
		for (DWORD i = 1; i < fileSize; i++) {
			if (i % 12 == 0)
				fprintf(pFile, "\n\t");
			fprintf(pFile, "0x%.2X,", (unsigned char)fileBuffer[i]);
		}
		fseek(pFile, -1, SEEK_CUR); // remove the last ','
		fprintf(pFile, "\n};");
		fclose(pFile);
	}else
		return FALSE;
	return TRUE;
}



int main(int argc, char* argv[]) {
	HANDLE hFile;
	DWORD fileSize;

	char* inputStrArg = NULL;
	char* outputStrArg = "payload.h";
	char* nameStrArg = "payload";


	if (argc < 3) {
		printf("[X] Error: Invalid argument number !\n");
		return TRUE;
	}

	for (int i = 1; i < argc -1; i++) {
		if (strcmp(argv[i], "-i") == 0 && argv[i + 1] != NULL) {
			inputStrArg = argv[i + 1];
		}
		if (strcmp(argv[i], "-o") == 0 && argv[i + 1] != NULL) {
			outputStrArg = argv[i + 1];
		}
		if (strcmp(argv[i], "-n") == 0 && argv[i + 1] != NULL) {
			nameStrArg = argv[i + 1];
		}
	}
	if (inputStrArg == NULL) {
		printf("[X] Error: inputStrArg Not set !\n");
		return TRUE;
	}
	hFile = CreateFileA(inputStrArg, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		printf("[X] Error: Unable to open the replacement executable. CreateFile failed with error %d\n", GetLastError());
		return TRUE;
	}

	fileSize = GetFileSize(hFile, NULL); // Get the size of the replacement executable
	if (fileSize == 0) {
		printf("[X] Error: invalid file size !\n");
		return TRUE;
	}
	
	char* fileBuffer = (char*)calloc(fileSize + 1, 1);
	if (fileBuffer != NULL) {
		DWORD dataRead = 0;
		//PIMAGE_DOS_HEADER pIDH;
		//PIMAGE_NT_HEADERS pINH;
			
		if (!ReadFile(hFile, fileBuffer, fileSize, &dataRead, NULL)){
			printf("[X] Error: Unable to read the replacement executable. ReadFile failed with error %d\n", GetLastError());
			free(fileBuffer);
			return TRUE;
		}
		/*
		pIDH = (PIMAGE_DOS_HEADER)fileBuffer;
		if (pIDH->e_magic != IMAGE_DOS_SIGNATURE) {
			printf("[X] Error: Invalid executable format.\n");
			free(fileBuffer);
			return TRUE;
		}
		// Get the address of the IMAGE_NT_HEADERS
		pINH = (PIMAGE_NT_HEADERS)((LPBYTE)fileBuffer + pIDH->e_lfanew);
		if (pINH->Signature != IMAGE_NT_SIGNATURE) {
			printf("[X] Error: NT signature mismatch !\n");
			free(fileBuffer);
			return TRUE;
		}
		*/
		if (createFile(fileBuffer, fileSize, outputStrArg, nameStrArg)) {
			printf("[+] File %s create successfully (Size: %i bytes).\n", outputStrArg, fileSize);
		}else {
			printf("[X] Error: creating the file %s !\n", outputStrArg);
			free(fileBuffer);
			return TRUE;
		}
		free(fileBuffer);
	}

	return FALSE;
}