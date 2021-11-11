#include <stdio.h>
#include <Windows.h>
#include <imagehlp.h>

#pragma comment(lib, "Imagehlp.lib")

#define BUFFER_SIZE 1024

// http://bytepointer.com/resources/microsoft_pe_checksum_algo_distilled.htm -> DOC 

volatile int CheckCodeSection() {
    DWORD buffSize = BUFFER_SIZE;
    char* processName = (char*)calloc(BUFFER_SIZE, 1);
    if (processName != NULL){
        HANDLE processHandle = GetCurrentProcess();
        if (processHandle != NULL) {
            if (QueryFullProcessImageNameA(processHandle, 0, processName, &buffSize)) {
                DWORD HeaderCheckSum = 0;
                DWORD CheckSum = 0;

                //printf("[-] MapFileAndCheckSum:\n");
                if (MapFileAndCheckSumA(processName, &HeaderCheckSum, &CheckSum) == CHECKSUM_SUCCESS) {
                    printf("\tHeaderCheckSum: 0x%x\n", HeaderCheckSum);
                    printf("\tCheckSum: 0x%x\n", CheckSum);
                    free(processName);
                    CloseHandle(processHandle);
                    return HeaderCheckSum == CheckSum;
                } else
                    printf("[X] Error MapFileAndCheckSumA: %lu", GetLastError());
            } else 
                printf("[X] Error GetModuleBaseNameA : %lu", GetLastError());
            CloseHandle(processHandle);
        }
        free(processName);
    }
	return FALSE;
}

volatile int CheckCodeSectionOK() {
    printf("[i] CheckCodeSection OK\n");
    return TRUE;
}
volatile int CheckCodeSectionError() {
    printf("[i] CheckCodeSection Error\n");
    return FALSE;
}

volatile int OKmsg() {
    printf("[-] OK vvvvvvvvvvvvvvvvvvvvv\n");
    return TRUE;
}
volatile int ERRORmsg() {
    printf("[x] Error xxxxxxxxxxxxxxxxxxxxxxxxxx\n");
    return FALSE;
}

int main() {
    if (CheckCodeSection())
        CheckCodeSectionOK();
    else
        CheckCodeSectionError();

    int volatile test = rand() % 50;
    if (test < 50)
        OKmsg();
    else
        ERRORmsg();

    if (CheckCodeSection())
        CheckCodeSectionOK();
    else
        CheckCodeSectionError();
	system("pause");
	return FALSE;
}