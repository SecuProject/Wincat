#include <Windows.h>
#include <stdio.h>
#include <compressapi.h>

#pragma comment(lib, "Cabinet.lib")

// https://docs.microsoft.com/en-us/windows/win32/cmpapi/using-the-compression-api-in-buffer-mode
int CompressFile(LPCWSTR InputFilePath, LPCWSTR OutputFilePath) {
    COMPRESSOR_HANDLE Compressor = NULL;
    PBYTE CompressedBuffer = NULL;
    PBYTE InputBuffer = NULL;
    HANDLE InputFile = INVALID_HANDLE_VALUE;
    HANDLE CompressedFile = INVALID_HANDLE_VALUE;
    BOOL DeleteTargetFile = TRUE;
    BOOL Success;
    SIZE_T CompressedDataSize, CompressedBufferSize;
    DWORD InputFileSize, ByteRead, ByteWritten;
    LARGE_INTEGER FileSize;
    BOOL retValue = FALSE;
   
    //  Open input file for reading, existing file only.
    InputFile = CreateFileW(InputFilePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (InputFile == INVALID_HANDLE_VALUE) {
        printf("[X] Cannot open \t%ws\n", InputFilePath);
        retValue = TRUE;
        goto done;
    }

    //  Get input file size.
    Success = GetFileSizeEx(InputFile, &FileSize);
    if ((!Success) || (FileSize.QuadPart > 0xFFFFFFFF)) {
        printf("[X] Cannot get input file size or file is larger than 4GB.\n");
        retValue = TRUE;
        goto done;
    }
    InputFileSize = FileSize.LowPart;

    //  Allocate memory for file content.
    InputBuffer = (PBYTE)malloc(InputFileSize);
    if (!InputBuffer) {
        printf("[X] Cannot allocate memory for uncompressed buffer.\n");
        retValue = TRUE;
        goto done;
    }

    //  Read input file.
    Success = ReadFile(InputFile, InputBuffer, InputFileSize, &ByteRead, NULL);
    if ((!Success) || (ByteRead != InputFileSize)) {
        printf("[X] Cannot read from \t%ws\n", InputFilePath);
        retValue = TRUE;
        goto done;
    }

    //  Open an empty file for writing, if exist, overwrite it.
    CompressedFile = CreateFileW(OutputFilePath, GENERIC_WRITE | DELETE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

    if (CompressedFile == INVALID_HANDLE_VALUE) {
        printf("[X] Cannot create file \t%ws\n", OutputFilePath);
        retValue = TRUE;
        goto done;
    }

    //  Create an XpressHuff compressor.
    Success = CreateCompressor(
        COMPRESS_ALGORITHM_XPRESS_HUFF, //  Compression Algorithm
        NULL,                           //  Optional allocation routine
        &Compressor);                   //  Handle

    if (!Success) {
        printf("[X] Cannot create a compressor %lu.\n", GetLastError());
        retValue = TRUE;
        goto done;
    }

    //  Query compressed buffer size.
    Success = Compress(Compressor, InputBuffer, InputFileSize, NULL, 0, &CompressedBufferSize);

    //  Allocate memory for compressed buffer.
    if (!Success) {
        DWORD ErrorCode = GetLastError();

        if (ErrorCode != ERROR_INSUFFICIENT_BUFFER) {
            printf("[X] Cannot compress data: %lu.\n", ErrorCode);
            retValue = TRUE;
            goto done;
        }

        CompressedBuffer = (PBYTE)malloc(CompressedBufferSize);
        if (!CompressedBuffer) {
            printf("[X] Cannot allocate memory for compressed buffer.\n");
            retValue = TRUE;
            goto done;
        }
    }

    //  Call Compress() again to do real compression and output the compressed
    //  data to CompressedBuffer.
    Success = Compress(Compressor, InputBuffer, InputFileSize, CompressedBuffer, CompressedBufferSize, &CompressedDataSize);

    if (!Success) {
        printf("[X] Cannot compress data: %lu\n", GetLastError());
        goto done;
    }

    //  Write compressed data to output file.
    Success = WriteFile(CompressedFile, CompressedBuffer, CompressedDataSize, &ByteWritten, NULL);

    if ((ByteWritten != CompressedDataSize) || (!Success)) {
        printf("[X] Cannot write compressed data to file: %lu.\n", GetLastError());
        retValue = TRUE;
        goto done;
    }
    float compressionRatio = (float)CompressedDataSize / (float)InputFileSize;
    printf("[i] Compression ratio: %.3f%%\n", (1 - compressionRatio)*100);
    DeleteTargetFile = FALSE;
done:
    if (Compressor != NULL)
        CloseCompressor(Compressor);
    if (CompressedBuffer)
        free(CompressedBuffer);
    if (InputBuffer)
        free(InputBuffer);
    if (InputFile != INVALID_HANDLE_VALUE)
        CloseHandle(InputFile);
    if (CompressedFile != INVALID_HANDLE_VALUE) {
        //  Compression fails, delete the compressed file.
        if (DeleteTargetFile) {
            FILE_DISPOSITION_INFO fdi;
            fdi.DeleteFile = TRUE;      //  Marking for deletion
            Success = SetFileInformationByHandle(CompressedFile, FileDispositionInfo, &fdi, sizeof(FILE_DISPOSITION_INFO));
            if (!Success) {
                printf("[X] Cannot delete corrupted compressed file.\n");
                retValue = TRUE;
            }
        }
        CloseHandle(CompressedFile);
    }
    return retValue;
}


int wmain(_In_ int argc, _In_ WCHAR* argv[]) {
    if (argc != 3) {
        printf("Usage:\n");
        printf("\t%ws <input_file_name> <compressd_file_name>\n", argv[0]);
        return TRUE;
    }
    return !CompressFile(argv[1], argv[2]);
}