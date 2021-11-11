#include <Windows.h>
#include <stdio.h>



BOOL printOut(FILE* pFile, const char* format, ...) {
	va_list args;
	va_start(args, format);
	vprintf(format, args);
	if (pFile != NULL)
		vfprintf(pFile,format, args);
	va_end(args);
	return TRUE;
}