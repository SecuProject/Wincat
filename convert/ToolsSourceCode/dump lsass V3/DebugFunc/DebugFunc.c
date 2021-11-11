#include <Windows.h>
#include <stdio.h>

void PauseDebug() {
#if _DEBUG
	system("pause");
#endif
}
void PrintDebug(const char* format, ...) {
#if _DEBUG
	va_list args;
	va_start(args, format);
	vprintf(format, args);
	va_end(args);
#endif
}