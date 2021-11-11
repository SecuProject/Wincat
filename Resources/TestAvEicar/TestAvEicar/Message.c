#include <stdio.h>
#include <Windows.h>

#define COLOR_YELLOW 14
#define COLOR_RED	 12
#define COLOR_GREEN	 10
#define COLOR_GRIS   7


void MsgIcon(char* msg, int color, BOOL tab) {
	HANDLE handler = GetStdHandle(STD_OUTPUT_HANDLE);
	printf("%s[", tab ? "\t" : "");
	SetConsoleTextAttribute(handler, color);
	printf("%s", msg);
	SetConsoleTextAttribute(handler, COLOR_GRIS);
	//CloseHandle(handler);
	printf("] ");

}

void MsgOK(const char* format, ...) {
	va_list args;
	va_start(args, format);
	MsgIcon("*", COLOR_GREEN, FALSE);
	vprintf(format, args);
	va_end(args);
}
void MsgOK2(const char* format, ...) {
	va_list args;
	va_start(args, format);
	MsgIcon("*", COLOR_GREEN, TRUE);
	vprintf(format, args);
	va_end(args);
}

void MsgWarning(const char* format, ...) {
	va_list args;
	va_start(args, format);
	MsgIcon("!", COLOR_YELLOW, FALSE);
	vprintf(format, args);
	va_end(args);
}
void MsgWarning2(const char* format, ...) {
	va_list args;
	va_start(args, format);
	MsgIcon("!", COLOR_YELLOW, TRUE);
	vprintf(format, args);
	va_end(args);
}

void MsgError(const char* format, ...) {
	va_list args;
	va_start(args, format);
	MsgIcon("X", COLOR_RED, FALSE);
	vprintf(format, args);
	va_end(args);
}
void MsgError2(char* format, ...) {
	va_list args;
	va_start(args, format);
	MsgIcon("x", COLOR_RED, TRUE);
	vprintf(format, args);
	va_end(args);
}




void MsgPass2(char* format, ...) {
	va_list args;
	va_start(args, format);
	MsgIcon("PASS", COLOR_GREEN, TRUE);
	printf(" ");
	vprintf(format, args);
	va_end(args);
}
void MsgBlock2(char* format, ...) {
	va_list args;
	va_start(args, format);
	MsgIcon("BLOCK", COLOR_RED, TRUE);
	vprintf(format, args);
	va_end(args);
}