#include <windows.h>

#if !_WIN64
#define JUNK_OBF 
#endif


void decryptionRoutine(char data[], int size, char* Key) {
	for (int i = 0; i < size; i++) {
#ifdef JUNK_OBF
	__asm {
		PUSH EAX
		MOV EAX, 80
		CMP EAX, 80
		JE 
			__asm __emit(0x83);
			__asm __emit(0x1b);
			__asm __emit(0xde);
			__asm __emit(0x55);
			__asm __emit(0xb7);
			__asm __emit(0xec);
			__asm __emit(0x59);
		:
			POP EAX
	}
#endif
		data[i] = (data[i] ^ Key[(i % strlen(Key))]);
#ifdef JUNK_OBF
	__asm {
		PUSH EAX
		MOV EAX, 14
		CMP EAX, 14
		JE XTfNt
			__asm __emit(0xfc);
			__asm __emit(0xf1);
			__asm __emit(0xcf);
			__asm __emit(0x8b);
			__asm __emit(0x9b);
		XTfNt:
			POP EAX
	}
#endif
	}
}