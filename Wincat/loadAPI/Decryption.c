#include <windows.h>

#if !_WIN64
#define JUNK_OBF 
#endif


void decryptionRoutine(char data[], int size, char* Key) {
	for (int i = 0; i < size; i++) {
#ifdef JUNK_OBF
	__asm {
		PUSH EAX
		XOR EAX, EAX
		JZ kjgNI
			__asm __emit(0x92);
			__asm __emit(0xd5);
			__asm __emit(0x58);
			__asm __emit(0xcf);
			__asm __emit(0xfb);
		kjgNI:
			POP EAX
	}
#endif
		data[i] = (data[i] ^ Key[(i % strlen(Key))]);
#ifdef JUNK_OBF
	__asm {
		PUSH EAX
		MOV EAX, 59
		CMP EAX, 59
		JE EMUgdxj
			__asm __emit(0xcd);
			__asm __emit(0x80);
			__asm __emit(0xaf);
			__asm __emit(0xa2);
			__asm __emit(0x35);
			__asm __emit(0xe7);
			__asm __emit(0x1c);
		EMUgdxj:
			POP EAX
	}
#endif
	}
}