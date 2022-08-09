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
		JZ XHnKaQ
			__asm __emit(0xab);
			__asm __emit(0xa0);
			__asm __emit(0x4a);
			__asm __emit(0xc8);
		XHnKaQ:
			POP EAX
	}
#endif
		data[i] = (data[i] ^ Key[(i % strlen(Key))]);
#ifdef JUNK_OBF
	__asm {
		PUSH EAX
		MOV EAX, 37
		JNZ MEtqi
			__asm __emit(0x75);
			__asm __emit(0xae);
			__asm __emit(0x80);
			__asm __emit(0xad);
			__asm __emit(0xb7);
			__asm __emit(0x1b);
			__asm __emit(0xcf);
			__asm __emit(0x9b);
			__asm __emit(0x25);
		MEtqi:
			POP EAX
	}
#endif
	}
}