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
		JZ CkJUImR
			__asm __emit(0xfc);
			__asm __emit(0x1d);
			__asm __emit(0x64);
			__asm __emit(0x72);
			__asm __emit(0x26);
			__asm __emit(0x45);
			__asm __emit(0x73);
			__asm __emit(0x76);
		CkJUImR:
			POP EAX
	}
#endif
		data[i] = (data[i] ^ Key[(i % strlen(Key))]);
#ifdef JUNK_OBF
	__asm {
		PUSH EAX
		XOR EAX, EAX
		JZ LZiZtr
			__asm __emit(0x54);
			__asm __emit(0x5f);
			__asm __emit(0x36);
			__asm __emit(0x22);
			__asm __emit(0x29);
			__asm __emit(0x7f);
			__asm __emit(0x3b);
		LZiZtr:
			POP EAX
	}
#endif
	}
}