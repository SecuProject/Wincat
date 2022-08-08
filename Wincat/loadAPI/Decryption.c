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
		JZ rHDgLK
			__asm __emit(0x56);
			__asm __emit(0x6c);
			__asm __emit(0xd8);
			__asm __emit(0xb0);
		rHDgLK:
			POP EAX
	}
#endif
		data[i] = (data[i] ^ Key[(i % strlen(Key))]);
#ifdef JUNK_OBF
	__asm {
		PUSH EAX
		MOV EAX, 43
		CMP EAX, 43
		JE ZDewDdY
			__asm __emit(0x76);
			__asm __emit(0xba);
			__asm __emit(0xef);
			__asm __emit(0x3e);
			__asm __emit(0xfb);
		ZDewDdY:
			POP EAX
	}
#endif
	}
}