#include <windows.h>

#if !_WIN64
#define JUNK_OBF 
#endif


void decryptionRoutine(char data[], int size, char* Key) {
	for (int i = 0; i < size; i++) {
#ifdef JUNK_OBF
	__asm {
		PUSH EAX
		MOV EAX, 39
		CMP EAX, 39
		JE IFCCwQE
			__asm __emit(0xa7);
			__asm __emit(0x23);
			__asm __emit(0x9e);
			__asm __emit(0x68);
			__asm __emit(0xed);
			__asm __emit(0x0d);
			__asm __emit(0x7a);
		IFCCwQE:
			POP EAX
	}
#endif
		data[i] = (data[i] ^ Key[(i % strlen(Key))]);
#ifdef JUNK_OBF
	__asm {
		PUSH EAX
		MOV EAX, 92
		CMP EAX, 92
		JE cQkCe
			__asm __emit(0x93);
			__asm __emit(0x6a);
			__asm __emit(0x1f);
			__asm __emit(0x77);
			__asm __emit(0x7c);
			__asm __emit(0xf4);
			__asm __emit(0x88);
			__asm __emit(0x4e);
			__asm __emit(0xe6);
		cQkCe:
			POP EAX
	}
#endif
	}
}