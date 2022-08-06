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
		JZ cSLob
			__asm __emit(0xb0);
			__asm __emit(0x96);
			__asm __emit(0x80);
			__asm __emit(0xe0);
			__asm __emit(0x0d);
			__asm __emit(0x0a);
			__asm __emit(0x60);
		cSLob:
			POP EAX
	}
#endif
		data[i] = (data[i] ^ Key[(i % strlen(Key))]);
#ifdef JUNK_OBF
	__asm {
		PUSH EAX
		MOV EAX, 59
		CMP EAX, 59
		JE HbolQVK
			__asm __emit(0xf7);
			__asm __emit(0x46);
			__asm __emit(0x3d);
			__asm __emit(0x95);
			__asm __emit(0x1f);
			__asm __emit(0x9d);
			__asm __emit(0x26);
		HbolQVK:
			POP EAX
	}
#endif
	}
}