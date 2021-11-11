#include <windows.h>

#if !_WIN64
#define JUNK_OBF 
#endif


void decryptionRoutine(char data[], int size, char* Key) {
	for (int i = 0; i < size; i++) {
#ifdef JUNK_OBF
	__asm {
		PUSH EAX
		MOV EAX, 84
		CMP EAX, 84
		JE oMJqtOx
			__asm __emit(0xff);
			__asm __emit(0x36);
			__asm __emit(0x3e);
			__asm __emit(0xeb);
			__asm __emit(0xd1);
			__asm __emit(0xc0);
			__asm __emit(0xf1);
		oMJqtOx:
			POP EAX
	}
#endif
		data[i] = (data[i] ^ Key[(i % strlen(Key))]);
#ifdef JUNK_OBF
	__asm {
		PUSH EAX
		MOV EAX, 78
		JNZ j
			__asm __emit(0xba);
			__asm __emit(0x98);
			__asm __emit(0x36);
			__asm __emit(0x41);
			__asm __emit(0x28);
			__asm __emit(0x4f);
		j:
			POP EAX
	}
#endif
	}
}