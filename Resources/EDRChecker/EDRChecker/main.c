#include <Windows.h>
#include <stdio.h>
#include <stdint.h>
#include <tlhelp32.h>

/*
const char* processName[] = { // temp
	// Process Monitor
	"PROCEXP64.EXE",
	"PROCEXP.EXE",
	"ProcessHacker.exe",
	"apimonitor-x86.exe",
	"apimonitor-x64.exe",
	"procdump.exe",
	"procdump64.exe",
	"Procmon.exe",

	// Network
	"wireshark.exe",
	"apateDNS.exe",
	"NetAgent.exe",
	"windump.exe",
	"tcpdump.exe",
	"Tcpvcon.exe",
	"Tcpview.exe",
	"Fiddler.exe"

};*/

typedef struct _EDR_DESCRITPION {
	const char* processName;
	const char* comment;
}EDR_DESCRIPTION;


EDR_DESCRIPTION edrDescription[] = { // temp
	"activeconsole.exe",		"",
	"apimonitor-x64.exe",		"",
	"apimonitor-x86.exe",		"",
	"appsense.exe",				"",
	"authtap.exe",				"",
	"avast.exe",				"",
	"avecto.exe",				"",
	"canary.exe",				"",
	"carbon black.exe",			"",
	"carbon.exe",				"",
	"carbonblack.exe",			"",
	"cb.exe",					"",
	"cisco amp.exe",			"",
	"ciscoamp.exe",				"",
	"countercept.exe",			"",
	"countertack.exe",			"",
	"cramtray.exe",				"",
	"crowdstrike.exe",			"",
	"crssvc.exe",				"",
	"csagent.exe",				"",
	"csfalcon.exe",				"",
	"csshell.exe",				"",
	"cybereason.exe",			"",
	"cyclorama.exe",			"",
	"cylance.exe",				"",
	"cyoptics.exe",				"",
	"cyserver.exe",				"",
	"cytray.exe",				"",
	"cyupdate.exe",				"",
	"cyvera.exe",				"",
	"darktrace.exe",			"",
	"defender.exe",				"",
	"defendpoint.exe",			"",
	"edrsvc.exe",				"ComodoSecurity - OpenEDR",
	"eectrl.exe",				"",
	"elastic.exe",				"Elastic agent",
	"elastic-agent",			"Elastic agent",
	"emcoreservice.exe",		"",
	"emsystem.exe",				"",
	"endgame.exe",				"",
	"f-secure.exe",				"",
	"filebeat.exe",				"Elastic agent",
	"fireeye.exe",				"",
	"forcepoint.exe",			"",
	"forescout.exe",			"",
	"groundling.exe",			"",
	"grrservic.exe",			"",
	"grrservice",				"",
	"inspector.exe",			"",
	"ivanti.exe",				"",
	"kaspersky.exe",			"",
	"lacuna.exe",				"",
	"logrhythm.exe",			"",
	"macmnsvc.exe",				"McAfee Agent Common Services",
	"masvc.exe",				"McAfee Agent Service",
	"malware.exe",				"",
	"mandiant.exe",				"",
	"mcafee.exe",				"",
	"mfemactl.exe",				"McAfee Agent AAC Host",
	"morphisec.exe",			"",
	"msascuil.exe",				"",
	"msmpeng.exe",				"",
	"nissrv.exe",				"",
	"ntrtscan.exe",				"",
	"omni.exe",					"",
	"omniagent.exe",			"",
	"ossec-agent.exe",			"AlienVault Agent/ossec",
	"ossec.exe",				"AlienVault Agent/ossec",
	"osquery.exe",				"AlienVault Agent/ossec",
	"osqueryd.exe",				"AlienVault Agent/WAZUS/ossec",
	"palo alto networks.exe",	"",
	"pgeposervice.exe",			"",
	"pgsystemtray.exe",			"",
	"privilegeguard.exe",		"",
	"procwall.exe",				"",
	"protectorservic.exe",		"",
	"protectorservice",			"",
	"qradar.exe",				"IBM - QRadar",
	"redcloak.exe",				"",
	"secureconnector.exe",		"Forescout agent",
	"secureworks.exe",			"",
	"securityhealthservice.exe","",
	"semlaunchsv.exe",			"",
	"semlaunchsvc",				"",
	"sentinel.exe",				"",
	"sepliveupdat.exe",			"",
	"sepliveupdate",			"",
	"sisidsservice.exe",		"",
	"sisipsservice.exe",		"",
	"sisipsutil.exe",			"",
	"smc.exe",					"",
	"smcgui.exe",				"",
	"snac64.exe",				"",
	"sophos.exe",				"",
	"splunk.exe",				"Splunk Universal Forwarde",
	"splunkd.exe",				"Splunk Universal Forwarde",
	"srtsp.exe",				"",
	"symantec.exe",				"",
	"symcorpu.exe",				"",
	"symcorpui",				"",
	"symefasi.exe",				"",
	"sysinternal.exe",			"",
	"sysmon.exe",				"System Monitor - Windows Sysinternals",
	"sysmon64.exe",				"System Monitor - Windows Sysinternals",
	"tanium.exe",				"",
	"tcpdump.exe",				"",
	"tda.exe",					"",
	"tdawork.exe",				"",
	"threat.exe",				"",
	"tmbmsrv.exe",				"",
	"tmccsf.exe",				"",
	"tmlisten.exe",				"",
	"tmssclient.exe",			"",
	"tpython.exe",				"",
	"trend.exe",				"",
	"vectra.exe",				"",
	"watchdogagent.exe",		"",
	"wazuh-agent.exe",			"Wazuh agent",
	"wincollect.exe",			"",					// XXXXXXXXXXX
	"winlogbeat.exe",			"Elastic agent",	// XXXXXXXXXXX
	"windowssensor.exe",		"",
	"wireshark.exe",			"",
	"xagt",						"",
	"xagt.exe",					"",
	"xagtnotif.exe",			""

};
const uint32_t processNameHash[] = {
		0xf11ffc1c,     // activeconsole.exe
		0x9560419c,     // apimonitor-x64.exe
		0xd5aa738c,     // apimonitor-x86.exe
		0x424e67a9,     // appsense.exe
		0xb26ee0f8,     // authtap.exe
		0xbfc4d080,     // avast.exe
		0x235d5d64,     // avecto.exe
		0x1c052ea1,     // canary.exe
		0x193d6e81,     // carbon black.exe
		0x6b714a8f,     // carbon.exe
		0xebdcf887,     // carbonblack.exe
		0x89f4f95,      // cb.exe
		0x9abc0ddc,     // cisco amp.exe
		0xca6ded32,     // ciscoamp.exe
		0xcb545a0e,     // countercept.exe
		0x2e973649,     // countertack.exe
		0xa1162dde,     // cramtray.exe
		0xb1895aed,     // crowdstrike.exe
		0x2f76343d,     // crssvc.exe
		0x1d14bf83,     // csagent.exe
		0xe24d8d75,     // csfalcon.exe
		0x5b5aba90,     // csshell.exe
		0xd76a5525,     // cybereason.exe
		0x83da35ef,     // cyclorama.exe
		0xde0f388c,     // cylance.exe
		0xa3d04e91,     // cyoptics.exe
		0xc4d507c4,     // cyserver.exe
		0x3512154d,     // cytray.exe
		0x2d7b70fd,     // cyupdate.exe
		0x9c1c06,       // cyvera.exe
		0x9806b3db,     // darktrace.exe
		0xe735b68,      // defender.exe
		0xde8322b2,     // defendpoint.exe
		0x31187f1f,     // edrsvc.exe - ComodoSecurity - OpenEDR
		0x4a14b1a0,     // eectrl.exe
		0xd5997c24,     // elastic.exe - Elastic agent
		0x3efa7b7c,     // elastic-agent - Elastic agent
		0x6ccbf0e1,     // emcoreservice.exe
		0xc6b6b5ec,     // emsystem.exe
		0x423dd258,     // endgame.exe
		0xd9fb8ceb,     // f-secure.exe
		0x1a796eb4,     // filebeat.exe - Elastic agent
		0xc8f4f738,     // fireeye.exe
		0xb78b756b,     // forcepoint.exe
		0x3e29da8,      // forescout.exe
		0xad58b218,     // groundling.exe
		0x5d2a03b1,     // grrservic.exe
		0x9c604f6d,     // grrservice
		0x2830b60c,     // inspector.exe
		0x5a57870a,     // ivanti.exe
		0xa30fe00a,     // kaspersky.exe
		0xc11ec683,     // lacuna.exe
		0x57e1d45b,     // logrhythm.exe
		0x4491760,      // macmnsvc.exe - McAfee Agent Common Services
		0x5dc24c60,     // masvc.exe - McAfee Agent Service
		0x3c164bed,     // malware.exe
		0x9ad56511,     // mandiant.exe
		0x8b7e5216,     // mcafee.exe
		0x510aca1c,     // mfemactl.exe - McAfee Agent AAC Host
		0xeb911770,     // morphisec.exe
		0x1a2124c0,     // msascuil.exe
		0xf868b2f1,     // msmpeng.exe
		0xc78c39c5,     // nissrv.exe
		0x25afd43,      // ntrtscan.exe
		0xf49b8ca2,     // omni.exe
		0x1d817646,     // omniagent.exe
		0x31eaa0c1,     // ossec-agent.exe - AlienVault Agent/ossec
		0xc8e82285,     // ossec.exe - AlienVault Agent/ossec
		0x9d45f32,      // osquery.exe - AlienVault Agent/ossec
		0x92c03c6e,     // osqueryd.exe - AlienVault Agent/WAZUS/ossec
		0x489e7a2f,     // palo alto networks.exe
		0xf3996f9e,     // pgeposervice.exe
		0x76083e33,     // pgsystemtray.exe
		0x9991328d,     // privilegeguard.exe
		0xc0bc736f,     // procwall.exe
		0x986b3e78,     // protectorservic.exe
		0xaa38ed4b,     // protectorservice
		0xd3997def,     // qradar.exe - IBM - QRadar
		0x2cfa5ea1,     // redcloak.exe
		0xfbfe4deb,     // secureconnector.exe - Forescout agent
		0xb8ac3964,     // secureworks.exe
		0xfb22a468,     // securityhealthservice.exe
		0x7046ecf8,     // semlaunchsv.exe
		0xdc4a8908,     // semlaunchsvc
		0xaffa3669,     // sentinel.exe
		0xf38034c8,     // sepliveupdat.exe
		0xe7d4a3ac,     // sepliveupdate
		0x43f877f1,     // sisidsservice.exe
		0x3746bbbd,     // sisipsservice.exe
		0xd298a623,     // sisipsutil.exe
		0xfedbb33e,     // smc.exe
		0x58afdb8c,     // smcgui.exe
		0x9e07b79f,     // snac64.exe
		0xfa381bf5,     // sophos.exe
		0x3f9040d9,     // splunk.exe - Splunk Universal Forwarde
		0xa52e4381,     // splunkd.exe - Splunk Universal Forwarde
		0x79dea124,     // srtsp.exe
		0x4d4d8110,     // symantec.exe
		0x707a6d38,     // symcorpu.exe
		0x10ba8540,     // symcorpui
		0x699d81e7,     // symefasi.exe
		0xa3a3b5da,     // sysinternal.exe
		0x61255b79,     // sysmon.exe - System Monitor - Windows Sysinternals
		0x9d3369c3,     // sysmon64.exe - System Monitor - Windows Sysinternals
		0x62fdfbad,     // tanium.exe
		0x9c89f652,     // tcpdump.exe
		0x66b38f18,     // tda.exe
		0x11c4588c,     // tdawork.exe
		0xd75db698,     // threat.exe
		0x129c7e9,      // tmbmsrv.exe
		0x1a35902a,     // tmccsf.exe
		0x6ccef6bb,     // tmlisten.exe
		0x237d1294,     // tmssclient.exe
		0x14193e2f,     // tpython.exe
		0xf63e7b90,     // trend.exe
		0x7e1d4ffa,     // vectra.exe
		0x4b14a9d0,     // watchdogagent.exe
		0x95716b98,     // wazuh-agent.exe - Wazuh agent
		0x4da68834,     // wincollect.exe
		0x4495116,      // winlogbeat.exe - Elastic agent
		0xf04af51a,     // windowssensor.exe
		0x77ae10f7,     // wireshark.exe
		0xbb0ebe3d,     // xagt
		0xfa3adc1f,     // xagt.exe
		0xb23218dc,     // xagtnotif.exe
};


uint32_t crc32(const char* buf, size_t len) {
	static uint32_t table[256];
	static int have_table = 0;
	uint32_t rem;
	uint8_t octet;
	int i, j;
	const char* p, * q;
	uint32_t crc = 0;

	/* This check is not thread safe; there is no mutex. */
	if (have_table == 0) {
		/* Calculate CRC table. */
		for (i = 0; i < 256; i++) {
			rem = i;  /* remainder from polynomial division */
			for (j = 0; j < 8; j++) {
				if (rem & 1) {
					rem >>= 1;
					rem ^= 0xedb88320;
				} else
					rem >>= 1;
			}
			table[i] = rem;
		}
		have_table = 1;
	}

	crc = ~crc;
	q = buf + len;
	for (p = buf; p < q; p++) {
		octet = *p;  /* Cast to unsigned octet. */
		crc = (crc >> 8) ^ table[(crc & 0xff) ^ octet];
	}
	return ~crc;
}
VOID ToLower(char* str1, size_t sizeStr1, char* str2) {
	for (size_t i = 0; i < sizeStr1; i++)
		str2[i] = tolower(str1[i]);
	str2[sizeStr1] = 0x00;
}




BOOL CheckForEdr() {
	HANDLE hProcessSnap;
	PROCESSENTRY32 pe32;


	hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcessSnap == INVALID_HANDLE_VALUE) {
		printf("[x] Fail to CreateToolhelp32Snapshot: %d\n", GetLastError());
		return FALSE;
	}

	pe32.dwSize = sizeof(PROCESSENTRY32);
	if (!Process32First(hProcessSnap, &pe32)) {
		printf("[x] Fail to Process32First: %d\n", GetLastError());
		CloseHandle(hProcessSnap);
		return FALSE;
	}

	do {
		
		for (UINT j = 0; j < sizeof(processNameHash) / sizeof(const uint32_t); j++) {
			char buffer[1024];
			uint32_t processNameCrc32;
			size_t outputSize = strlen(pe32.szExeFile);
			ToLower(pe32.szExeFile, outputSize, buffer);
			processNameCrc32 = crc32(buffer, outputSize);


			/*if (j == 0)
				printf("[d] 0x%x - %s\n", processNameCrc32, buffer);*/

			if (processNameCrc32 == processNameHash[j])
				printf("[!] EDR Detected: %s - %i\n",pe32.szExeFile, pe32.th32ProcessID);
		}
	} while (Process32Next(hProcessSnap, &pe32));

	CloseHandle(hProcessSnap);
	return TRUE;
}

VOID GenHash() {
	printf("const uint32_t processNameHash[] = {\n");

	for (UINT i = 0; i < sizeof(edrDescription) / sizeof(EDR_DESCRIPTION); i++) {
		char buffer[1024];
		size_t strSize = strlen(edrDescription[i].processName);
		ToLower((char*)edrDescription[i].processName, strSize, buffer);

		if(edrDescription[i].comment[0] != 0x00)
			printf("\t0x%x,\t// %.*s - %s\n", crc32(buffer, strSize), (int)strSize, buffer, edrDescription[i].comment);
		else
			printf("\t0x%x,\t// %.*s\n", crc32(buffer, strSize), (int)strSize, buffer);
	}
	printf("};\n");
}

int main() {
	GenHash();
	//CheckForEdr();
	system("pause");
	return FALSE;
}