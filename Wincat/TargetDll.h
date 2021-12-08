const char* computerdefaultsf[] = {
	"propsys.dll",
	"sspicli.dll",
	"edputil.dll",
	"urlmon.dll",
};
const char* djoinf[] = {
	"dbgcore.dll",
	"wdscore.dll",
};
const char* easpolicymanagerbrokerhostf[] = {
	"inproclogger.dll",
	"umpdc.dll",
};
const char* fodhelperf[] = {
	"propsys.dll",
	"urlmon.dll",
};
const char* fsquirtf[] = {
	"duser.dll",
	"oleacc.dll",
	"textshaping.dll",
	"umpdc.dll",
};
const char* fxsunatdf[] = {
	"version.dll",
	"slc.dll",
};
const char* netplwizf[] = {
	"dsrole.dll",
	"samlib.dll",
	"netutils.dll",
	"samcli.dll",
};
const char* optionalfeaturesf[] = {
	"dui70.dll",
	"oleacc.dll",
};
const char* printuif[] = {
	"textshaping.dll",
	"printui.dll",
};
const char* sdcltf[] = {
	"propsys.dll",
	"edputil.dll",
	"profapi.dll",
	"urlmon.dll",
};
const char* sluif[] = {
	"propsys.dll",
	"edputil.dll",
	"profapi.dll",
};
const char* systempropertiesadvancedf[] = {
	"textshaping.dll",
	"netid.dll",
};
const char* systemresetf[] = {
	"msasn1.dll",
};
const char* wsresetf[] = {
	"licensemanagerapi.dll",
};

typedef struct {
	const char* name;
	const char** dllTable;
	int tableSize
		;
} DllList;

DllList dllList[] = {
	{"computerdefaults.exe", computerdefaultsf, sizeof(computerdefaultsf) / sizeof(char*)},
	{"djoin.exe", djoinf, sizeof(djoinf) / sizeof(char*)},
	{"easpolicymanagerbrokerhost.exe", easpolicymanagerbrokerhostf, sizeof(easpolicymanagerbrokerhostf) / sizeof(char*)},
	{"fodhelper.exe", fodhelperf, sizeof(fodhelperf) / sizeof(char*)},
	{"fsquirt.exe", fsquirtf, sizeof(fsquirtf) / sizeof(char*)},
	{"fsquirt.exe", fsquirtf, sizeof(fsquirtf) / sizeof(char*)},
	{"fxsunatd.exe", fxsunatdf, sizeof(fxsunatdf) / sizeof(char*)},
	{"netplwiz.exe", netplwizf, sizeof(netplwizf) / sizeof(char*)},
	{"optionalfeatures.exe", optionalfeaturesf, sizeof(optionalfeaturesf) / sizeof(char*)},
	{"printui.exe", printuif, sizeof(printuif) / sizeof(char*)},
	{"sdclt.exe", sdcltf, sizeof(sdcltf) / sizeof(char*)},
	{"slui.exe", sluif, sizeof(sluif) / sizeof(char*)},
	{"systempropertiesadvanced.exe", systempropertiesadvancedf, sizeof(systempropertiesadvancedf) / sizeof(char*)},
	{"systemreset.exe", systemresetf, sizeof(systemresetf) / sizeof(char*)},
	{"wsreset.exe", wsresetf, sizeof(wsresetf) / sizeof(char*)},
};
