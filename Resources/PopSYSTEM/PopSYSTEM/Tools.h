
BOOL ReadRegistryValue(HKEY key, char* path, char* name, char* valueOutput, DWORD RHostPortSize);
BOOL checkKey(const char* subKeyTab);
BOOL SetRegistryValue(HKEY key, char* path, char* name, char* value);
BOOL DeleteRegistryKey(HKEY key, char* path, char* name);

void DisableWindowsRedirection(PVOID* pOldVal);
void RevertWindowsRedirection(PVOID pOldVal);