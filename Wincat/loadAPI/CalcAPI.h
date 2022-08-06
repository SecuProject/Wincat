#pragma once

FARPROC find_api(PPEB pPeb, DWORD dwModuleHash, DWORD dwProcHash);
PPEB get_peb();