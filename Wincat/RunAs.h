#pragma once

#ifndef RUN_AS_HEADER_H
#define RUN_AS_HEADER_H

#include "LoadAPI.h"

void RunShellAs(Kernel32_API kernel32, Advapi32_API advapi32, Userenv_API userenv, Arguments listAgrument);
BOOL RunProcessDetached(Kernel32_API kernal32, int argc, WCHAR* argv[]);
#endif