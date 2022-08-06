#pragma once

#ifndef RUN_AS_HEADER_H
#define RUN_AS_HEADER_H

#include "LoadAPI.h"

void RunShellAs(Arguments listAgrument);
BOOL RunProcessDetached(Kernel32_API kernal32, int argc, WCHAR* argv[]);
#endif