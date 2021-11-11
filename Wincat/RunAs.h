#pragma once

#ifndef RUN_AS_HEADER_H
#define RUN_AS_HEADER_H

void RunShellAs(Arguments listAgrument);
BOOL RunProcessDetached(int argc, WCHAR* argv[]);
#endif