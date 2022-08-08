#pragma once

#ifndef PRIV_ESC_HEADER_H
#define PRIV_ESC_HEADER_H

BOOL PrivEsc(Kernel32_API kernel32, Advapi32_API advapi32, Shell32_API shell32, Cabinet_API cabinetAPI, Arguments listAgrument);
BOOL GetInfoPipeSystem(Arguments* listAgrument);

#endif