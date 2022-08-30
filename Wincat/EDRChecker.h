#pragma once

#ifndef EDR_CHECKER_HEADER_H
#define EDR_CHECKER_HEADER_H

#ifndef uint32_t
typedef unsigned int       uint32_t;
#endif


BOOL EDRChecker();
uint32_t crc32(const char* buf, size_t len);

#endif