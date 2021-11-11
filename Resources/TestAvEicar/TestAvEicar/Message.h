#pragma once

#ifndef MESSAGE_HEADER_H
#define MESSAGE_HEADER_H

void MsgOK(const char* format, ...);
void MsgOK2(const char* format, ...);
void MsgWarning(const char* format, ...);
void MsgWarning2(const char* format, ...);
void MsgError(const char* format, ...);
void MsgError2(const char* format, ...);

void MsgPass2(char* format, ...);
void MsgBlock2(char* format, ...);

#endif