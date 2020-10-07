#pragma once
#include <iostream>
#include <Windows.h>
#include <fstream>
#include <stdexcept>

#define ERROR_INVALID_FILE			1
#define ERROR_ALLOCATION_IMAGE		2
#define ERROR_ALLOCATION_STRING		11
#define ERROR_WRITE_IMAGE			3
#define ERROR_WRITE_SECTION			4
#define ERROR_ALLOCATION_LOADER_DATA 5
#define ERROR_WRITE_LOADER_DATA		6
#define ERROR_WRITE_SHELLCODE		7
#define ERROR_WRITE_STRING			12
#define ERROR_CREATE_THREAD			8
#define ERROR_INVALID_HANDLE		9
#define ERROR_INVALID_PARAMETERS	10
#define ERROR_THREAD_CREATION		13

extern struct StealthInject {
	StealthInject(HANDLE hProcess, LPVOID baseAddrDLL);
	StealthInject(HANDLE hProcess, LPCSTR DLLpath);
	StealthInject(HANDLE hProcess, LPCSTR Dllpath, bool regularInject = 0);
	DWORD lastError = 0;
};