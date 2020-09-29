#pragma once
#include <iostream>
#include <Windows.h>
#include <fstream>
#include <stdexcept>

#define ERROR_INVALID_FILE			1
#define ERROR_ALLOCATION_IMAGE		2
#define ERROR_WRITE_IMAGE			3
#define ERROR_WRITE_SECTION			4
#define ERROR_ALLOCATION_LOADER_DATA 5
#define ERROR_WRITE_LOADER_DATA		6
#define ERROR_WRITE_SHELLCODE		7
#define ERROR_CREATE_THREAD			8

extern struct StealthInject {
	StealthInject(HANDLE hProcess, LPVOID baseAddrDLL);
	StealthInject(HANDLE hProcess, LPCSTR DLLpath);
};