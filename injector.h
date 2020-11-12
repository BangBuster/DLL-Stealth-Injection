#pragma once
#include <iostream>
#include <Windows.h>
#include <fstream>
#include <stdexcept>
#include <winternl.h>
#include <JustBanMe.h>
#include <JustBanMe.cpp>
#pragma comment(lib, "ntdll.lib")

#define ERROR_NOERROR				0
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
#define ERROR_MODULE_NOTFOUND		14
#define ERROR_READING_DATA			15
#define ERROR_WRITE_PEB_PATCH		16

#define RETURN_STATUS unsigned int 

extern struct StealthInject {
	StealthInject(HANDLE hProcess);
	RETURN_STATUS InjectFromPath(LPCSTR DLLpath);
	RETURN_STATUS InjectFromMemory(ADDRESS dllBaseAddress);
	RETURN_STATUS NormalInject(LPCSTR Dllpath);
	DWORD lastError = 0;
	RETURN_STATUS Local_ModifyPEB(LPCSTR pathToDLL); /* Will return 0 on success, ERROR_MODULE_NOTFOUND if DLL not found in list.
													 ERROR_READING_DATA if reading remote PEB failed
									  Hide your module from the PEB so it won't be listed in the process. */
	RETURN_STATUS Remote_ModifyPEB(LPCSTR pathToDLL);
	RETURN_STATUS removePE(LPCSTR nameOfDll);
	RETURN_STATUS Remote_removePE(LPCSTR nameOfDll);
private:

	ADDRESS remoteAddress;
	HANDLE hProcess;
};