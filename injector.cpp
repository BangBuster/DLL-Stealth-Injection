#include "injector.h"

typedef HMODULE(__stdcall* pLoadLibraryA)(LPCSTR);
typedef FARPROC(__stdcall* pGetProcAddress)(HMODULE, LPCSTR);

typedef int(__stdcall* dllEntry)(HMODULE, DWORD, LPVOID);

struct loaderdata {
	LPVOID ImageBaseAddr;

	PIMAGE_NT_HEADERS NtHeaders;
	PIMAGE_BASE_RELOCATION BaseReloc;
	PIMAGE_IMPORT_DESCRIPTOR ImportDirectory;

	pLoadLibraryA fnLoadLibraryA;
	pGetProcAddress fnGetProcAddress;
};

DWORD InternalLoader(LPVOID loaderLocation) {
	loaderdata* LoaderParams = (loaderdata*)loaderLocation;
	DWORD imageBaseAddr = (DWORD)((LPBYTE)LoaderParams->ImageBaseAddr - LoaderParams->NtHeaders->OptionalHeader.ImageBase); // Subtract ImageBase from Base Memory
	// Adjust base relocations
	PIMAGE_BASE_RELOCATION pIBR = LoaderParams->BaseReloc;
	while (pIBR->VirtualAddress) {											// while base relocation table exists
		if (pIBR->SizeOfBlock >= sizeof(IMAGE_BASE_RELOCATION)) {			// if block valid
			int numberOfEnteries = (pIBR->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / 2;		// number of enteries in table
			PWORD entry = (PWORD)(pIBR + 1);																								

			for (int i = 0; i < numberOfEnteries; i++) {					// Looping through table
				if (entry[i]) {												// If list isnt null
					PDWORD ptr = (PDWORD)((LPBYTE)LoaderParams->ImageBaseAddr + (pIBR->VirtualAddress + (entry[i] & 0xFFF)));
					*ptr += imageBaseAddr;									// Add existing value with imageBaseAddr
				}
			}
		}
		pIBR = (PIMAGE_BASE_RELOCATION)((LPBYTE)pIBR + pIBR->SizeOfBlock); // next block
	}

	// fix DLL imports and call if necessary
	PIMAGE_IMPORT_DESCRIPTOR pIID = LoaderParams->ImportDirectory;
	while (pIID->Characteristics){			// While imports exists
		PIMAGE_THUNK_DATA OrigFirstThunk = (PIMAGE_THUNK_DATA)((LPBYTE)LoaderParams->ImageBaseAddr + pIID->OriginalFirstThunk); // look up table
		PIMAGE_THUNK_DATA FirstThunk = (PIMAGE_THUNK_DATA)((LPBYTE)LoaderParams->ImageBaseAddr + pIID->FirstThunk); // IAT
		HMODULE hModule = LoaderParams->fnLoadLibraryA((LPCSTR)LoaderParams->ImageBaseAddr + pIID->Name); // loads descriptor library

		if (!hModule)
			return FALSE;

		while (OrigFirstThunk->u1.AddressOfData){
			if (OrigFirstThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) // if function is imported by ordinal
			{
				// Import by ordinal
				DWORD64 Function = (DWORD64)LoaderParams->fnGetProcAddress(hModule,
					(LPCSTR)(OrigFirstThunk->u1.Ordinal & 0xFFFF));

				if (!Function)
					return FALSE;

				FirstThunk->u1.Function = Function; // append function to IAT
			}
			else {
				// Import by name
				PIMAGE_IMPORT_BY_NAME pIBN = (PIMAGE_IMPORT_BY_NAME)((LPBYTE)LoaderParams->ImageBaseAddr + OrigFirstThunk->u1.AddressOfData);
				
				DWORD64 Function = (DWORD64)LoaderParams->fnGetProcAddress(hModule, (LPCSTR)pIBN->Name); // get function addr by its name
				
				if (!Function)
					return FALSE;

				FirstThunk->u1.Function = Function; // append function to IAT
			}
			OrigFirstThunk++;
			FirstThunk++;
		}
		pIID++;
	}
	if (LoaderParams->NtHeaders->OptionalHeader.AddressOfEntryPoint){
		dllEntry EntryPoint = (dllEntry)((LPBYTE)LoaderParams->ImageBaseAddr + LoaderParams->NtHeaders->OptionalHeader.AddressOfEntryPoint);
		ZeroMemory(LoaderParams->ImageBaseAddr, 0x9f); // Remove PE signatures
		return EntryPoint((HMODULE)LoaderParams->ImageBaseAddr, DLL_PROCESS_ATTACH, NULL); // Call the entry point
	}
	return TRUE;
}

void referencePoint() {}

StealthInject::StealthInject(HANDLE hProcess, LPVOID baseAddrDLL) {
	if (!hProcess) { throw ERROR_INVALID_HANDLE; }
	loaderdata _loaderdata;
	// Parse PE headers
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)baseAddrDLL;
	PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((LPBYTE)baseAddrDLL + pDosHeader->e_lfanew);
	PIMAGE_SECTION_HEADER pSection = (PIMAGE_SECTION_HEADER)(pNtHeaders + 1);

	// Allocate memory for the image in remote process
	PVOID ExecutableImage = VirtualAllocEx(hProcess, NULL, pNtHeaders->OptionalHeader.SizeOfImage,
		MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!ExecutableImage) { throw ERROR_ALLOCATION_IMAGE; }
	// Copy the image to target process
	if (!WriteProcessMemory(hProcess, ExecutableImage, baseAddrDLL,
		pNtHeaders->OptionalHeader.SizeOfHeaders, NULL)) {
		StealthInject::lastError = GetLastError();
		throw ERROR_WRITE_IMAGE;
	}
	
	// Copy sections
	for (int i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++) {
		if (!WriteProcessMemory(hProcess, (PVOID)((LPBYTE)ExecutableImage + pSection[i].VirtualAddress),
			(PVOID)((LPBYTE)baseAddrDLL + pSection[i].PointerToRawData), pSection[i].SizeOfRawData, NULL)) {
			StealthInject::lastError = GetLastError();
			throw ERROR_WRITE_SECTION;
		}
	}
	
	// Fill loader data
	_loaderdata.ImageBaseAddr = ExecutableImage;
	_loaderdata.NtHeaders = (PIMAGE_NT_HEADERS)((LPBYTE)ExecutableImage + pDosHeader->e_lfanew);
	_loaderdata.BaseReloc = (PIMAGE_BASE_RELOCATION)((LPBYTE)ExecutableImage + pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
	_loaderdata.ImportDirectory = (PIMAGE_IMPORT_DESCRIPTOR)((LPBYTE)ExecutableImage + pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
	_loaderdata.fnLoadLibraryA = LoadLibraryA;
	_loaderdata.fnGetProcAddress = GetProcAddress;

	// Allocate memory for the loader data
	PVOID LoaderMemory = VirtualAllocEx(hProcess, NULL, sizeof(loaderdata), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!LoaderMemory) { throw ERROR_ALLOCATION_LOADER_DATA; }
	// Write loader data to memory
	if (!WriteProcessMemory(hProcess, LoaderMemory, &_loaderdata, sizeof(_loaderdata), NULL)) { throw ERROR_WRITE_LOADER_DATA; }
	// Write Internal loader shellcode
	if (!WriteProcessMemory(hProcess, (LPVOID)((loaderdata*)LoaderMemory + 1), InternalLoader, (DWORD)referencePoint - (DWORD)InternalLoader, NULL)) { throw ERROR_WRITE_SHELLCODE; }
	
	// Create remote thread to call the internal loader
	HANDLE hThread = CreateRemoteThread(hProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)((loaderdata*)LoaderMemory + 1), LoaderMemory, NULL, NULL);
	if (!hThread) { StealthInject::lastError = GetLastError(); throw ERROR_CREATE_THREAD; }
	WaitForSingleObject(hThread, INFINITE);

	// Clean up
	VirtualFreeEx(hProcess, LoaderMemory, 0, MEM_RELEASE);
}

StealthInject::StealthInject(HANDLE hProcess, LPCSTR DLLpath) {
	if (!hProcess) { throw ERROR_INVALID_HANDLE; }
	// Load DLL into own memory
	std::ifstream File(DLLpath, std::ios::binary | std::ios::ate);
	size_t szFile = File.tellg();
	if (szFile < 0x1000) { // if file smaller than 4096
		throw ERROR_INVALID_FILE;
	}
	PBYTE FileBuffer = new BYTE[szFile];
	File.seekg(0, std::ios::beg);
	File.read((char*)(FileBuffer), szFile);
	File.close();

	loaderdata _loaderdata;
	// Parse PE headers
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)FileBuffer;
	PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((LPBYTE)FileBuffer + pDosHeader->e_lfanew);
	PIMAGE_SECTION_HEADER pSection = (PIMAGE_SECTION_HEADER)(pNtHeaders + 1);

	// Allocate memory for the image in remote process
	PVOID ExecutableImage = VirtualAllocEx(hProcess, NULL, pNtHeaders->OptionalHeader.SizeOfImage,
		MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!ExecutableImage) { StealthInject::lastError = GetLastError(); throw ERROR_ALLOCATION_IMAGE; }
	// Copy the headers to target process
	if(!WriteProcessMemory(hProcess, ExecutableImage, FileBuffer,
		pNtHeaders->OptionalHeader.SizeOfHeaders, NULL)) {
		StealthInject::lastError = GetLastError();
		throw ERROR_WRITE_IMAGE;
	}
	// Copy sections
	for (int i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++){
		if (!WriteProcessMemory(hProcess, (PVOID)((LPBYTE)ExecutableImage + pSection[i].VirtualAddress),
			(PVOID)((LPBYTE)FileBuffer + pSection[i].PointerToRawData), pSection[i].SizeOfRawData, NULL)) {
			StealthInject::lastError = GetLastError();
			throw ERROR_WRITE_SECTION;
		}
	}
	
	// Fill loader data
	_loaderdata.ImageBaseAddr = ExecutableImage;
	_loaderdata.NtHeaders = (PIMAGE_NT_HEADERS)((LPBYTE)ExecutableImage + pDosHeader->e_lfanew);
	_loaderdata.BaseReloc = (PIMAGE_BASE_RELOCATION)((LPBYTE)ExecutableImage + pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
	_loaderdata.ImportDirectory = (PIMAGE_IMPORT_DESCRIPTOR)((LPBYTE)ExecutableImage + pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
	_loaderdata.fnLoadLibraryA = LoadLibraryA;
	_loaderdata.fnGetProcAddress = GetProcAddress;

	// Allocate memory for the loader data
	PVOID LoaderMemory = VirtualAllocEx(hProcess, NULL, sizeof(loaderdata), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!LoaderMemory) { throw ERROR_ALLOCATION_LOADER_DATA; }
	// Write loader data to memory
	if (!WriteProcessMemory(hProcess, LoaderMemory, &_loaderdata, sizeof(_loaderdata), NULL)) { throw ERROR_WRITE_LOADER_DATA; }
	// Write Internal loader shellcode
	if (!WriteProcessMemory(hProcess, (LPVOID)((loaderdata*)LoaderMemory + 1), InternalLoader, (DWORD)referencePoint - (DWORD)InternalLoader, NULL)) { throw ERROR_WRITE_SHELLCODE; }
	// Create remote thread to call the internal loader
	HANDLE hThread = CreateRemoteThread(hProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)((loaderdata*)LoaderMemory + 1), LoaderMemory, NULL, NULL);
	if (!hThread) { StealthInject::lastError = GetLastError(); throw ERROR_CREATE_THREAD; }
	WaitForSingleObject(hThread, INFINITE);
	// Clean up
	VirtualFreeEx(hProcess, LoaderMemory, 0, MEM_RELEASE);
}
StealthInject::StealthInject(HANDLE hProcess, LPCSTR Dllpath, bool regularInject) {
	if (!regularInject) { throw ERROR_INVALID_PARAMETERS; }
	if (!hProcess) { throw ERROR_INVALID_HANDLE; }

	size_t strSz = strlen(Dllpath);

	LPVOID strAddress = VirtualAllocEx(hProcess, NULL, strSz, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!strAddress) { StealthInject::lastError = GetLastError(); throw ERROR_ALLOCATION_STRING; }

	if (!WriteProcessMemory(hProcess, strAddress, Dllpath, strSz, 0)) { StealthInject::lastError = GetLastError();  throw ERROR_WRITE_STRING; }
	
	HANDLE thread = CreateRemoteThread(hProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)LoadLibraryA, strAddress, NULL, NULL);
	if (!thread) { StealthInject::lastError = GetLastError(); throw ERROR_THREAD_CREATION; }

	WaitForSingleObject(thread, INFINITE);
	CloseHandle(thread);
	VirtualFreeEx(hProcess, strAddress, 0, MEM_RELEASE);
}

int StealthInject::modifyPEB(LPCWSTR pathToDLL) {
	PTEB pTEB;
	PPEB pPEB;
	PPEB_LDR_DATA pLdrData;
	PLIST_ENTRY listHead, bufferEntry;
	PLDR_DATA_TABLE_ENTRY LdrEntry;
#ifdef _WIN64
	pPEB = (PPEB)__readgsqword(12 * sizeof(LPVOID));
#else
	pPEB = (PPEB)__readfsdword(12 * sizeof(LPVOID));
#endif
	pLdrData = pPEB->Ldr;
	listHead = &pLdrData->InMemoryOrderModuleList;
	bufferEntry = listHead->Flink;
	bool found = false;
	do {
		LdrEntry = (PLDR_DATA_TABLE_ENTRY)((ADDRESS)bufferEntry - sizeof(LPVOID)*2);
		UNICODE_STRING dllName = LdrEntry->FullDllName;
		if (!wcscmp(dllName.Buffer, pathToDLL)) { // If module name equals to provided name, patch the PEB
			PLIST_ENTRY previous = bufferEntry->Blink;
			PLIST_ENTRY next = bufferEntry->Flink;
			previous->Flink = next;
			next->Blink = previous;
			found = true;
		}
		bufferEntry = bufferEntry->Flink;
	} while (bufferEntry != listHead);
	if (!found) { return 1; } // DLL not found
	return 0;
}