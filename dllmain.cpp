// dllmain.cpp : Defines the entry point for the DLL application.
#include <iostream>
#include <Windows.h> 
#include <tlhelp32.h>
#pragma warning(disable:4996)

int main(HMODULE hModule) {
    AllocConsole();
    freopen("CONOUT$", "w", stdout);
    std::cout << "I'm IN!" << std::endl;
   
    FreeConsole();
    FreeLibraryAndExitThread(hModule, 0);
    return 0;
}
BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    {
        CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)main, hModule, NULL, NULL);
        break;
    }
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
