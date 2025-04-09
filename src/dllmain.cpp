#include "../include/OfficeApiHook.h"

// The necessary Windows/Winsock headers are now included via OfficeApiHook.h
// #define WIN32_LEAN_AND_MEAN             // Exclude rarely-used stuff from Windows headers
// #include <windows.h>
// #include <winsock2.h>
// #include <ws2tcpip.h>
// #include <wininet.h>
// #include <detours.h> // Already included via OfficeApiHook.h

// Global variables
HookConfig g_config;
std::mutex g_logMutex;
std::ofstream g_logFile;
std::ofstream g_debugLogFile;
std::map<DWORD, SuspiciousNetworkInfo> g_threadSuspiciousNetworkActivity;
std::map<HANDLE, std::wstring> g_handleToPath;
std::map<std::string, int> g_alertCount;

// Original API function pointers
HANDLE(WINAPI* Real_CreateFileW)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE) = CreateFileW;
HANDLE(WINAPI* Real_CreateFileA)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE) = CreateFileA;
BOOL(WINAPI* Real_WriteFile)(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED) = WriteFile;
BOOL(WINAPI* Real_CloseHandle)(HANDLE) = CloseHandle;
BOOL(WINAPI* Real_CreateProcessW)(LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION) = CreateProcessW;
BOOL(WINAPI* Real_CreateProcessA)(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION) = CreateProcessA;
LONG(WINAPI* Real_RegOpenKeyExW)(HKEY, LPCWSTR, DWORD, REGSAM, PHKEY) = RegOpenKeyExW;
LONG(WINAPI* Real_RegOpenKeyExA)(HKEY, LPCSTR, DWORD, REGSAM, PHKEY) = RegOpenKeyExA;
LONG(WINAPI* Real_RegSetValueExW)(HKEY, LPCWSTR, DWORD, DWORD, CONST BYTE*, DWORD) = RegSetValueExW;
LONG(WINAPI* Real_RegSetValueExA)(HKEY, LPCSTR, DWORD, DWORD, CONST BYTE*, DWORD) = RegSetValueExA;
int(WSAAPI* Real_connect)(SOCKET, const struct sockaddr*, int) = connect;
HINTERNET(WINAPI* Real_HttpOpenRequestW)(HINTERNET, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR*, DWORD, DWORD_PTR) = HttpOpenRequestW;
HINTERNET(WINAPI* Real_InternetConnectW)(HINTERNET, LPCWSTR, INTERNET_PORT, LPCWSTR, LPCWSTR, DWORD, DWORD, DWORD_PTR) = InternetConnectW;
HMODULE(WINAPI* Real_LoadLibraryW)(LPCWSTR) = LoadLibraryW;
HMODULE(WINAPI* Real_LoadLibraryA)(LPCSTR) = LoadLibraryA;
HMODULE(WINAPI* Real_LoadLibraryExW)(LPCWSTR, HANDLE, DWORD) = LoadLibraryExW;
LPVOID(WINAPI* Real_VirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD) = VirtualAlloc;
BOOL(WINAPI* Real_VirtualProtect)(LPVOID, SIZE_T, DWORD, PDWORD) = VirtualProtect;

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        // Load configuration, initialize hooks, and set up logging
        LoadConfiguration();
        InitializeLogging();
        InitializeHooks();
        HookDebugLog("DLL injected successfully into process %d", GetCurrentProcessId());
        break;
    case DLL_THREAD_ATTACH:
        break;
    case DLL_THREAD_DETACH:
        break;
    case DLL_PROCESS_DETACH:
        // Clean up hooks and close logs
        FinalizeHooks();
        CloseLogging();
        break;
    }
    return TRUE;
}

bool InitializeHooks()
{
    // Initialize Detours for hooking
    DetourRestoreAfterWith();
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());

    // Hook each API function if its category is enabled in configuration
    if (g_config.monitorFileOperations) {
        DetourAttach(&(PVOID&)Real_CreateFileW, Hooked_CreateFileW);
        DetourAttach(&(PVOID&)Real_CreateFileA, Hooked_CreateFileA);
        DetourAttach(&(PVOID&)Real_WriteFile, Hooked_WriteFile);
        DetourAttach(&(PVOID&)Real_CloseHandle, Hooked_CloseHandle);
        HookDebugLog("File operation hooks installed");
    }

    if (g_config.monitorProcessOperations) {
        DetourAttach(&(PVOID&)Real_CreateProcessW, Hooked_CreateProcessW);
        DetourAttach(&(PVOID&)Real_CreateProcessA, Hooked_CreateProcessA);
        HookDebugLog("Process operation hooks installed");
    }

    if (g_config.monitorRegistryOperations) {
        DetourAttach(&(PVOID&)Real_RegOpenKeyExW, Hooked_RegOpenKeyExW);
        DetourAttach(&(PVOID&)Real_RegOpenKeyExA, Hooked_RegOpenKeyExA);
        DetourAttach(&(PVOID&)Real_RegSetValueExW, Hooked_RegSetValueExW);
        DetourAttach(&(PVOID&)Real_RegSetValueExA, Hooked_RegSetValueExA);
        HookDebugLog("Registry operation hooks installed");
    }

    if (g_config.monitorNetworkOperations) {
        DetourAttach(&(PVOID&)Real_connect, Hooked_connect);
        DetourAttach(&(PVOID&)Real_HttpOpenRequestW, Hooked_HttpOpenRequestW);
        DetourAttach(&(PVOID&)Real_InternetConnectW, Hooked_InternetConnectW);
        HookDebugLog("Network operation hooks installed");
    }

    if (g_config.monitorDllOperations) {
        DetourAttach(&(PVOID&)Real_LoadLibraryW, Hooked_LoadLibraryW);
        DetourAttach(&(PVOID&)Real_LoadLibraryA, Hooked_LoadLibraryA);
        DetourAttach(&(PVOID&)Real_LoadLibraryExW, Hooked_LoadLibraryExW);
        HookDebugLog("DLL operation hooks installed");
    }

    if (g_config.monitorMemoryOperations) {
        DetourAttach(&(PVOID&)Real_VirtualAlloc, Hooked_VirtualAlloc);
        DetourAttach(&(PVOID&)Real_VirtualProtect, Hooked_VirtualProtect);
        HookDebugLog("Memory operation hooks installed");
    }

    // Commit the transaction
    LONG error = DetourTransactionCommit();
    if (error != NO_ERROR) {
        HookDebugLog("Error installing hooks: %d", error);
        return false;
    }

    HookDebugLog("All hooks installed successfully");
    return true;
}

void FinalizeHooks()
{
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());

    // Unhook each API function if its category is enabled in configuration
    if (g_config.monitorFileOperations) {
        DetourDetach(&(PVOID&)Real_CreateFileW, Hooked_CreateFileW);
        DetourDetach(&(PVOID&)Real_CreateFileA, Hooked_CreateFileA);
        DetourDetach(&(PVOID&)Real_WriteFile, Hooked_WriteFile);
        DetourDetach(&(PVOID&)Real_CloseHandle, Hooked_CloseHandle);
    }

    if (g_config.monitorProcessOperations) {
        DetourDetach(&(PVOID&)Real_CreateProcessW, Hooked_CreateProcessW);
        DetourDetach(&(PVOID&)Real_CreateProcessA, Hooked_CreateProcessA);
    }

    if (g_config.monitorRegistryOperations) {
        DetourDetach(&(PVOID&)Real_RegOpenKeyExW, Hooked_RegOpenKeyExW);
        DetourDetach(&(PVOID&)Real_RegOpenKeyExA, Hooked_RegOpenKeyExA);
        DetourDetach(&(PVOID&)Real_RegSetValueExW, Hooked_RegSetValueExW);
        DetourDetach(&(PVOID&)Real_RegSetValueExA, Hooked_RegSetValueExA);
    }

    if (g_config.monitorNetworkOperations) {
        DetourDetach(&(PVOID&)Real_connect, Hooked_connect);
        DetourDetach(&(PVOID&)Real_HttpOpenRequestW, Hooked_HttpOpenRequestW);
        DetourDetach(&(PVOID&)Real_InternetConnectW, Hooked_InternetConnectW);
    }

    if (g_config.monitorDllOperations) {
        DetourDetach(&(PVOID&)Real_LoadLibraryW, Hooked_LoadLibraryW);
        DetourDetach(&(PVOID&)Real_LoadLibraryA, Hooked_LoadLibraryA);
        DetourDetach(&(PVOID&)Real_LoadLibraryExW, Hooked_LoadLibraryExW);
    }

    if (g_config.monitorMemoryOperations) {
        DetourDetach(&(PVOID&)Real_VirtualAlloc, Hooked_VirtualAlloc);
        DetourDetach(&(PVOID&)Real_VirtualProtect, Hooked_VirtualProtect);
    }

    DetourTransactionCommit();
    HookDebugLog("All hooks removed");
} 