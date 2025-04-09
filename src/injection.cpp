#include "../include/OfficeApiHook.h"
#include <windows.h>
#include <string>
#include <thread>

// Get the DLL path for injection
std::wstring GetDllPathForInjection() {
    wchar_t dllPath[MAX_PATH] = { 0 };
    GetModuleFileNameW(GetModuleHandleA("Dll1.dll"), dllPath, MAX_PATH);
    return std::wstring(dllPath);
}

// Thread procedure for injection
DWORD WINAPI InjectionThreadProc(LPVOID lpParameter) {
    // Extract the process ID from the parameter (cast via DWORD_PTR)
    DWORD processId = static_cast<DWORD>(reinterpret_cast<DWORD_PTR>(lpParameter));
    
    HookDebugLog("Injection thread started for process ID: %d", processId);
    
    // Sleep briefly to allow the target process to initialize
    Sleep(500);
    
    // Inject the DLL into the target process
    InjectIntoProcess(processId);
    
    return 0;
}

// Inject the DLL into a target process
void InjectIntoProcess(DWORD processId) {
    HookDebugLog("Attempting to inject into process ID: %d", processId);
    
    // Open the target process
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    if (hProcess == NULL) {
        HookDebugLog("Failed to open process for injection. Error: %d", GetLastError());
        return;
    }
    
    // Get the DLL path
    std::wstring dllPath = GetDllPathForInjection();
    std::string utf8DllPath = WideToUTF8(dllPath);
    
    HookDebugLog("Injecting DLL: %s", utf8DllPath.c_str());
    
    // Calculate the size of the DLL path string (including null terminator)
    SIZE_T dllPathSize = (utf8DllPath.length() + 1) * sizeof(char);
    
    // Allocate memory in the target process for the DLL path
    LPVOID remoteDllPath = VirtualAllocEx(hProcess, NULL, dllPathSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (remoteDllPath == NULL) {
        HookDebugLog("Failed to allocate memory in target process. Error: %d", GetLastError());
        CloseHandle(hProcess);
        return;
    }
    
    // Write the DLL path to the allocated memory
    if (!WriteProcessMemory(hProcess, remoteDllPath, utf8DllPath.c_str(), dllPathSize, NULL)) {
        HookDebugLog("Failed to write DLL path to target process. Error: %d", GetLastError());
        VirtualFreeEx(hProcess, remoteDllPath, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return;
    }
    
    // Get the address of LoadLibraryA
    LPVOID loadLibraryAddr = reinterpret_cast<LPVOID>(GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA"));
    if (loadLibraryAddr == NULL) {
        HookDebugLog("Failed to get LoadLibraryA address. Error: %d", GetLastError());
        VirtualFreeEx(hProcess, remoteDllPath, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return;
    }
    
    // Create a remote thread to load the DLL
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(loadLibraryAddr), remoteDllPath, 0, NULL);
    if (hThread == NULL) {
        HookDebugLog("Failed to create remote thread. Error: %d", GetLastError());
        VirtualFreeEx(hProcess, remoteDllPath, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return;
    }
    
    // Wait for the remote thread to complete
    WaitForSingleObject(hThread, INFINITE);
    
    // Get the thread exit code (handle to the loaded DLL or NULL on failure)
    DWORD exitCode = 0;
    GetExitCodeThread(hThread, &exitCode);
    
    if (exitCode == 0) {
        HookDebugLog("LoadLibrary failed in the target process");
    } else {
        HookDebugLog("Successfully injected DLL into process ID: %d", processId);
    }
    
    // Clean up
    CloseHandle(hThread);
    VirtualFreeEx(hProcess, remoteDllPath, 0, MEM_RELEASE);
    CloseHandle(hProcess);
} 