#include "../include/OfficeApiHook.h"
#include <windows.h>
#include <string>
#include <sstream>
#include <regex>

// Hooked LoadLibraryW
HMODULE WINAPI Hooked_LoadLibraryW(LPCWSTR lpLibFileName) {
    // Skip logging for null library names
    if (lpLibFileName == NULL) {
        return Real_LoadLibraryW(lpLibFileName);
    }

    // Skip monitoring if DLL operations are disabled
    if (!g_config.monitorDllOperations) {
        return Real_LoadLibraryW(lpLibFileName);
    }
    
    // PRE-CALL CHECKS
    std::wstring dllPath(lpLibFileName);
    bool isSuspicious = IsSuspiciousDll(dllPath);
    bool isWhitelisted = false;
    std::string blockReason;

    // Check Whitelist
    for (const auto& pattern : g_config.whitelistedDlls) {
        try {
            if (std::regex_search(dllPath, pattern)) {
                isWhitelisted = true;
                break;
            }
        } catch (...) { /* Ignore regex errors */ }
    }

    // Determine if blocking is needed
    bool shouldBlock = isSuspicious && !isWhitelisted && (g_config.actionOnSuspicious >= ACTION_BLOCK_ERROR);

    if (shouldBlock) {
        blockReason = "Suspicious DLL load denied: " + WideToUTF8(dllPath);
        std::stringstream blockDetails;
        blockDetails << "LibraryName: " << WideToUTF8(dllPath) << std::endl;
        LogBlockedOperation(DLL_OPERATIONS, "LoadLibraryW", blockReason, blockDetails.str());

        if (g_config.actionOnSuspicious == ACTION_TERMINATE_THREAD) { TerminateThread(GetCurrentThread(), 1); }
        else if (g_config.actionOnSuspicious == ACTION_TERMINATE_PROCESS) { TerminateProcess(GetCurrentProcess(), 1); }

        SetLastError(ERROR_ACCESS_DENIED);
        return NULL;
    }

    // If not blocking, proceed
    HMODULE hResult = Real_LoadLibraryW(lpLibFileName);
    DWORD lastError = GetLastError();
    
    // POST-CALL LOGGING & ALERTS (Only if NOT whitelisted)
    if (!isWhitelisted) {
        std::stringstream details;
        details << "LibraryName: " << WideToUTF8(lpLibFileName) << std::endl;
        details << "Result: " << (hResult ? "SUCCESS" : "FAILED") << std::endl;
        details << "Result Handle: 0x" << std::hex << (DWORD_PTR)hResult << std::dec << std::endl;
        if (!hResult) {
            details << "LastError: " << lastError << std::endl;
        }
        LogApiCall(DLL_OPERATIONS, "LoadLibraryW", details.str());

        if (isSuspicious && hResult) {
            std::stringstream alertDetails;
            alertDetails << "Suspicious DLL Loaded (Allowed):" << std::endl;
            alertDetails << "DLL: " << WideToUTF8(lpLibFileName) << std::endl;
            alertDetails << "Process: " << WideToUTF8(GetProcessImageName()) << " (PID: " << GetCurrentProcessId() << ")" << std::endl;
            RaiseAlert(DLL_OPERATIONS, "Suspicious DLL Loaded (Allowed)", alertDetails.str());
        }
    }
    
    SetLastError(lastError);
    return hResult;
}

// Hooked LoadLibraryA
HMODULE WINAPI Hooked_LoadLibraryA(LPCSTR lpLibFileName) {
    // Skip logging for null library names
    if (lpLibFileName == NULL) {
        return Real_LoadLibraryA(lpLibFileName);
    }
    
    // Skip monitoring if DLL operations are disabled
    if (!g_config.monitorDllOperations) {
        return Real_LoadLibraryA(lpLibFileName);
    }
    
    std::wstring wideLibFileName = UTF8ToWide(lpLibFileName);

    // PRE-CALL CHECKS
    bool isSuspicious = IsSuspiciousDll(wideLibFileName);
    bool isWhitelisted = false;
    std::string blockReason;

    for (const auto& pattern : g_config.whitelistedDlls) {
        try {
            if (std::regex_search(wideLibFileName, pattern)) {
                isWhitelisted = true;
                break;
            }
        } catch (...) { /* Ignore regex errors */ }
    }

    bool shouldBlock = isSuspicious && !isWhitelisted && (g_config.actionOnSuspicious >= ACTION_BLOCK_ERROR);

    if (shouldBlock) {
        blockReason = "Suspicious DLL load denied: " + std::string(lpLibFileName);
        std::stringstream blockDetails;
        blockDetails << "LibraryName: " << lpLibFileName << std::endl;
        LogBlockedOperation(DLL_OPERATIONS, "LoadLibraryA", blockReason, blockDetails.str());

        if (g_config.actionOnSuspicious == ACTION_TERMINATE_THREAD) { TerminateThread(GetCurrentThread(), 1); }
        else if (g_config.actionOnSuspicious == ACTION_TERMINATE_PROCESS) { TerminateProcess(GetCurrentProcess(), 1); }

        SetLastError(ERROR_ACCESS_DENIED); 
        return NULL;
    }

    // If not blocking, proceed
    HMODULE hResult = Real_LoadLibraryA(lpLibFileName);
    DWORD lastError = GetLastError();

    // POST-CALL LOGGING & ALERTS (Only if NOT whitelisted)
    if (!isWhitelisted) {
        std::stringstream details;
        details << "LibraryName: " << lpLibFileName << std::endl;
        details << "Result: " << (hResult ? "SUCCESS" : "FAILED") << std::endl;
        details << "Result Handle: 0x" << std::hex << (DWORD_PTR)hResult << std::dec << std::endl;
        if (!hResult) {
             details << "LastError: " << lastError << std::endl;
        }
        LogApiCall(DLL_OPERATIONS, "LoadLibraryA", details.str());

        if (isSuspicious && hResult) {
            std::stringstream alertDetails;
            alertDetails << "Suspicious DLL loaded (Allowed):" << std::endl;
            alertDetails << "DLL: " << lpLibFileName << std::endl;
            alertDetails << "Process: " << WideToUTF8(GetProcessImageName()) << " (PID: " << GetCurrentProcessId() << ")" << std::endl;
            RaiseAlert(DLL_OPERATIONS, "Suspicious DLL Loaded (Allowed)", alertDetails.str());
        }
    }
    
    SetLastError(lastError);
    return hResult;
}

// Hooked LoadLibraryExW
HMODULE WINAPI Hooked_LoadLibraryExW(LPCWSTR lpLibFileName, HANDLE hFile, DWORD dwFlags) {
    // Skip logging for null library names
    if (lpLibFileName == NULL) {
        return Real_LoadLibraryExW(lpLibFileName, hFile, dwFlags);
    }

    // Skip monitoring if DLL operations are disabled
    if (!g_config.monitorDllOperations) {
        return Real_LoadLibraryExW(lpLibFileName, hFile, dwFlags);
    }
    
    std::wstring dllPath(lpLibFileName);

    // PRE-CALL CHECKS
    bool isSuspicious = IsSuspiciousDll(dllPath);
    bool isWhitelisted = false;
    std::string blockReason;

    for (const auto& pattern : g_config.whitelistedDlls) {
        try {
            if (std::regex_search(dllPath, pattern)) {
                isWhitelisted = true;
                break;
            }
        } catch (...) { /* Ignore regex errors */ }
    }

    bool shouldBlock = isSuspicious && !isWhitelisted && (g_config.actionOnSuspicious >= ACTION_BLOCK_ERROR);

    if (shouldBlock) {
        blockReason = "Suspicious DLL load denied: " + WideToUTF8(dllPath);
        std::stringstream blockDetails;
        blockDetails << "LibraryName: " << WideToUTF8(dllPath) << std::endl;
        blockDetails << "Flags: 0x" << std::hex << dwFlags << std::dec << std::endl; 
        // Add flags to block details
        LogBlockedOperation(DLL_OPERATIONS, "LoadLibraryExW", blockReason, blockDetails.str());

        if (g_config.actionOnSuspicious == ACTION_TERMINATE_THREAD) { TerminateThread(GetCurrentThread(), 1); }
        else if (g_config.actionOnSuspicious == ACTION_TERMINATE_PROCESS) { TerminateProcess(GetCurrentProcess(), 1); }

        SetLastError(ERROR_ACCESS_DENIED); 
        return NULL;
    }

    // If not blocking, proceed
    HMODULE hResult = Real_LoadLibraryExW(lpLibFileName, hFile, dwFlags);
    DWORD lastError = GetLastError();

    // POST-CALL LOGGING & ALERTS (Only if NOT whitelisted)
    if (!isWhitelisted) {
        std::stringstream flagsStr; // Keep flags string generation
        if (dwFlags & LOAD_LIBRARY_AS_DATAFILE) flagsStr << "AS_DATAFILE ";
        // ... (add other flags)
        std::stringstream details;
        details << "LibraryName: " << WideToUTF8(dllPath) << std::endl;
        details << "Flags: 0x" << std::hex << dwFlags << std::dec << " (" << flagsStr.str() << ")" << std::endl;
        details << "Result: " << (hResult ? "SUCCESS" : "FAILED") << std::endl;
        details << "Result Handle: 0x" << std::hex << (DWORD_PTR)hResult << std::dec << std::endl;
        if (!hResult) {
             details << "LastError: " << lastError << std::endl;
        }
        LogApiCall(DLL_OPERATIONS, "LoadLibraryExW", details.str());

        if (isSuspicious && hResult) {
            std::stringstream alertDetails;
            alertDetails << "Suspicious DLL loaded (Allowed):" << std::endl;
            alertDetails << "DLL: " << WideToUTF8(dllPath) << std::endl;
            alertDetails << "Flags: " << flagsStr.str() << std::endl;
            alertDetails << "Process: " << WideToUTF8(GetProcessImageName()) << " (PID: " << GetCurrentProcessId() << ")" << std::endl;
            RaiseAlert(DLL_OPERATIONS, "Suspicious DLL Loaded (Allowed)", alertDetails.str());
        }
    }
    
    SetLastError(lastError);
    return hResult;
} 