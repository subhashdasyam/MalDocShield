#include "../include/OfficeApiHook.h"
#include <windows.h>
#include <string>
#include <sstream>
#include <thread>

// Hooked CreateProcessW
BOOL WINAPI Hooked_CreateProcessW(
    LPCWSTR lpApplicationName,
    LPWSTR lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL bInheritHandles,
    DWORD dwCreationFlags,
    LPVOID lpEnvironment,
    LPCWSTR lpCurrentDirectory,
    LPSTARTUPINFOW lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation
) {
    // Skip monitoring if process operations are disabled
    if (!g_config.monitorProcessOperations) {
        return Real_CreateProcessW(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes,
                                  bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory,
                                  lpStartupInfo, lpProcessInformation);
    }
    
    // Get process details for pre-call check
    std::wstring appName = (lpApplicationName != NULL) ? lpApplicationName : L"";
    std::wstring cmdLine = (lpCommandLine != NULL) ? lpCommandLine : L"";
    std::wstring processName = L"<UNKNOWN>";
    if (!appName.empty() && appName != L"<NULL>") {
        processName = GetFileNameFromPath(appName);
    } else if (!cmdLine.empty() && cmdLine != L"<NULL>") {
        size_t firstSpace = cmdLine.find_first_of(L" ");
        if (firstSpace != std::wstring::npos) {
            processName = GetFileNameFromPath(cmdLine.substr(0, firstSpace));
        } else {
            processName = GetFileNameFromPath(cmdLine);
        }
    }
    
    // PRE-CALL CHECKS
    bool isSuspicious = IsSuspiciousProcess(processName);
    bool isWhitelisted = false;
    std::string blockReason;
    std::string utf8ProcName = WideToUTF8(processName);

    // Check Whitelist (compare against lowercase process name)
    std::string lowerProcName = utf8ProcName;
    std::transform(lowerProcName.begin(), lowerProcName.end(), lowerProcName.begin(), 
                   [](unsigned char c){ return my_tolower_safe(c); });
    for (const auto& whitelistedName : g_config.whitelistedProcesses) {
        std::string lowerWhitelisted = whitelistedName;
        std::transform(lowerWhitelisted.begin(), lowerWhitelisted.end(), lowerWhitelisted.begin(), 
                       [](unsigned char c){ return my_tolower_safe(c); });
        if (lowerProcName == lowerWhitelisted) {
            isWhitelisted = true;
            break;
        }
    }

    // Determine if blocking is needed
    bool shouldBlock = isSuspicious && !isWhitelisted && (g_config.actionOnSuspicious >= ACTION_BLOCK_ERROR);

    if (shouldBlock) {
        blockReason = "Suspicious process launch denied: " + utf8ProcName;
        std::stringstream blockDetails;
        blockDetails << "ApplicationName: ";
        if (lpApplicationName) { blockDetails << WideToUTF8(lpApplicationName); } else { blockDetails << "<NULL>"; }
        blockDetails << std::endl;

        blockDetails << "CommandLine: ";
        if (lpCommandLine) { blockDetails << WideToUTF8(lpCommandLine); } else { blockDetails << "<NULL>"; }
        blockDetails << std::endl;
        
        blockDetails << "ProcessName: " << utf8ProcName << std::endl;
        blockDetails << "CreationFlags: 0x" << std::hex << dwCreationFlags << std::dec << std::endl;
        
        blockDetails << "CurrentDirectory: ";
        if (lpCurrentDirectory) { blockDetails << WideToUTF8(lpCurrentDirectory); } else { blockDetails << "<NULL>"; }
        blockDetails << std::endl;

        // blockDetails << "Process ID: " << lpProcessInformation->dwProcessId << std::endl; // PID not available yet if blocking
        // blockDetails << "Thread ID: " << lpProcessInformation->dwThreadId << std::endl; // TID not available yet if blocking
        LogBlockedOperation(PROCESS_OPERATIONS, "CreateProcessW", blockReason, blockDetails.str());

        if (g_config.actionOnSuspicious == ACTION_TERMINATE_THREAD) { TerminateThread(GetCurrentThread(), 1); }
        else if (g_config.actionOnSuspicious == ACTION_TERMINATE_PROCESS) { TerminateProcess(GetCurrentProcess(), 1); }

        SetLastError(ERROR_ACCESS_DENIED); 
        return FALSE; // Return FALSE for CreateProcess failure
    }

    // If not blocking, proceed with original call (keeping suspend flag logic)
    DWORD originalFlags = dwCreationFlags;
    dwCreationFlags |= CREATE_SUSPENDED;
    BOOL result = Real_CreateProcessW(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes,
                                     bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory,
                                     lpStartupInfo, lpProcessInformation);
    DWORD lastError = GetLastError();
    
    // POST-CALL LOGGING & ALERTS (Only if NOT whitelisted)
    if (result && !isWhitelisted) { // Only log/alert if create succeeded and not whitelisted
        std::stringstream details;
        details << "ApplicationName: " << WideToUTF8(appName) << std::endl;
        details << "CommandLine: " << WideToUTF8(cmdLine) << std::endl;
        details << "ProcessName: " << WideToUTF8(processName) << std::endl;
        details << "CreationFlags: 0x" << std::hex << originalFlags << std::dec << std::endl;
        details << "CurrentDirectory: " << (lpCurrentDirectory ? WideToUTF8(lpCurrentDirectory) : "<NULL>") << std::endl;
        details << "Process ID: " << lpProcessInformation->dwProcessId << std::endl;
        details << "Thread ID: " << lpProcessInformation->dwThreadId << std::endl;
        details << "Result: SUCCESS" << std::endl;
        LogApiCall(PROCESS_OPERATIONS, "CreateProcessW", details.str());

        std::wstring parentProcessName = GetProcessImageName();

        // Raise standard alert if suspicious (but wasn't blocked)
        if (isSuspicious) {
            std::stringstream alertDetails;
            alertDetails << "Suspicious process launched:" << std::endl;
            alertDetails << "Process: " << WideToUTF8(processName) << std::endl;
            alertDetails << "Command: " << WideToUTF8(cmdLine) << std::endl;
            alertDetails << "Parent: " << WideToUTF8(parentProcessName) << " (PID: " << GetCurrentProcessId() << ")" << std::endl;
            RaiseAlert(PROCESS_OPERATIONS, "Suspicious Process Launch (Allowed)", alertDetails.str());
        }
        
        // Auto-injection logic (remains the same)
        bool shouldInject = (_wcsicmp(processName.c_str(), parentProcessName.c_str()) == 0);
        if (shouldInject) {
            HookDebugLog("Auto-injection triggered for child process with same name: %ws (PID: %d)", 
                     processName.c_str(), lpProcessInformation->dwProcessId);
            
            // Create a thread to handle the injection (using DWORD_PTR cast)
            HANDLE hInjectionThread = CreateThread(NULL, 0, InjectionThreadProc, 
                                                   reinterpret_cast<LPVOID>(static_cast<DWORD_PTR>(lpProcessInformation->dwProcessId)), 
                                                   0, NULL);
            if (hInjectionThread) {
                CloseHandle(hInjectionThread);
            }
        }
    }
    else if (!result) { // Log failure only if it wasn't blocked
        // Log failure details if CreateProcess failed for a non-blocked attempt
        std::stringstream details;
        details << "ApplicationName: " << (lpApplicationName ? WideToUTF8(lpApplicationName) : "<NULL>") << std::endl;
        details << "CommandLine: " << (lpCommandLine ? WideToUTF8(lpCommandLine) : "<NULL>") << std::endl;
        details << "ProcessName: " << WideToUTF8(processName) << std::endl;
        details << "CreationFlags: 0x" << std::hex << originalFlags << std::dec << std::endl;
        details << "CurrentDirectory: " << (lpCurrentDirectory ? WideToUTF8(lpCurrentDirectory) : "<NULL>") << std::endl;
        details << "Process ID: " << lpProcessInformation->dwProcessId << std::endl;
        details << "Thread ID: " << lpProcessInformation->dwThreadId << std::endl;
        details << "Result: FAILED" << std::endl;
        details << "LastError: " << lastError << std::endl;
        LogApiCall(PROCESS_OPERATIONS, "CreateProcessW", details.str());
    }

    // Resume the process if it was successfully created and not originally suspended
    if (result && !(originalFlags & CREATE_SUSPENDED)) {
        ResumeThread(lpProcessInformation->hThread);
    }

    SetLastError(lastError); // Restore original error code
    return result;
}

// Hooked CreateProcessA
BOOL WINAPI Hooked_CreateProcessA(
    LPCSTR lpApplicationName,
    LPSTR lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL bInheritHandles,
    DWORD dwCreationFlags,
    LPVOID lpEnvironment,
    LPCSTR lpCurrentDirectory,
    LPSTARTUPINFOA lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation
) {
    // Skip monitoring if process operations are disabled
    if (!g_config.monitorProcessOperations) {
        return Real_CreateProcessA(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes,
                                  bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory,
                                  lpStartupInfo, lpProcessInformation);
    }
    
    // Get process details for pre-call check
    std::wstring wideAppName = (lpApplicationName != NULL) ? UTF8ToWide(lpApplicationName) : L"";
    std::wstring wideCmdLine = (lpCommandLine != NULL) ? UTF8ToWide(lpCommandLine) : L"";
    std::wstring processName = L"<UNKNOWN>";
    if (!wideAppName.empty()) {
        processName = GetFileNameFromPath(wideAppName);
    } else if (!wideCmdLine.empty()) {
        size_t firstSpace = wideCmdLine.find_first_of(L" ");
        if (firstSpace != std::wstring::npos) {
            processName = GetFileNameFromPath(wideCmdLine.substr(0, firstSpace));
        } else {
            processName = GetFileNameFromPath(wideCmdLine);
        }
    }
    
    // PRE-CALL CHECKS
    bool isSuspicious = IsSuspiciousProcess(processName);
    bool isWhitelisted = false;
    std::string blockReason;
    std::string utf8ProcName = WideToUTF8(processName);

    // Check Whitelist (compare against lowercase process name)
    std::string lowerProcName = utf8ProcName;
    std::transform(lowerProcName.begin(), lowerProcName.end(), lowerProcName.begin(), 
                   [](unsigned char c){ return my_tolower_safe(c); });
    for (const auto& whitelistedName : g_config.whitelistedProcesses) {
        std::string lowerWhitelisted = whitelistedName;
        std::transform(lowerWhitelisted.begin(), lowerWhitelisted.end(), lowerWhitelisted.begin(), 
                       [](unsigned char c){ return my_tolower_safe(c); });
        if (lowerProcName == lowerWhitelisted) {
            isWhitelisted = true;
            break;
        }
    }

    // Determine if blocking is needed
    bool shouldBlock = isSuspicious && !isWhitelisted && (g_config.actionOnSuspicious >= ACTION_BLOCK_ERROR);

    if (shouldBlock) {
        blockReason = "Suspicious process launch denied: " + utf8ProcName;
        std::stringstream blockDetails;
        blockDetails << "ApplicationName: " << (lpApplicationName ? lpApplicationName : "<NULL>") << std::endl;
        blockDetails << "CommandLine: " << (lpCommandLine ? lpCommandLine : "<NULL>") << std::endl;
        blockDetails << "ProcessName: " << WideToUTF8(processName) << std::endl;
        blockDetails << "CreationFlags: 0x" << std::hex << dwCreationFlags << std::dec << std::endl;
        blockDetails << "CurrentDirectory: " << (lpCurrentDirectory ? lpCurrentDirectory : "<NULL>") << std::endl;
        blockDetails << "Process ID: " << lpProcessInformation->dwProcessId << std::endl;
        blockDetails << "Thread ID: " << lpProcessInformation->dwThreadId << std::endl;
        LogBlockedOperation(PROCESS_OPERATIONS, "CreateProcessA", blockReason, blockDetails.str());

        if (g_config.actionOnSuspicious == ACTION_TERMINATE_THREAD) { TerminateThread(GetCurrentThread(), 1); }
        else if (g_config.actionOnSuspicious == ACTION_TERMINATE_PROCESS) { TerminateProcess(GetCurrentProcess(), 1); }

        SetLastError(ERROR_ACCESS_DENIED);
        return FALSE;
    }

    // If not blocking, proceed (keeping suspend flag logic)
    DWORD originalFlags = dwCreationFlags;
    dwCreationFlags |= CREATE_SUSPENDED;
    BOOL result = Real_CreateProcessA(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes,
                                     bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory,
                                     lpStartupInfo, lpProcessInformation);
    DWORD lastError = GetLastError();
    
    // POST-CALL LOGGING & ALERTS (Only if NOT whitelisted)
    if (result && !isWhitelisted) {
        std::stringstream details;
        details << "ApplicationName: " << (lpApplicationName ? lpApplicationName : "<NULL>") << std::endl;
        details << "CommandLine: " << (lpCommandLine ? lpCommandLine : "<NULL>") << std::endl;
        details << "ProcessName: " << WideToUTF8(processName) << std::endl;
        details << "CreationFlags: 0x" << std::hex << originalFlags << std::dec << std::endl;
        details << "CurrentDirectory: " << (lpCurrentDirectory ? lpCurrentDirectory : "<NULL>") << std::endl;
        details << "Process ID: " << lpProcessInformation->dwProcessId << std::endl;
        details << "Thread ID: " << lpProcessInformation->dwThreadId << std::endl;
        details << "Result: SUCCESS" << std::endl;
        LogApiCall(PROCESS_OPERATIONS, "CreateProcessA", details.str());

        std::wstring parentProcessName = GetProcessImageName();

        if (isSuspicious) {
            std::stringstream alertDetails;
            alertDetails << "Suspicious process launched:" << std::endl;
            alertDetails << "Process: " << WideToUTF8(processName) << std::endl;
            alertDetails << "Command: " << (lpCommandLine ? lpCommandLine : "<NULL>") << std::endl;
            alertDetails << "Parent: " << WideToUTF8(parentProcessName) << " (PID: " << GetCurrentProcessId() << ")" << std::endl;
            RaiseAlert(PROCESS_OPERATIONS, "Suspicious Process Launch (Allowed)", alertDetails.str());
        }
        
        // Auto-injection logic
        bool shouldInject = (_wcsicmp(processName.c_str(), parentProcessName.c_str()) == 0);
        if (shouldInject) {
            HookDebugLog("Auto-injection triggered for child process with same name: %ws (PID: %d)", 
                 processName.c_str(), lpProcessInformation->dwProcessId);
            
            // Create a thread to handle the injection (using DWORD_PTR cast)
            HANDLE hInjectionThread = CreateThread(NULL, 0, InjectionThreadProc, 
                                                   reinterpret_cast<LPVOID>(static_cast<DWORD_PTR>(lpProcessInformation->dwProcessId)), 
                                                   0, NULL);
            if (hInjectionThread) {
                CloseHandle(hInjectionThread);
            }
        }
    }
    else if (!result) { // Log failure only if it wasn't blocked
        std::stringstream details;
        details << "ApplicationName: " << (lpApplicationName ? lpApplicationName : "<NULL>") << std::endl;
        details << "CommandLine: " << (lpCommandLine ? lpCommandLine : "<NULL>") << std::endl;
        details << "ProcessName: " << WideToUTF8(processName) << std::endl;
        details << "CreationFlags: 0x" << std::hex << originalFlags << std::dec << std::endl;
        details << "CurrentDirectory: " << (lpCurrentDirectory ? lpCurrentDirectory : "<NULL>") << std::endl;
        details << "Process ID: " << lpProcessInformation->dwProcessId << std::endl;
        details << "Thread ID: " << lpProcessInformation->dwThreadId << std::endl;
        details << "Result: FAILED" << std::endl;
        details << "LastError: " << lastError << std::endl;
        LogApiCall(PROCESS_OPERATIONS, "CreateProcessA", details.str());
    }

    // Resume the process
    if (result && !(originalFlags & CREATE_SUSPENDED)) {
        ResumeThread(lpProcessInformation->hThread);
    }

    SetLastError(lastError);
    return result;
} 