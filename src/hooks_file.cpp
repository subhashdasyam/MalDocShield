#include "../include/OfficeApiHook.h"
#include <windows.h>
#include <string>
#include <sstream>
#include <vector>
#include <chrono>

// Hooked CreateFileW
HANDLE WINAPI Hooked_CreateFileW(
    LPCWSTR lpFileName,
    DWORD dwDesiredAccess,
    DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes,
    HANDLE hTemplateFile
) {
    // Skip logging/detection for null or invalid paths
    if (lpFileName == NULL || lpFileName[0] == L'\0') {
        return Real_CreateFileW(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, 
                                dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
    }
    
    // Skip monitoring if file operations are disabled
    if (!g_config.monitorFileOperations) {
        return Real_CreateFileW(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, 
                                dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
    }
    
    // PRE-CALL CHECKS
    std::wstring filePath(lpFileName);
    bool isSuspicious = IsSuspiciousFilePath(filePath); // Check suspicious patterns
    bool isWhitelisted = false;
    std::string blockReason;

    // Check Whitelist
    for (const auto& pattern : g_config.whitelistedPaths) {
        try {
            if (std::regex_search(filePath, pattern)) {
                isWhitelisted = true;
                break;
            }
        } catch (...) { /* Ignore regex errors */ }
    }

    // Determine if blocking is needed (Suspicious AND NOT Whitelisted AND Configured to Block)
    bool shouldBlock = isSuspicious && !isWhitelisted && (g_config.actionOnSuspicious >= ACTION_BLOCK_ERROR);

    if (shouldBlock) {
        blockReason = "Suspicious file path access denied: " + WideToUTF8(filePath);
        
        // Build details for logging the block
        std::stringstream blockDetails;
        blockDetails << "FileName: " << WideToUTF8(filePath) << std::endl;
        blockDetails << "Access Requested: " << /* Format dwDesiredAccess */ std::hex << dwDesiredAccess << std::dec << std::endl;
        blockDetails << "Action: Blocked (Returning INVALID_HANDLE_VALUE)" << std::endl;
        blockDetails << "Process: " << WideToUTF8(GetProcessImageName()) << " (PID: " << GetCurrentProcessId() << ")" << std::endl;
        
        // Log the blocked operation (flushes log)
        LogBlockedOperation(FILE_OPERATIONS, "CreateFileW", blockReason, blockDetails.str());

        // Perform configured action
        if (g_config.actionOnSuspicious == ACTION_TERMINATE_THREAD) {
            TerminateThread(GetCurrentThread(), 1);
        }
        else if (g_config.actionOnSuspicious == ACTION_TERMINATE_PROCESS) {
            TerminateProcess(GetCurrentProcess(), 1);
        }

        // For ACTION_BLOCK_ERROR, set error and return invalid handle
        SetLastError(ERROR_ACCESS_DENIED);
        return INVALID_HANDLE_VALUE;
    }

    // If not blocking, proceed with original call
    HANDLE hResult = Real_CreateFileW(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, 
                                      dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
    DWORD lastError = GetLastError(); // Capture error code immediately
    
    // POST-CALL LOGGING & ALERTS (Only if NOT whitelisted)
    if (!isWhitelisted) {
        std::string utf8FileName = WideToUTF8(filePath);
        // Build access rights string
        std::stringstream accessRights;
        if (dwDesiredAccess & GENERIC_READ) accessRights << "GENERIC_READ ";
        if (dwDesiredAccess & GENERIC_WRITE) accessRights << "GENERIC_WRITE ";
        if (dwDesiredAccess & GENERIC_EXECUTE) accessRights << "GENERIC_EXECUTE ";
        if (dwDesiredAccess & GENERIC_ALL) accessRights << "GENERIC_ALL ";
        
        // Build creation disposition string
        std::string disposition;
        switch (dwCreationDisposition) {
            case CREATE_ALWAYS: disposition = "CREATE_ALWAYS"; break;
            case CREATE_NEW: disposition = "CREATE_NEW"; break;
            case OPEN_ALWAYS: disposition = "OPEN_ALWAYS"; break;
            case OPEN_EXISTING: disposition = "OPEN_EXISTING"; break;
            case TRUNCATE_EXISTING: disposition = "TRUNCATE_EXISTING"; break;
            default: disposition = "UNKNOWN"; break;
        }
        
        // Build log details
        std::stringstream details;
        details << "FileName: " << utf8FileName << std::endl;
        details << "AccessRights: " << accessRights.str() << std::endl;
        details << "ShareMode: 0x" << std::hex << dwShareMode << std::dec << std::endl;
        details << "CreationDisposition: " << disposition << std::endl;
        details << "Result Handle: 0x" << std::hex << (DWORD_PTR)hResult << std::dec << std::endl;
        details << "LastError: " << lastError << std::endl;

        LogApiCall(FILE_OPERATIONS, "CreateFileW", details.str());

        // Raise standard alert if suspicious (but wasn't blocked)
        if (isSuspicious && hResult != INVALID_HANDLE_VALUE) {
            std::stringstream alertDetails;
            alertDetails << "Suspicious file access:" << std::endl;
            alertDetails << "File: " << utf8FileName << std::endl;
            alertDetails << "Access: " << accessRights.str() << std::endl;
            alertDetails << "Process: " << WideToUTF8(GetProcessImageName()) << " (PID: " << GetCurrentProcessId() << ")" << std::endl;
            RaiseAlert(FILE_OPERATIONS, "Suspicious File Access (Allowed)", alertDetails.str());
        }
    }
    
    // Store handle-to-path mapping regardless of whitelist status
    if (hResult != INVALID_HANDLE_VALUE) {
        g_handleToPath[hResult] = filePath;
    }
    
    SetLastError(lastError); // Restore original error code before returning
    return hResult;
}

// Hooked CreateFileA
HANDLE WINAPI Hooked_CreateFileA(
    LPCSTR lpFileName,
    DWORD dwDesiredAccess,
    DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes,
    HANDLE hTemplateFile
) {
    // Skip logging/detection for null or invalid paths
    if (lpFileName == NULL || lpFileName[0] == '\0') {
        return Real_CreateFileA(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, 
                                dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
    }
    
    // Skip monitoring if file operations are disabled
    if (!g_config.monitorFileOperations) {
        return Real_CreateFileA(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, 
                                dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
    }

    std::wstring wideFilePath = UTF8ToWide(lpFileName);

    // PRE-CALL CHECKS (similar to CreateFileW)
    bool isSuspicious = IsSuspiciousFilePath(wideFilePath);
    bool isWhitelisted = false;
    std::string blockReason;

    for (const auto& pattern : g_config.whitelistedPaths) {
        try {
            if (std::regex_search(wideFilePath, pattern)) {
                isWhitelisted = true;
                break;
            }
        } catch (...) { /* Ignore regex errors */ }
    }

    bool shouldBlock = isSuspicious && !isWhitelisted && (g_config.actionOnSuspicious >= ACTION_BLOCK_ERROR);

    if (shouldBlock) {
        blockReason = "Suspicious file path access denied: " + std::string(lpFileName);
        std::stringstream blockDetails;
        blockDetails << "FileName: " << lpFileName << std::endl;
        // ... (fill blockDetails)
        LogBlockedOperation(FILE_OPERATIONS, "CreateFileA", blockReason, blockDetails.str());

        if (g_config.actionOnSuspicious == ACTION_TERMINATE_THREAD) { TerminateThread(GetCurrentThread(), 1); }
        else if (g_config.actionOnSuspicious == ACTION_TERMINATE_PROCESS) { TerminateProcess(GetCurrentProcess(), 1); }

        SetLastError(ERROR_ACCESS_DENIED);
        return INVALID_HANDLE_VALUE;
    }

    // If not blocking, proceed
    HANDLE hResult = Real_CreateFileA(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, 
                                      dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
    DWORD lastError = GetLastError();
    
    // POST-CALL LOGGING & ALERTS (Only if NOT whitelisted)
    if (!isWhitelisted) {
        // ... (Build accessRights string) ...
        // ... (Build disposition string) ...
        std::stringstream details;
        // ... (populate details as before) ...
        details << "Result Handle: 0x" << std::hex << (DWORD_PTR)hResult << std::dec << std::endl;
        details << "LastError: " << lastError << std::endl;
        LogApiCall(FILE_OPERATIONS, "CreateFileA", details.str());

        if (isSuspicious && hResult != INVALID_HANDLE_VALUE) {
            std::stringstream alertDetails;
             // ... (populate alert details as before) ...
            RaiseAlert(FILE_OPERATIONS, "Suspicious File Access (Allowed)", alertDetails.str());
        }
    }
    
    // Store handle-to-path mapping
    if (hResult != INVALID_HANDLE_VALUE) {
        g_handleToPath[hResult] = wideFilePath;
    }
    
    SetLastError(lastError);
    return hResult;
}

// Hooked WriteFile
BOOL WINAPI Hooked_WriteFile(
    HANDLE hFile,
    LPCVOID lpBuffer,
    DWORD nNumberOfBytesToWrite,
    LPDWORD lpNumberOfBytesWritten,
    LPOVERLAPPED lpOverlapped
) {
    // Skip monitoring if file operations are disabled
    if (!g_config.monitorFileOperations) {
        return Real_WriteFile(hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped);
    }
    
    // Initial checks
    if (hFile == INVALID_HANDLE_VALUE || lpBuffer == NULL || nNumberOfBytesToWrite == 0) {
         return Real_WriteFile(hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped);
    }

    // Skip non-disk files
    if (GetFileType(hFile) != FILE_TYPE_DISK) {
        return Real_WriteFile(hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped);
    }

    std::wstring filePath = L"<unknown>";
    auto it = g_handleToPath.find(hFile);
    if (it != g_handleToPath.end()) {
        filePath = it->second;
    }

    // Check Whitelist (using path from CreateFile)
    bool isWhitelisted = false;
    if (filePath != L"<unknown>") {
        for (const auto& pattern : g_config.whitelistedPaths) {
            try {
                if (std::regex_search(filePath, pattern)) {
                    isWhitelisted = true;
                    break;
                }
            } catch (...) { /* Ignore regex errors */ }
        }
    }

    // Call original function FIRST for WriteFile, as we need the result/bytes written for analysis
    BOOL result = Real_WriteFile(hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped);
    DWORD lastError = GetLastError();
    DWORD bytesWritten = (result && lpNumberOfBytesWritten) ? *lpNumberOfBytesWritten : 0;

    // Log the basic call details (even if whitelisted, for tracing)
    std::stringstream details;
    details << "File: " << WideToUTF8(filePath) << std::endl;
    details << "BytesToWrite: " << nNumberOfBytesToWrite << std::endl;
    details << "BytesWritten: " << bytesWritten << std::endl;
    details << "Result: " << (result ? "SUCCESS" : "FAILED") << std::endl;
    details << "LastError: " << lastError << std::endl;
    LogApiCall(FILE_OPERATIONS, "WriteFile", details.str());

    // POST-CALL ANALYSIS & ALERTING (Only if write succeeded, we have data, and NOT whitelisted)
    if (!isWhitelisted && result && bytesWritten > 0) {
        const BYTE* data = static_cast<const BYTE*>(lpBuffer);
        SIZE_T dataSize = bytesWritten;
        bool isContentSuspicious = false;
        std::stringstream suspiciousReasons;
        std::string fileHash = "N/A";

        // 1. Entropy Check
        double entropy = CalculateEntropy(data, dataSize);
        if (entropy > 7.5) {
            isContentSuspicious = true;
            suspiciousReasons << "- High entropy data (" << entropy << ")\n";
        }

        // 2. Keyword Check
        if (ContainsSuspiciousKeywords(data, dataSize)) {
            isContentSuspicious = true;
            suspiciousReasons << "- Contains suspicious keywords/scripts\n";
        }

        // 3. PE Header Check (if enabled)
        if (g_config.analyzePEHeaders && IsPEHeader(data, dataSize)) {
             isContentSuspicious = true;
             suspiciousReasons << "- Contains PE header (Executable code)\n";
        }

        // 4. Network Correlation Check
        DWORD threadId = GetCurrentThreadId();
        auto netActivityIt = g_threadSuspiciousNetworkActivity.find(threadId);
        if (netActivityIt != g_threadSuspiciousNetworkActivity.end()) {
            auto now = std::chrono::system_clock::now();
            auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - netActivityIt->second.time).count();
            if (elapsed < 10) { // Time window (e.g., 10 seconds)
                isContentSuspicious = true;
                suspiciousReasons << "- Follows recent suspicious network activity to [" 
                                  << netActivityIt->second.endpoint 
                                  << "] (" << elapsed << "s ago)\n";
            }
            // Optional: Remove the entry after correlation?
            // g_threadSuspiciousNetworkActivity.erase(netActivityIt);
        }
        
        // 5. Calculate Hash (if enabled)
        if (g_config.hashWrittenFiles) {
            fileHash = CalculateSHA256(data, dataSize);
        }

        // Raise Alert (WriteFile doesn't have a pre-call block, only post-call alert)
        if (isContentSuspicious) {
            std::stringstream alertDetails;
            alertDetails << "Suspicious content written to file:" << std::endl;
            alertDetails << "File: " << WideToUTF8(filePath) << std::endl;
            alertDetails << "Size: " << dataSize << " bytes" << std::endl;
            if (g_config.hashWrittenFiles) {
                alertDetails << "SHA256: " << fileHash << std::endl;
            }
            alertDetails << "Reasons:" << std::endl << suspiciousReasons.str();
            alertDetails << "Process: " << WideToUTF8(GetProcessImageName()) << " (PID: " << GetCurrentProcessId() << ")" << std::endl;

            // Note: No blocking action here, only alerting after the write
            RaiseAlert(FILE_OPERATIONS, "Suspicious File Content Written", alertDetails.str());
        }
    }

    SetLastError(lastError);
    return result;
}

// Hooked CloseHandle
BOOL WINAPI Hooked_CloseHandle(HANDLE hObject) {
    // Skip monitoring if file operations are disabled
    if (!g_config.monitorFileOperations) {
        return Real_CloseHandle(hObject);
    }
    
    // Remove handle from tracking map before closing
    auto it = g_handleToPath.find(hObject);
    if (it != g_handleToPath.end()) {
        // Build log details for the close operation
        std::stringstream details;
        details << "Handle: 0x" << std::hex << (DWORD_PTR)hObject << std::dec << std::endl;
        details << "File: " << WideToUTF8(it->second) << std::endl;
        
        // Log the API call
        LogApiCall(FILE_OPERATIONS, "CloseHandle", details.str());
        
        // Remove the handle from our tracking map
        g_handleToPath.erase(it);
    }
    
    // Call original function
    return Real_CloseHandle(hObject);
} 