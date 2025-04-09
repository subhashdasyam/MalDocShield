#include "../include/OfficeApiHook.h"
#include <windows.h>
#include <string>
#include <sstream>
#include <iomanip>

// Hooked VirtualAlloc
LPVOID WINAPI Hooked_VirtualAlloc(
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD flAllocationType,
    DWORD flProtect
) {
    // Skip monitoring if memory operations are disabled
    if (!g_config.monitorMemoryOperations) {
        return Real_VirtualAlloc(lpAddress, dwSize, flAllocationType, flProtect);
    }
    
    // PRE-CALL CHECKS (No specific pre-call blocking based on params for Alloc)
    // Blocking would typically happen based on subsequent VirtualProtect

    // Call original function
    LPVOID result = Real_VirtualAlloc(lpAddress, dwSize, flAllocationType, flProtect);
    DWORD lastError = GetLastError();

    // POST-CALL ANALYSIS & LOGGING
    // Build allocation type string
    std::stringstream allocTypeStr;
    if (flAllocationType & MEM_COMMIT) allocTypeStr << "MEM_COMMIT ";
    if (flAllocationType & MEM_RESERVE) allocTypeStr << "MEM_RESERVE ";
    if (flAllocationType & MEM_RESET) allocTypeStr << "MEM_RESET ";
    if (flAllocationType & MEM_TOP_DOWN) allocTypeStr << "MEM_TOP_DOWN ";
    if (flAllocationType & MEM_WRITE_WATCH) allocTypeStr << "MEM_WRITE_WATCH ";
    if (flAllocationType & MEM_PHYSICAL) allocTypeStr << "MEM_PHYSICAL ";
    if (flAllocationType & MEM_RESET_UNDO) allocTypeStr << "MEM_RESET_UNDO ";
    if (flAllocationType & MEM_LARGE_PAGES) allocTypeStr << "MEM_LARGE_PAGES ";
    
    // Build protection string
    std::stringstream protectStr;
    switch (flProtect & ~(PAGE_GUARD | PAGE_NOCACHE | PAGE_WRITECOMBINE)) {
        case PAGE_NOACCESS: protectStr << "PAGE_NOACCESS"; break;
        case PAGE_READONLY: protectStr << "PAGE_READONLY"; break;
        case PAGE_READWRITE: protectStr << "PAGE_READWRITE"; break;
        case PAGE_WRITECOPY: protectStr << "PAGE_WRITECOPY"; break;
        case PAGE_EXECUTE: protectStr << "PAGE_EXECUTE"; break;
        case PAGE_EXECUTE_READ: protectStr << "PAGE_EXECUTE_READ"; break;
        case PAGE_EXECUTE_READWRITE: protectStr << "PAGE_EXECUTE_READWRITE"; break;
        case PAGE_EXECUTE_WRITECOPY: protectStr << "PAGE_EXECUTE_WRITECOPY"; break;
        default: protectStr << "UNKNOWN"; break;
    }
    
    if (flProtect & PAGE_GUARD) protectStr << " | PAGE_GUARD";
    if (flProtect & PAGE_NOCACHE) protectStr << " | PAGE_NOCACHE";
    if (flProtect & PAGE_WRITECOMBINE) protectStr << " | PAGE_WRITECOMBINE";
    
    // Check if this is a suspicious allocation (executable and writable)
    bool isSuspicious = false;
    std::string suspiciousReason;
    
    // Executable and writable allocations are suspicious
    if ((flProtect & PAGE_EXECUTE_READWRITE) == PAGE_EXECUTE_READWRITE) {
        isSuspicious = true;
        suspiciousReason = "Executable and writable memory allocation (PAGE_EXECUTE_READWRITE)";
    }
    
    // Large executable allocations are also suspicious
    if (!isSuspicious && (flProtect & PAGE_EXECUTE) && dwSize > 1024 * 1024) {  // > 1MB
        isSuspicious = true;
        suspiciousReason = "Large executable memory allocation (>1MB)";
    }
    
    // Build log details
    std::stringstream details;
    details << "Requested Address: 0x" << std::hex << lpAddress << std::dec << std::endl;
    details << "Size: " << dwSize << " bytes (" << std::fixed << std::setprecision(2) << (dwSize / 1024.0) << " KB)" << std::endl;
    details << "AllocationType: 0x" << std::hex << flAllocationType << std::dec << " (" << allocTypeStr.str() << ")" << std::endl;
    details << "Protection: 0x" << std::hex << flProtect << std::dec << " (" << protectStr.str() << ")" << std::endl;
    details << "Result Address: 0x" << std::hex << result << std::dec << std::endl;
    
    if (!result) {
        details << "LastError: " << lastError << std::endl;
    }
    
    // Log the API call
    LogApiCall(MEMORY_OPERATIONS, "VirtualAlloc", details.str());
    
    // Raise Alert (No blocking for VirtualAlloc itself based on these checks)
    if (isSuspicious && result) {
        std::stringstream alertDetails;
        alertDetails << "Suspicious memory allocation:" << std::endl;
        alertDetails << "Reason: " << suspiciousReason << std::endl;
        alertDetails << "Address: 0x" << std::hex << result << std::dec << std::endl;
        alertDetails << "Size: " << dwSize << " bytes (" << std::fixed << std::setprecision(2) << (dwSize / 1024.0) << " KB)" << std::endl;
        alertDetails << "Protection: " << protectStr.str() << std::endl;
        alertDetails << "Process: " << WideToUTF8(GetProcessImageName()) << " (PID: " << GetCurrentProcessId() << ")" << std::endl;
        
        RaiseAlert(MEMORY_OPERATIONS, "Suspicious Memory Allocation", alertDetails.str());
    }
    
    SetLastError(lastError);
    return result;
}

// Hooked VirtualProtect
BOOL WINAPI Hooked_VirtualProtect(
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD flNewProtect,
    PDWORD lpflOldProtect
) {
    // Skip monitoring if memory operations are disabled
    if (!g_config.monitorMemoryOperations) {
        return Real_VirtualProtect(lpAddress, dwSize, flNewProtect, lpflOldProtect);
    }
    
    // PRE-CALL CHECKS
    // Determine if the protection change is suspicious
    bool isSuspicious = false;
    std::string blockReason;
    // Note: We don't know oldProtect definitively before the call unless we query it,
    // which adds overhead. We'll base suspicion primarily on the new protection.
    if ((flNewProtect & PAGE_EXECUTE_READWRITE) == PAGE_EXECUTE_READWRITE) {
        isSuspicious = true;
        blockReason = "Attempt to set memory protection to executable and writable (PAGE_EXECUTE_READWRITE)";
    }
    // Could add more checks here, e.g., if flNewProtect includes PAGE_EXECUTE
    
    // Determine if blocking is needed
    bool shouldBlock = isSuspicious && (g_config.actionOnSuspicious >= ACTION_BLOCK_ERROR);

    if (shouldBlock) {
        std::stringstream blockDetails;
        blockDetails << "Address: 0x" << std::hex << lpAddress << std::dec << std::endl;
        blockDetails << "Size: " << dwSize << " bytes" << std::endl;
        blockDetails << "New Protection Requested: 0x" << std::hex << flNewProtect << std::dec << std::endl;
        // ... (fill blockDetails)
        LogBlockedOperation(MEMORY_OPERATIONS, "VirtualProtect", blockReason, blockDetails.str());

        if (g_config.actionOnSuspicious == ACTION_TERMINATE_THREAD) { TerminateThread(GetCurrentThread(), 1); }
        else if (g_config.actionOnSuspicious == ACTION_TERMINATE_PROCESS) { TerminateProcess(GetCurrentProcess(), 1); }

        SetLastError(ERROR_ACCESS_DENIED); 
        return FALSE; // Return FALSE for VirtualProtect failure
    }

    // If not blocking, proceed
    DWORD actualOldProtect = 0; // Variable to store the actual old protection
    BOOL result = Real_VirtualProtect(lpAddress, dwSize, flNewProtect, &actualOldProtect); // Pass our variable
    DWORD lastError = GetLastError();

    // POST-CALL LOGGING & ALERTS
    // Build protection string for new protection
    std::stringstream newProtectStr;
    switch (flNewProtect & ~(PAGE_GUARD | PAGE_NOCACHE | PAGE_WRITECOMBINE)) {
        case PAGE_NOACCESS: newProtectStr << "PAGE_NOACCESS"; break;
        case PAGE_READONLY: newProtectStr << "PAGE_READONLY"; break;
        case PAGE_READWRITE: newProtectStr << "PAGE_READWRITE"; break;
        case PAGE_WRITECOPY: newProtectStr << "PAGE_WRITECOPY"; break;
        case PAGE_EXECUTE: newProtectStr << "PAGE_EXECUTE"; break;
        case PAGE_EXECUTE_READ: newProtectStr << "PAGE_EXECUTE_READ"; break;
        case PAGE_EXECUTE_READWRITE: newProtectStr << "PAGE_EXECUTE_READWRITE"; break;
        case PAGE_EXECUTE_WRITECOPY: newProtectStr << "PAGE_EXECUTE_WRITECOPY"; break;
        default: newProtectStr << "UNKNOWN"; break;
    }
    
    if (flNewProtect & PAGE_GUARD) newProtectStr << " | PAGE_GUARD";
    if (flNewProtect & PAGE_NOCACHE) newProtectStr << " | PAGE_NOCACHE";
    if (flNewProtect & PAGE_WRITECOMBINE) newProtectStr << " | PAGE_WRITECOMBINE";
    
    // Build protection string for old protection
    std::stringstream oldProtectStr;
    switch (actualOldProtect & ~(PAGE_GUARD | PAGE_NOCACHE | PAGE_WRITECOMBINE)) {
        case PAGE_NOACCESS: oldProtectStr << "PAGE_NOACCESS"; break;
        case PAGE_READONLY: oldProtectStr << "PAGE_READONLY"; break;
        case PAGE_READWRITE: oldProtectStr << "PAGE_READWRITE"; break;
        case PAGE_WRITECOPY: oldProtectStr << "PAGE_WRITECOPY"; break;
        case PAGE_EXECUTE: oldProtectStr << "PAGE_EXECUTE"; break;
        case PAGE_EXECUTE_READ: oldProtectStr << "PAGE_EXECUTE_READ"; break;
        case PAGE_EXECUTE_READWRITE: oldProtectStr << "PAGE_EXECUTE_READWRITE"; break;
        case PAGE_EXECUTE_WRITECOPY: oldProtectStr << "PAGE_EXECUTE_WRITECOPY"; break;
        default: oldProtectStr << "UNKNOWN"; break;
    }
    
    if (actualOldProtect & PAGE_GUARD) oldProtectStr << " | PAGE_GUARD";
    if (actualOldProtect & PAGE_NOCACHE) oldProtectStr << " | PAGE_NOCACHE";
    if (actualOldProtect & PAGE_WRITECOMBINE) oldProtectStr << " | PAGE_WRITECOMBINE";
    
    // Re-evaluate suspicion based on actual old protection if needed (optional)
    bool postCallSuspicious = false;
    std::string postCallReason;
     if ((flNewProtect & PAGE_EXECUTE) && !(actualOldProtect & PAGE_EXECUTE)) {
        postCallSuspicious = true;
        postCallReason = "Memory protection changed from non-executable to executable";
    }
    if (!postCallSuspicious && (flNewProtect & PAGE_EXECUTE_READWRITE) == PAGE_EXECUTE_READWRITE) {
         postCallSuspicious = true;
         postCallReason = "Memory protection set to executable and writable (PAGE_EXECUTE_READWRITE)";
    }
    
    std::stringstream details;
    details << "Address: 0x" << std::hex << lpAddress << std::dec << std::endl;
    details << "Size: " << dwSize << " bytes (" << std::fixed << std::setprecision(2) << (dwSize / 1024.0) << " KB)" << std::endl;
    details << "Old Protection: 0x" << std::hex << actualOldProtect << std::dec << " (" << oldProtectStr.str() << ")" << std::endl;
    details << "New Protection: 0x" << std::hex << flNewProtect << std::dec << " (" << newProtectStr.str() << ")" << std::endl;
    details << "Result: " << (result ? "SUCCESS" : "FAILED") << std::endl;
    
    if (!result) {
        details << "LastError: " << lastError << std::endl;
    }
    
    // Log the API call
    LogApiCall(MEMORY_OPERATIONS, "VirtualProtect", details.str());

    // Raise Alert if the operation succeeded and was deemed suspicious post-call
    if (postCallSuspicious && result) {
        std::stringstream alertDetails;
        alertDetails << "Suspicious memory protection change:" << std::endl;
        alertDetails << "Reason: " << postCallReason << std::endl;
        alertDetails << "Address: 0x" << std::hex << lpAddress << std::dec << std::endl;
        alertDetails << "Size: " << dwSize << " bytes (" << std::fixed << std::setprecision(2) << (dwSize / 1024.0) << " KB)" << std::endl;
        alertDetails << "Old Protection: " << oldProtectStr.str() << std::endl;
        alertDetails << "New Protection: " << newProtectStr.str() << std::endl;
        alertDetails << "Process: " << WideToUTF8(GetProcessImageName()) << " (PID: " << GetCurrentProcessId() << ")" << std::endl;
        
        RaiseAlert(MEMORY_OPERATIONS, "Suspicious Memory Protection Change (Allowed)", alertDetails.str());
    }
    
    // Restore the original value pointed to by lpflOldProtect if the user provided it
    // This maintains the API contract if the call succeeded.
    if (result && lpflOldProtect != NULL) {
        *lpflOldProtect = actualOldProtect;
    }

    SetLastError(lastError);
    return result;
} 