#include "../include/OfficeApiHook.h"
#include <windows.h>
#include <string>
#include <sstream>
#include <iomanip>
#include <regex>

// Helper function to convert registry key handle to string representation
std::wstring GetKeyPath(HKEY hKey) {
    // Handle predefined keys
    if (hKey == HKEY_CLASSES_ROOT) return L"HKEY_CLASSES_ROOT";
    if (hKey == HKEY_CURRENT_USER) return L"HKEY_CURRENT_USER";
    if (hKey == HKEY_LOCAL_MACHINE) return L"HKEY_LOCAL_MACHINE";
    if (hKey == HKEY_USERS) return L"HKEY_USERS";
    if (hKey == HKEY_PERFORMANCE_DATA) return L"HKEY_PERFORMANCE_DATA";
    if (hKey == HKEY_CURRENT_CONFIG) return L"HKEY_CURRENT_CONFIG";
    if (hKey == HKEY_DYN_DATA) return L"HKEY_DYN_DATA";
    
    // For other keys, try to get the name
    WCHAR keyPath[MAX_PATH] = { 0 };
    DWORD keyPathSize = MAX_PATH;
    
    LONG result = RegQueryInfoKeyW(hKey, keyPath, &keyPathSize, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
    if (result == ERROR_SUCCESS) {
        return std::wstring(keyPath);
    }
    
    // Return generic representation for unknown keys
    std::wstringstream ss;
    ss << L"0x" << std::hex << (DWORD_PTR)hKey;
    return ss.str();
}

// Hooked RegOpenKeyExW
LONG WINAPI Hooked_RegOpenKeyExW(
    HKEY hKey,
    LPCWSTR lpSubKey,
    DWORD ulOptions,
    REGSAM samDesired,
    PHKEY phkResult
) {
    // Skip logging for null subkeys
    if (lpSubKey == NULL) {
        return Real_RegOpenKeyExW(hKey, lpSubKey, ulOptions, samDesired, phkResult);
    }

    // Skip monitoring if registry operations are disabled
    if (!g_config.monitorRegistryOperations) {
        return Real_RegOpenKeyExW(hKey, lpSubKey, ulOptions, samDesired, phkResult);
    }
    
    // PRE-CALL CHECKS
    std::wstring baseKeyName = GetKeyPath(hKey);
    std::wstring fullKeyPath = baseKeyName + L"\\" + std::wstring(lpSubKey);
    bool isSuspicious = IsSuspiciousRegistryKey(fullKeyPath); // Check suspicious patterns
    bool isWhitelisted = false;
    std::string blockReason;

    // Check Whitelist
    for (const auto& pattern : g_config.whitelistedKeys) {
        try {
            if (std::regex_search(fullKeyPath, pattern)) {
                isWhitelisted = true;
                break;
            }
        } catch (...) { /* Ignore regex errors */ }
    }

    // Determine if blocking is needed
    bool shouldBlock = isSuspicious && !isWhitelisted && (g_config.actionOnSuspicious >= ACTION_BLOCK_ERROR);

    if (shouldBlock) {
        blockReason = "Suspicious registry key open denied: " + WideToUTF8(fullKeyPath);
        std::stringstream blockDetails;
        blockDetails << "Key: " << WideToUTF8(fullKeyPath) << std::endl;
        blockDetails << "Access Requested: " << std::hex << samDesired << std::dec << std::endl;
        // ... (fill blockDetails)
        LogBlockedOperation(REGISTRY_OPERATIONS, "RegOpenKeyExW", blockReason, blockDetails.str());

        if (g_config.actionOnSuspicious == ACTION_TERMINATE_THREAD) { TerminateThread(GetCurrentThread(), 1); }
        else if (g_config.actionOnSuspicious == ACTION_TERMINATE_PROCESS) { TerminateProcess(GetCurrentProcess(), 1); }

        return ERROR_ACCESS_DENIED; // Return error code for registry functions
    }

    // If not blocking, proceed
    LONG result = Real_RegOpenKeyExW(hKey, lpSubKey, ulOptions, samDesired, phkResult);
    DWORD lastError = GetLastError();
    
    // POST-CALL LOGGING & ALERTS (Only if NOT whitelisted)
    if (!isWhitelisted) {
        // Build access rights string
        std::stringstream accessRights;
        if (samDesired & KEY_READ) accessRights << "KEY_READ ";
        if (samDesired & KEY_WRITE) accessRights << "KEY_WRITE ";
        if (samDesired & KEY_EXECUTE) accessRights << "KEY_EXECUTE ";
        if (samDesired & KEY_ALL_ACCESS) accessRights << "KEY_ALL_ACCESS ";
        
        // Build log details
        std::stringstream details;
        details << "BaseKey: " << WideToUTF8(baseKeyName) << std::endl;
        details << "SubKey: " << WideToUTF8(lpSubKey) << std::endl;
        details << "FullPath: " << WideToUTF8(fullKeyPath) << std::endl;
        details << "AccessRights: " << accessRights.str() << std::endl;
        details << "Result: " << result << std::endl;
        if (result != ERROR_SUCCESS) {
             details << "LastError: " << lastError << std::endl;
        }
        
        if (result == ERROR_SUCCESS && phkResult != NULL) {
            std::stringstream keyHandle;
            keyHandle << "0x" << std::hex << (DWORD_PTR)*phkResult;
            details << "ResultHandle: " << keyHandle.str() << std::endl;
        }
        
        LogApiCall(REGISTRY_OPERATIONS, "RegOpenKeyExW", details.str());

        if (isSuspicious && result == ERROR_SUCCESS) {
            std::stringstream alertDetails;
            alertDetails << "Suspicious registry key access:" << std::endl;
            alertDetails << "Key: " << WideToUTF8(fullKeyPath) << std::endl;
            alertDetails << "Access: " << accessRights.str() << std::endl;
            alertDetails << "Process: " << WideToUTF8(GetProcessImageName()) << " (PID: " << GetCurrentProcessId() << ")" << std::endl;
            
            RaiseAlert(REGISTRY_OPERATIONS, "Suspicious Registry Access (Allowed)", alertDetails.str());
        }
    }

    // For registry ops, the return value IS the error code
    return result;
}

// Hooked RegOpenKeyExA
LONG WINAPI Hooked_RegOpenKeyExA(
    HKEY hKey,
    LPCSTR lpSubKey,
    DWORD ulOptions,
    REGSAM samDesired,
    PHKEY phkResult
) {
     // Skip logging for null subkeys
    if (lpSubKey == NULL) {
        return Real_RegOpenKeyExA(hKey, lpSubKey, ulOptions, samDesired, phkResult);
    }

    // Skip monitoring if registry operations are disabled
    if (!g_config.monitorRegistryOperations) {
        return Real_RegOpenKeyExA(hKey, lpSubKey, ulOptions, samDesired, phkResult);
    }
    
    std::wstring wideSubKey = UTF8ToWide(lpSubKey);
    std::wstring baseKeyName = GetKeyPath(hKey);
    std::wstring fullKeyPath = baseKeyName + L"\\" + wideSubKey;

    // PRE-CALL CHECKS
    bool isSuspicious = IsSuspiciousRegistryKey(fullKeyPath);
    bool isWhitelisted = false;
    std::string blockReason;

    for (const auto& pattern : g_config.whitelistedKeys) {
        try {
            if (std::regex_search(fullKeyPath, pattern)) {
                isWhitelisted = true;
                break;
            }
        } catch (...) { /* Ignore regex errors */ }
    }

    bool shouldBlock = isSuspicious && !isWhitelisted && (g_config.actionOnSuspicious >= ACTION_BLOCK_ERROR);

    if (shouldBlock) {
        blockReason = "Suspicious registry key open denied: " + std::string(lpSubKey);
        std::stringstream blockDetails;
        // ... (fill blockDetails)
        LogBlockedOperation(REGISTRY_OPERATIONS, "RegOpenKeyExA", blockReason, blockDetails.str());

        if (g_config.actionOnSuspicious == ACTION_TERMINATE_THREAD) { TerminateThread(GetCurrentThread(), 1); }
        else if (g_config.actionOnSuspicious == ACTION_TERMINATE_PROCESS) { TerminateProcess(GetCurrentProcess(), 1); }

        return ERROR_ACCESS_DENIED;
    }

    // If not blocking, proceed
    LONG result = Real_RegOpenKeyExA(hKey, lpSubKey, ulOptions, samDesired, phkResult);
    DWORD lastError = GetLastError(); // Note: result itself is often the error code for Reg* fns

    // POST-CALL LOGGING & ALERTS (Only if NOT whitelisted)
    if (!isWhitelisted) {
         // Build access rights string
        std::stringstream accessRights;
        if (samDesired & KEY_READ) accessRights << "KEY_READ ";
        if (samDesired & KEY_WRITE) accessRights << "KEY_WRITE ";
        if (samDesired & KEY_EXECUTE) accessRights << "KEY_EXECUTE ";
        if (samDesired & KEY_ALL_ACCESS) accessRights << "KEY_ALL_ACCESS ";
        
        // Build log details
        std::stringstream details;
        details << "BaseKey: " << WideToUTF8(baseKeyName) << std::endl;
        details << "SubKey: " << lpSubKey << std::endl;
        details << "FullPath: " << WideToUTF8(fullKeyPath) << std::endl;
        details << "AccessRights: " << accessRights.str() << std::endl;
        details << "Result: " << result << std::endl;
        if (result != ERROR_SUCCESS) {
             details << "LastError: " << lastError << std::endl;
        }
        
        if (result == ERROR_SUCCESS && phkResult != NULL) {
            std::stringstream keyHandle;
            keyHandle << "0x" << std::hex << (DWORD_PTR)*phkResult;
            details << "ResultHandle: " << keyHandle.str() << std::endl;
        }
        
        LogApiCall(REGISTRY_OPERATIONS, "RegOpenKeyExA", details.str());

        if (isSuspicious && result == ERROR_SUCCESS) {
            std::stringstream alertDetails;
            alertDetails << "Suspicious registry key access:" << std::endl;
            alertDetails << "Key: " << WideToUTF8(fullKeyPath) << std::endl;
            alertDetails << "Access: " << accessRights.str() << std::endl;
            alertDetails << "Process: " << WideToUTF8(GetProcessImageName()) << " (PID: " << GetCurrentProcessId() << ")" << std::endl;
            
            RaiseAlert(REGISTRY_OPERATIONS, "Suspicious Registry Access (Allowed)", alertDetails.str());
        }
    }

    return result;
}

// Hooked RegSetValueExW
LONG WINAPI Hooked_RegSetValueExW(
    HKEY hKey,
    LPCWSTR lpValueName,
    DWORD Reserved,
    DWORD dwType,
    CONST BYTE* lpData,
    DWORD cbData
) {
    // Skip monitoring if registry operations are disabled
    if (!g_config.monitorRegistryOperations) {
        return Real_RegSetValueExW(hKey, lpValueName, Reserved, dwType, lpData, cbData);
    }
    
    // PRE-CALL CHECKS
    std::wstring keyPath = GetKeyPath(hKey); // Get path before potentially blocking
    bool isSuspicious = IsSuspiciousRegistryKey(keyPath);
    bool isWhitelisted = false;
    std::string blockReason;

    // Check Whitelist
    for (const auto& pattern : g_config.whitelistedKeys) {
        try {
            if (std::regex_search(keyPath, pattern)) {
                isWhitelisted = true;
                break;
            }
        } catch (...) { /* Ignore regex errors */ }
    }

    // Determine if blocking is needed
    bool shouldBlock = isSuspicious && !isWhitelisted && (g_config.actionOnSuspicious >= ACTION_BLOCK_ERROR);

    if (shouldBlock) {
        blockReason = "Suspicious registry key write denied: " + WideToUTF8(keyPath);
        std::wstring valueName = (lpValueName != NULL) ? lpValueName : L"(Default)";
        std::stringstream blockDetails;
        blockDetails << "Key: " << WideToUTF8(keyPath) << std::endl;
        blockDetails << "Value Name: " << WideToUTF8(valueName) << std::endl;
        blockDetails << "Type: " << dwType << std::endl;
        blockDetails << "Size: " << cbData << std::endl;
        // ... (fill blockDetails)
        LogBlockedOperation(REGISTRY_OPERATIONS, "RegSetValueExW", blockReason, blockDetails.str());

        if (g_config.actionOnSuspicious == ACTION_TERMINATE_THREAD) { TerminateThread(GetCurrentThread(), 1); }
        else if (g_config.actionOnSuspicious == ACTION_TERMINATE_PROCESS) { TerminateProcess(GetCurrentProcess(), 1); }

        return ERROR_ACCESS_DENIED;
    }

    // If not blocking, proceed
    LONG result = Real_RegSetValueExW(hKey, lpValueName, Reserved, dwType, lpData, cbData);
    DWORD lastError = GetLastError();
    
    // POST-CALL LOGGING & ALERTS (Only if NOT whitelisted)
    if (!isWhitelisted) {
        std::wstring valueName = (lpValueName != NULL) ? lpValueName : L"(Default)";
        // Build data type string
        std::string dataType;
        switch (dwType) {
            case REG_SZ: dataType = "REG_SZ"; break;
            case REG_MULTI_SZ: dataType = "REG_MULTI_SZ"; break;
            case REG_EXPAND_SZ: dataType = "REG_EXPAND_SZ"; break;
            case REG_BINARY: dataType = "REG_BINARY"; break;
            case REG_DWORD: dataType = "REG_DWORD"; break;
            case REG_QWORD: dataType = "REG_QWORD"; break;
            default: dataType = "UNKNOWN"; break;
        }
        
        // Build value data string (with type-specific formatting)
        std::string valueData = "<binary data>";
        if (lpData != NULL && cbData > 0) {
            if (dwType == REG_SZ || dwType == REG_EXPAND_SZ) {
                // String value (ensure it's null-terminated)
                if (cbData >= 2 && lpData[cbData - 2] == 0 && lpData[cbData - 1] == 0) {
                    std::wstring wideData(reinterpret_cast<const wchar_t*>(lpData));
                    valueData = WideToUTF8(wideData);
                }
            } else if (dwType == REG_DWORD && cbData == 4) {
                // DWORD value
                DWORD dwordValue = *reinterpret_cast<const DWORD*>(lpData);
                std::stringstream ss;
                ss << "0x" << std::hex << dwordValue << " (" << std::dec << dwordValue << ")";
                valueData = ss.str();
            } else if (dwType == REG_QWORD && cbData == 8) {
                // QWORD value
                ULONGLONG qwordValue = *reinterpret_cast<const ULONGLONG*>(lpData);
                std::stringstream ss;
                ss << "0x" << std::hex << qwordValue << " (" << std::dec << qwordValue << ")";
                valueData = ss.str();
            } else {
                // Binary data (show as hex dump for the first 16 bytes)
                std::stringstream ss;
                const size_t maxBytesToShow = std::min<size_t>(cbData, 16);
                for (size_t i = 0; i < maxBytesToShow; i++) {
                    ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(lpData[i]) << " ";
                }
                if (cbData > maxBytesToShow) {
                    ss << "... (" << std::dec << cbData << " bytes total)";
                }
                valueData = ss.str();
            }
        }
        
        // Build log details
        std::stringstream details;
        details << "Key: " << WideToUTF8(keyPath) << std::endl;
        details << "ValueName: " << WideToUTF8(valueName) << std::endl;
        details << "Type: " << dataType << std::endl;
        details << "DataSize: " << cbData << " bytes" << std::endl;
        details << "Data: " << valueData << std::endl;
        details << "Result: " << result << std::endl;
        if (result != ERROR_SUCCESS) {
             details << "LastError: " << lastError << std::endl;
        }
        LogApiCall(REGISTRY_OPERATIONS, "RegSetValueExW", details.str());

        // Raise standard alert if suspicious (but wasn't blocked)
        if (isSuspicious && result == ERROR_SUCCESS) {
            std::stringstream alertDetails;
            alertDetails << "Suspicious registry key modification:" << std::endl;
            alertDetails << "Key: " << WideToUTF8(keyPath) << std::endl;
            alertDetails << "Value: " << WideToUTF8(valueName) << std::endl;
            alertDetails << "Type: " << dataType << std::endl;
            alertDetails << "Data: " << valueData << std::endl;
            alertDetails << "Process: " << WideToUTF8(GetProcessImageName()) << " (PID: " << GetCurrentProcessId() << ")" << std::endl;
            
            RaiseAlert(REGISTRY_OPERATIONS, "Suspicious Registry Modification (Allowed)", alertDetails.str());
        }
    }

    return result;
}

// Hooked RegSetValueExA
LONG WINAPI Hooked_RegSetValueExA(
    HKEY hKey,
    LPCSTR lpValueName,
    DWORD Reserved,
    DWORD dwType,
    CONST BYTE* lpData,
    DWORD cbData
) {
    // Skip monitoring if registry operations are disabled
    if (!g_config.monitorRegistryOperations) {
        return Real_RegSetValueExA(hKey, lpValueName, Reserved, dwType, lpData, cbData);
    }
    
    // PRE-CALL CHECKS
    std::wstring keyPath = GetKeyPath(hKey); // Get path before potentially blocking
    bool isSuspicious = IsSuspiciousRegistryKey(keyPath);
    bool isWhitelisted = false;
    std::string blockReason;

    for (const auto& pattern : g_config.whitelistedKeys) {
        try {
            if (std::regex_search(keyPath, pattern)) {
                isWhitelisted = true;
                break;
            }
        } catch (...) { /* Ignore regex errors */ }
    }

    bool shouldBlock = isSuspicious && !isWhitelisted && (g_config.actionOnSuspicious >= ACTION_BLOCK_ERROR);

    if (shouldBlock) {
        blockReason = "Suspicious registry key write denied: " + WideToUTF8(keyPath);
        std::string valueName = (lpValueName != NULL) ? lpValueName : "(Default)";
        std::stringstream blockDetails;
        // ... (fill blockDetails)
        LogBlockedOperation(REGISTRY_OPERATIONS, "RegSetValueExA", blockReason, blockDetails.str());

        if (g_config.actionOnSuspicious == ACTION_TERMINATE_THREAD) { TerminateThread(GetCurrentThread(), 1); }
        else if (g_config.actionOnSuspicious == ACTION_TERMINATE_PROCESS) { TerminateProcess(GetCurrentProcess(), 1); }

        return ERROR_ACCESS_DENIED;
    }
    
    // If not blocking, proceed
    LONG result = Real_RegSetValueExA(hKey, lpValueName, Reserved, dwType, lpData, cbData);
    DWORD lastError = GetLastError();

    // POST-CALL LOGGING & ALERTS (Only if NOT whitelisted)
    if (!isWhitelisted) {
        std::string valueName = (lpValueName != NULL) ? lpValueName : "(Default)";
        // Build data type string
        std::string dataType;
        switch (dwType) {
            case REG_SZ: dataType = "REG_SZ"; break;
            case REG_MULTI_SZ: dataType = "REG_MULTI_SZ"; break;
            case REG_EXPAND_SZ: dataType = "REG_EXPAND_SZ"; break;
            case REG_BINARY: dataType = "REG_BINARY"; break;
            case REG_DWORD: dataType = "REG_DWORD"; break;
            case REG_QWORD: dataType = "REG_QWORD"; break;
            default: dataType = "UNKNOWN"; break;
        }
        
        // Build value data string (with type-specific formatting)
        std::string valueData = "<binary data>";
        if (lpData != NULL && cbData > 0) {
            if (dwType == REG_SZ || dwType == REG_EXPAND_SZ) {
                // String value (ensure it's null-terminated)
                if (cbData > 0 && lpData[cbData - 1] == 0) {
                    valueData = reinterpret_cast<const char*>(lpData);
                }
            } else if (dwType == REG_DWORD && cbData == 4) {
                // DWORD value
                DWORD dwordValue = *reinterpret_cast<const DWORD*>(lpData);
                std::stringstream ss;
                ss << "0x" << std::hex << dwordValue << " (" << std::dec << dwordValue << ")";
                valueData = ss.str();
            } else if (dwType == REG_QWORD && cbData == 8) {
                // QWORD value
                ULONGLONG qwordValue = *reinterpret_cast<const ULONGLONG*>(lpData);
                std::stringstream ss;
                ss << "0x" << std::hex << qwordValue << " (" << std::dec << qwordValue << ")";
                valueData = ss.str();
            } else {
                // Binary data (show as hex dump for the first 16 bytes)
                std::stringstream ss;
                const size_t maxBytesToShow = std::min<size_t>(cbData, 16);
                for (size_t i = 0; i < maxBytesToShow; i++) {
                    ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(lpData[i]) << " ";
                }
                if (cbData > maxBytesToShow) {
                    ss << "... (" << std::dec << cbData << " bytes total)";
                }
                valueData = ss.str();
            }
        }
        
        // Build log details
        std::stringstream details;
        details << "Key: " << WideToUTF8(keyPath) << std::endl;
        details << "ValueName: " << valueName << std::endl;
        details << "Type: " << dataType << std::endl;
        details << "DataSize: " << cbData << " bytes" << std::endl;
        details << "Data: " << valueData << std::endl;
        details << "Result: " << result << std::endl;
        if (result != ERROR_SUCCESS) {
             details << "LastError: " << lastError << std::endl;
        }
        LogApiCall(REGISTRY_OPERATIONS, "RegSetValueExA", details.str());

        if (isSuspicious && result == ERROR_SUCCESS) {
            std::stringstream alertDetails;
            alertDetails << "Suspicious registry key modification:" << std::endl;
            alertDetails << "Key: " << WideToUTF8(keyPath) << std::endl;
            alertDetails << "Value: " << valueName << std::endl;
            alertDetails << "Type: " << dataType << std::endl;
            alertDetails << "Data: " << valueData << std::endl;
            alertDetails << "Process: " << WideToUTF8(GetProcessImageName()) << " (PID: " << GetCurrentProcessId() << ")" << std::endl;
            
            RaiseAlert(REGISTRY_OPERATIONS, "Suspicious Registry Modification (Allowed)", alertDetails.str());
        }
    }
    
    return result;
} 