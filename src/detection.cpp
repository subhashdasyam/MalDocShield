#include "../include/OfficeApiHook.h"
#include <windows.h>
#include <string>
#include <regex>
#include <shlwapi.h>
#include <shlobj.h>

#pragma comment(lib, "shlwapi.lib")

// Check if a file path is suspicious
bool IsSuspiciousFilePath(const std::wstring& filePath) {
    // Check if the path matches any of the suspicious path patterns
    for (const auto& pattern : g_config.suspiciousPaths) {
        try {
            if (std::regex_search(filePath, pattern)) {
                HookDebugLog("Suspicious path pattern matched: %ws", filePath.c_str());
                return true;
            }
        }
        catch (const std::exception& e) {
            HookDebugLog("Regex error in IsSuspiciousFilePath (path): %s", e.what());
        }
    }

    // Get TEMP directory path
    wchar_t tempPath[MAX_PATH] = { 0 };
    if (GetTempPathW(MAX_PATH, tempPath) > 0) {
        // Check if the file is in the TEMP directory
        if (wcsstr(filePath.c_str(), tempPath) != NULL) {
            // Get the file extension
            std::wstring extension = PathFindExtensionW(filePath.c_str());
            
            // Check if the extension matches any of the suspicious extension patterns
            for (const auto& pattern : g_config.suspiciousExtensions) {
                try {
                    if (std::regex_search(extension, pattern)) {
                        HookDebugLog("Suspicious extension pattern matched: %ws", extension.c_str());
                        return true;
                    }
                }
                catch (const std::exception& e) {
                    HookDebugLog("Regex error in IsSuspiciousFilePath (extension): %s", e.what());
                }
            }
        }
    }

    return false;
}

// Check if a registry key path is suspicious
bool IsSuspiciousRegistryKey(const std::wstring& keyPath) {
    // Convert the Windows registry key HKEY constants to strings for path matching
    std::wstring fullPath;
    
    // Handle predefined key names
    if (keyPath.empty()) {
        return false;
    }
    
    // Convert the key path for regex matching
    fullPath = keyPath;
    
    // Check if the key matches any of the suspicious key patterns
    for (const auto& pattern : g_config.suspiciousKeys) {
        try {
            if (std::regex_search(fullPath, pattern)) {
                HookDebugLog("Suspicious registry key pattern matched: %ws", fullPath.c_str());
                return true;
            }
        }
        catch (const std::exception& e) {
            HookDebugLog("Regex error in IsSuspiciousRegistryKey: %s", e.what());
        }
    }
    
    return false;
}

// Check if a process name is in the suspicious processes list
bool IsSuspiciousProcess(const std::wstring& processName) {
    // Convert to lowercase for case-insensitive matching
    std::wstring lowerProcessName = processName;
    std::transform(lowerProcessName.begin(), lowerProcessName.end(), lowerProcessName.begin(), ::towlower);
    std::string utf8ProcessName = WideToUTF8(lowerProcessName);
    
    // Check for substring match with any suspicious process name
    for (const auto& suspiciousProcess : g_config.suspiciousProcesses) {
        std::string lowerSuspicious = suspiciousProcess;
        std::transform(lowerSuspicious.begin(), lowerSuspicious.end(), lowerSuspicious.begin(), ::tolower);
        
        if (utf8ProcessName.find(lowerSuspicious) != std::string::npos) {
            HookDebugLog("Suspicious process name matched: %ws", processName.c_str());
            return true;
        }
    }
    
    return false;
}

// Check if a network address or port is suspicious
bool IsSuspiciousNetwork(const std::string& address, int port) {
    // Check if the address matches any suspicious address pattern
    for (const auto& pattern : g_config.suspiciousAddresses) {
        try {
            if (std::regex_search(address, pattern)) {
                HookDebugLog("Suspicious network address pattern matched: %s", address.c_str());
                return true;
            }
        }
        catch (const std::exception& e) {
            HookDebugLog("Regex error in IsSuspiciousNetwork (address): %s", e.what());
        }
    }
    
    // Check if the port is in the suspicious ports list
    for (int suspiciousPort : g_config.suspiciousPorts) {
        if (port == suspiciousPort) {
            HookDebugLog("Suspicious network port matched: %d", port);
            return true;
        }
    }
    
    return false;
}

// Check if a DLL name is suspicious
bool IsSuspiciousDll(const std::wstring& dllName) {
    // Check if the DLL name matches any suspicious pattern
    for (const auto& pattern : g_config.suspiciousDlls) {
        try {
            if (std::regex_search(dllName, pattern)) {
                HookDebugLog("Suspicious DLL name pattern matched: %ws", dllName.c_str());
                return true;
            }
        }
        catch (const std::exception& e) {
            HookDebugLog("Regex error in IsSuspiciousDll: %s", e.what());
        }
    }
    
    return false;
} 