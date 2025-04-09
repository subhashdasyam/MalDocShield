#include "../include/OfficeApiHook.h"

// Necessary headers (like windows.h, string, vector, etc.) are included via OfficeApiHook.h

#include <Psapi.h> // Still needed specifically for this file
#include <cmath>   // Needed for log2 in CalculateEntropy
#include <cctype>  // Include here for std::tolower
#include <vector>  // Needed for buffer in hashing
#include <wincrypt.h> // Needed for CryptoAPI (hashing)

#pragma comment(lib, "crypt32.lib") // Link against Crypt32 for hashing

// Helper function to safely call std::tolower
unsigned char my_tolower_safe(unsigned char c) {
    return static_cast<unsigned char>(std::tolower(c));
}

// Get the process image name (executable name without path)
std::wstring GetProcessImageName() {
    return GetProcessImageNameFromPID(GetCurrentProcessId());
}

// Get the process image name from a process ID
std::wstring GetProcessImageNameFromPID(DWORD pid) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) {
        return L"UNKNOWN";
    }

    wchar_t processPath[MAX_PATH] = { 0 };
    if (GetModuleFileNameExW(hProcess, NULL, processPath, MAX_PATH) == 0) {
        CloseHandle(hProcess);
        return L"UNKNOWN";
    }

    CloseHandle(hProcess);

    // Extract just the filename from the path
    std::wstring path(processPath);
    size_t lastSlash = path.find_last_of(L'\\');
    if (lastSlash != std::wstring::npos) {
        return path.substr(lastSlash + 1);
    }
    return path;
}

// Extract filename from a path
std::wstring GetFileNameFromPath(const std::wstring& path) {
    size_t lastSlash = path.find_last_of(L'\\');
    if (lastSlash != std::wstring::npos) {
        return path.substr(lastSlash + 1);
    }
    return path;
}

// Convert a wide string to UTF-8
std::string WideToUTF8(const std::wstring& wide) {
    if (wide.empty()) {
        return "";
    }

    int size_needed = WideCharToMultiByte(CP_UTF8, 0, wide.c_str(), static_cast<int>(wide.size()), NULL, 0, NULL, NULL);
    if (size_needed <= 0) {
        return "";
    }

    std::string utf8(size_needed, 0);
    WideCharToMultiByte(CP_UTF8, 0, wide.c_str(), static_cast<int>(wide.size()), &utf8[0], size_needed, NULL, NULL);
    return utf8;
}

// Convert a UTF-8 string to wide string
std::wstring UTF8ToWide(const std::string& utf8) {
    if (utf8.empty()) {
        return L"";
    }

    int size_needed = MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), static_cast<int>(utf8.size()), NULL, 0);
    if (size_needed <= 0) {
        return L"";
    }

    std::wstring wide(size_needed, 0);
    MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), static_cast<int>(utf8.size()), &wide[0], size_needed);
    return wide;
}

// Split a string by delimiter
std::vector<std::string> SplitString(const std::string& str, char delimiter) {
    std::vector<std::string> result;
    std::stringstream ss(str);
    std::string item;

    while (std::getline(ss, item, delimiter)) {
        // Trim whitespace
        item.erase(0, item.find_first_not_of(" \t\n\r\f\v"));
        item.erase(item.find_last_not_of(" \t\n\r\f\v") + 1);
        
        if (!item.empty()) {
            result.push_back(item);
        }
    }

    return result;
}

// Calculate Shannon entropy of data (for detecting packed/encrypted content)
double CalculateEntropy(const BYTE* data, size_t size) {
    if (size == 0) {
        return 0.0;
    }

    // Count occurrences of each byte value
    size_t count[256] = { 0 };
    for (size_t i = 0; i < size; i++) {
        count[data[i]]++;
    }

    // Calculate entropy
    double entropy = 0.0;
    for (int i = 0; i < 256; i++) {
        if (count[i] == 0) {
            continue;
        }

        double probability = static_cast<double>(count[i]) / size;
        entropy -= probability * log2(probability);
    }

    return entropy;
}

// Check if data contains suspicious keywords
bool ContainsSuspiciousKeywords(const BYTE* data, size_t size) {
    // Early return if data is too small
    if (size < 4) {
        return false;
    }

    // Convert data to string (truncate if too large)
    const size_t MAX_CHECK_SIZE = 4096; // Only check the first 4KB to avoid performance issues
    size_t checkSize = std::min(size, MAX_CHECK_SIZE);
    
    // Create a NUL-terminated string for easier searching
    std::vector<char> buffer(checkSize + 1, 0);
    memcpy(buffer.data(), data, checkSize);
    
    // Convert to lowercase for case-insensitive search
    std::string content(buffer.data());
    // Replace std::transform with a manual loop to avoid macro conflicts
    for (char &c : content) {
        c = static_cast<char>(my_tolower_safe(static_cast<unsigned char>(c)));
    }

    // Define suspicious keywords for different script types
    const char* SUSPICIOUS_KEYWORDS[] = {
        // PowerShell indicators
        "powershell", "invoke-expression", "iex ", "downloadstring", 
        "downloadfile", "webclient", "bitstransfer", "bypass", "encodedcommand",
        "hidden", "noninteractive", "executionpolicy", "invoke-mimikatz",
        
        // Batch/CMD indicators
        "cmd.exe", "cmd /c", "cmd/c", "command.com", "wscript", "cscript",
        
        // VBS/JS indicators
        "createobject", "wscript.shell", "shell.application", "scripting.filesystemobject",
        "adodb.stream", "activexobject", "shellexecute", "wmi", "eval(",
        
        // Generic suspicious functions
        "createprocess", "shellexecute", "rundll32", "regsvr32", "system32\\",
        "certutil", "bitsadmin", "regwrite", "registry",
        
        // Malware-related indicators
        "payload", "exploit", "dropper", "inject", "shellcode", "malware",
        "ransom", "encrypt", "decrypt", "botnet", "backdoor"
    };

    // Check for presence of suspicious keywords
    for (const char* keyword : SUSPICIOUS_KEYWORDS) {
        HookDebugLog("Suspicious keyword found: %s", keyword);
        if (content.find(keyword) != std::string::npos) {
            return true;
        }
    }

    return false;
}

// Detect common file magic numbers (including basic PE check)
bool DetectFileMagicNumbers(const BYTE* data, size_t size) {
    // Early return if data is too small
    if (size < 8) {
        return false;
    }

    // Check for PE file (EXE/DLL)
    if (size >= 0x40 && data[0] == 'M' && data[1] == 'Z') {
        // Get PE header offset
        DWORD peOffset = *reinterpret_cast<const DWORD*>(data + 0x3C);
        
        // Validate PE offset is within buffer
        if (peOffset < size - 4) {
            // Check for PE signature
            if (data[peOffset] == 'P' && data[peOffset + 1] == 'E' && 
                data[peOffset + 2] == 0 && data[peOffset + 3] == 0) {
                HookDebugLog("PE file magic number detected");
                return true;
            }
        }
    }

    // Check for common script file signatures
    const struct {
        const char* signature;
        size_t length;
        const char* description;
    } FILE_SIGNATURES[] = {
        { "#!/bin/", 7, "Shell script" },
        { "#!/usr/bin/", 11, "Shell script" },
        { "<?php", 5, "PHP script" },
        { "<%@", 3, "ASP script" },
        { "import ", 7, "Python script" },
        { "function ", 9, "JavaScript/PowerShell" },
        { "Sub ", 4, "VBScript" },
        { "class ", 6, "Java/C#/Python" },
        { "<!DOCTYPE html", 14, "HTML file" },
        { "<html", 5, "HTML file" },
        { "PK\x03\x04", 4, "ZIP archive (potentially Office file)" },
        { "\x50\x4b\x03\x04\x14\x00\x06\x00", 8, "Office Open XML format" },
        { "MSCF", 4, "Microsoft CAB file" }
    };

    for (const auto& sig : FILE_SIGNATURES) {
        if (size >= sig.length && memcmp(data, sig.signature, sig.length) == 0) {
            HookDebugLog("File signature detected: %s", sig.description);
            return true;
        }
    }

    return false;
}

// Get the directory containing the current DLL module
std::wstring GetDllPath() {
    HMODULE hModule = NULL;
    if (GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                           (LPCWSTR)&GetDllPath, // Address within the DLL
                           &hModule) == 0) {
        return L""; // Could not get module handle
    }

    wchar_t dllPath[MAX_PATH];
    if (GetModuleFileNameW(hModule, dllPath, MAX_PATH) == 0) {
        return L""; // Could not get module file name
    }

    std::wstring path(dllPath);
    size_t lastSlash = path.find_last_of(L'\\');
    if (lastSlash != std::wstring::npos) {
        return path.substr(0, lastSlash);
    }
    return L""; // Should not happen for a valid path
}

// Check if data likely contains a PE header
bool IsPEHeader(const BYTE* data, size_t size) {
    // Basic PE Check: 'MZ' at start, 'PE\0\0' at offset specified in header
    if (size >= 0x40 && data[0] == 'M' && data[1] == 'Z') {
        DWORD peOffset = *reinterpret_cast<const DWORD*>(data + 0x3C);
        if (peOffset < size - 4) {
            if (data[peOffset] == 'P' && data[peOffset + 1] == 'E' && 
                data[peOffset + 2] == 0 && data[peOffset + 3] == 0) {
                return true;
            }
        }
    }
    return false;
}

// Calculate SHA256 hash of data
std::string CalculateSHA256(const BYTE* data, size_t size) {
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    std::string resultHash = "<hash calculation failed>";
    BYTE rgbHash[32]; // SHA256 produces 32 bytes
    DWORD cbHash = 32;
    CHAR rgbDigits[] = "0123456789abcdef";
    std::vector<char> hexHash(65); // 64 hex chars + null terminator

    // Get handle to the crypto provider
    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        return resultHash; 
    }

    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
        CryptReleaseContext(hProv, 0);
        return resultHash;
    }

    if (!CryptHashData(hHash, data, static_cast<DWORD>(size), 0)) {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return resultHash;
    }

    if (CryptGetHashParam(hHash, HP_HASHVAL, rgbHash, &cbHash, 0)) {
        // Convert binary hash to hex string
        for (DWORD i = 0; i < cbHash; i++) {
            hexHash[i * 2] = rgbDigits[rgbHash[i] >> 4];
            hexHash[i * 2 + 1] = rgbDigits[rgbHash[i] & 0xf];
        }
        hexHash[64] = 0; // Null terminate
        resultHash = hexHash.data();
    }

    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);

    return resultHash;
} 