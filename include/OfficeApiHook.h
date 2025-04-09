#pragma once

#define WIN32_LEAN_AND_MEAN             // Exclude rarely-used stuff from Windows headers
#define NOMINMAX                        // Exclude min/max macros from windows.h

// Winsock Headers - Include before windows.h
#include <winsock2.h>
#include <ws2tcpip.h>

// Other Windows Headers
#include <windows.h>
#include <wininet.h>

// Standard Library Headers (Include before Detours, just in case)
#include <string>
#include <vector>
#include <map>
#include <mutex>
#include <regex>
#include <chrono>
#include <fstream>
#include <sstream>
#include <set>
#include <algorithm>

// Detours Header (Include after Windows/Standard headers)
#include <detours.h>

// API Hooking Categories
enum HookCategory {
    FILE_OPERATIONS,
    REGISTRY_OPERATIONS,
    PROCESS_OPERATIONS,
    NETWORK_OPERATIONS,
    MEMORY_OPERATIONS,
    DLL_OPERATIONS,
    CRYPTO_OPERATIONS
};

// Alert Configuration
enum AlertLevel {
    ALERT_NONE = 0,
    ALERT_LOG_ONLY = 1,
    ALERT_MESSAGEBOX_ONLY = 2,
    ALERT_LOG_AND_MESSAGEBOX = 3
};

// Action to take on suspicious activity detection
enum SuspiciousAction {
    ACTION_LOG_ONLY = 0,         // Default: Only log the suspicious event
    ACTION_BLOCK_ERROR = 1,    // Log, prevent the API call, return an error
    ACTION_TERMINATE_THREAD = 2, // Log, prevent API call, terminate the calling thread (Use with caution!)
    ACTION_TERMINATE_PROCESS = 3 // Log, prevent API call, terminate the entire process (Use with extreme caution!)
};

// Configuration Structure
struct HookConfig {
    // File Operations
    bool monitorFileOperations;
    std::vector<std::wregex> suspiciousPaths;
    std::vector<std::wregex> suspiciousExtensions;
    std::vector<std::wregex> whitelistedPaths; // Whitelist

    // Registry Operations
    bool monitorRegistryOperations;
    std::vector<std::wregex> suspiciousKeys;
    std::vector<std::wregex> whitelistedKeys; // Whitelist

    // Process Operations
    bool monitorProcessOperations;
    std::vector<std::string> suspiciousProcesses;
    std::vector<std::string> whitelistedProcesses; // Whitelist

    // Network Operations
    bool monitorNetworkOperations;
    std::vector<std::regex> suspiciousAddresses;
    std::vector<int> suspiciousPorts;
    std::vector<std::regex> whitelistedNetwork; // Whitelist addresses/domains

    // Memory Operations
    bool monitorMemoryOperations;

    // DLL Operations
    bool monitorDllOperations;
    std::vector<std::wregex> suspiciousDlls;
    std::vector<std::wregex> whitelistedDlls; // Whitelist

    // Crypto Operations
    bool monitorCryptoOperations;

    // Analysis Options
    bool analyzePEHeaders; // Perform basic PE header checks on write/load
    bool hashWrittenFiles; // Calculate and log SHA256 hash of written file content

    // Alerts
    bool showAlerts;
    int maxAlertsPerCategory;
    AlertLevel alertLogLevel;

    // Action Configuration
    SuspiciousAction actionOnSuspicious; // Action to take when something suspicious is detected

    // Debug
    bool enableDebugLog;
};

// Forward declarations
bool InitializeHooks();
void FinalizeHooks();
bool LoadConfiguration();
void SetDefaultSuspiciousPatterns();
void InitializeLogging();
void CloseLogging();
void LogApiCall(HookCategory category, const char* functionName, const std::string& details);
void HookDebugLog(const char* format, ...);
bool RaiseAlert(HookCategory category, const std::string& reason, const std::string& details);
bool IsSuspiciousFilePath(const std::wstring& filePath);
bool IsSuspiciousRegistryKey(const std::wstring& keyPath);
bool IsSuspiciousProcess(const std::wstring& processName);
bool IsSuspiciousNetwork(const std::string& address, int port);
bool IsSuspiciousDll(const std::wstring& dllName);
double CalculateEntropy(const BYTE* data, size_t size);
bool ContainsSuspiciousKeywords(const BYTE* data, size_t size);
bool DetectFileMagicNumbers(const BYTE* data, size_t size);
DWORD WINAPI InjectionThreadProc(LPVOID lpParameter);
void InjectIntoProcess(DWORD processId);

// Utility functions
std::wstring GetDllPath();
std::wstring GetProcessImageName();
std::wstring GetProcessImageNameFromPID(DWORD pid);
std::wstring GetFileNameFromPath(const std::wstring& path);
std::string WideToUTF8(const std::wstring& wide);
std::wstring UTF8ToWide(const std::string& utf8);
std::vector<std::string> SplitString(const std::string& str, char delimiter);
std::string GetCurrentTimeFormatted();

// Global variables (defined in the cpp file)
extern HookConfig g_config;
extern std::mutex g_logMutex;
extern std::ofstream g_logFile;
extern std::ofstream g_debugLogFile;
extern std::map<HANDLE, std::wstring> g_handleToPath;
extern std::map<std::string, int> g_alertCount;

// API Declarations for Hook Functions
// These declarations match the Windows API functions we'll hook

// File Operations
extern "C" {
    // Original function pointers
    extern HANDLE(WINAPI* Real_CreateFileW)(
        LPCWSTR lpFileName,
        DWORD dwDesiredAccess,
        DWORD dwShareMode,
        LPSECURITY_ATTRIBUTES lpSecurityAttributes,
        DWORD dwCreationDisposition,
        DWORD dwFlagsAndAttributes,
        HANDLE hTemplateFile
    );

    extern HANDLE(WINAPI* Real_CreateFileA)(
        LPCSTR lpFileName,
        DWORD dwDesiredAccess,
        DWORD dwShareMode,
        LPSECURITY_ATTRIBUTES lpSecurityAttributes,
        DWORD dwCreationDisposition,
        DWORD dwFlagsAndAttributes,
        HANDLE hTemplateFile
    );

    extern BOOL(WINAPI* Real_WriteFile)(
        HANDLE hFile,
        LPCVOID lpBuffer,
        DWORD nNumberOfBytesToWrite,
        LPDWORD lpNumberOfBytesWritten,
        LPOVERLAPPED lpOverlapped
    );

    extern BOOL(WINAPI* Real_CloseHandle)(
        HANDLE hObject
    );

    // Hooked function declarations
    HANDLE WINAPI Hooked_CreateFileW(
        LPCWSTR lpFileName,
        DWORD dwDesiredAccess,
        DWORD dwShareMode,
        LPSECURITY_ATTRIBUTES lpSecurityAttributes,
        DWORD dwCreationDisposition,
        DWORD dwFlagsAndAttributes,
        HANDLE hTemplateFile
    );

    HANDLE WINAPI Hooked_CreateFileA(
        LPCSTR lpFileName,
        DWORD dwDesiredAccess,
        DWORD dwShareMode,
        LPSECURITY_ATTRIBUTES lpSecurityAttributes,
        DWORD dwCreationDisposition,
        DWORD dwFlagsAndAttributes,
        HANDLE hTemplateFile
    );

    BOOL WINAPI Hooked_WriteFile(
        HANDLE hFile,
        LPCVOID lpBuffer,
        DWORD nNumberOfBytesToWrite,
        LPDWORD lpNumberOfBytesWritten,
        LPOVERLAPPED lpOverlapped
    );

    BOOL WINAPI Hooked_CloseHandle(
        HANDLE hObject
    );

    // Process Operations
    extern BOOL(WINAPI* Real_CreateProcessW)(
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
    );

    extern BOOL(WINAPI* Real_CreateProcessA)(
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
    );

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
    );

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
    );

    // Registry Operations
    extern LONG(WINAPI* Real_RegOpenKeyExW)(
        HKEY hKey,
        LPCWSTR lpSubKey,
        DWORD ulOptions,
        REGSAM samDesired,
        PHKEY phkResult
    );

    extern LONG(WINAPI* Real_RegOpenKeyExA)(
        HKEY hKey,
        LPCSTR lpSubKey,
        DWORD ulOptions,
        REGSAM samDesired,
        PHKEY phkResult
    );

    extern LONG(WINAPI* Real_RegSetValueExW)(
        HKEY hKey,
        LPCWSTR lpValueName,
        DWORD Reserved,
        DWORD dwType,
        CONST BYTE* lpData,
        DWORD cbData
    );

    extern LONG(WINAPI* Real_RegSetValueExA)(
        HKEY hKey,
        LPCSTR lpValueName,
        DWORD Reserved,
        DWORD dwType,
        CONST BYTE* lpData,
        DWORD cbData
    );

    LONG WINAPI Hooked_RegOpenKeyExW(
        HKEY hKey,
        LPCWSTR lpSubKey,
        DWORD ulOptions,
        REGSAM samDesired,
        PHKEY phkResult
    );

    LONG WINAPI Hooked_RegOpenKeyExA(
        HKEY hKey,
        LPCSTR lpSubKey,
        DWORD ulOptions,
        REGSAM samDesired,
        PHKEY phkResult
    );

    LONG WINAPI Hooked_RegSetValueExW(
        HKEY hKey,
        LPCWSTR lpValueName,
        DWORD Reserved,
        DWORD dwType,
        CONST BYTE* lpData,
        DWORD cbData
    );

    LONG WINAPI Hooked_RegSetValueExA(
        HKEY hKey,
        LPCSTR lpValueName,
        DWORD Reserved,
        DWORD dwType,
        CONST BYTE* lpData,
        DWORD cbData
    );

    // Network Operations
    extern int (WSAAPI* Real_connect)(
        SOCKET s,
        const struct sockaddr* name,
        int namelen
    );

    extern HINTERNET (WINAPI* Real_HttpOpenRequestW)(
        HINTERNET hConnect,
        LPCWSTR lpszVerb,
        LPCWSTR lpszObjectName,
        LPCWSTR lpszVersion,
        LPCWSTR lpszReferer,
        LPCWSTR* lplpszAcceptTypes,
        DWORD dwFlags,
        DWORD_PTR dwContext
    );

    extern HINTERNET (WINAPI* Real_InternetConnectW)(
        HINTERNET hInternet,
        LPCWSTR lpszServerName,
        INTERNET_PORT nServerPort,
        LPCWSTR lpszUsername,
        LPCWSTR lpszPassword,
        DWORD dwService,
        DWORD dwFlags,
        DWORD_PTR dwContext
    );

    // Hooked function declarations
    int WSAAPI Hooked_connect(
        SOCKET s,
        const struct sockaddr* name,
        int namelen
    );

    HINTERNET WINAPI Hooked_HttpOpenRequestW(
        HINTERNET hConnect,
        LPCWSTR lpszVerb,
        LPCWSTR lpszObjectName,
        LPCWSTR lpszVersion,
        LPCWSTR lpszReferer,
        LPCWSTR* lplpszAcceptTypes,
        DWORD dwFlags,
        DWORD_PTR dwContext
    );

    HINTERNET WINAPI Hooked_InternetConnectW(
        HINTERNET hInternet,
        LPCWSTR lpszServerName,
        INTERNET_PORT nServerPort,
        LPCWSTR lpszUsername,
        LPCWSTR lpszPassword,
        DWORD dwService,
        DWORD dwFlags,
        DWORD_PTR dwContext
    );

    // DLL Operations
    extern HMODULE(WINAPI* Real_LoadLibraryW)(
        LPCWSTR lpLibFileName
    );

    extern HMODULE(WINAPI* Real_LoadLibraryA)(
        LPCSTR lpLibFileName
    );

    extern HMODULE(WINAPI* Real_LoadLibraryExW)(
        LPCWSTR lpLibFileName,
        HANDLE hFile,
        DWORD dwFlags
    );

    HMODULE WINAPI Hooked_LoadLibraryW(
        LPCWSTR lpLibFileName
    );

    HMODULE WINAPI Hooked_LoadLibraryA(
        LPCSTR lpLibFileName
    );

    HMODULE WINAPI Hooked_LoadLibraryExW(
        LPCWSTR lpLibFileName,
        HANDLE hFile,
        DWORD dwFlags
    );

    // Memory Operations
    extern LPVOID(WINAPI* Real_VirtualAlloc)(
        LPVOID lpAddress,
        SIZE_T dwSize,
        DWORD flAllocationType,
        DWORD flProtect
    );

    extern BOOL(WINAPI* Real_VirtualProtect)(
        LPVOID lpAddress,
        SIZE_T dwSize,
        DWORD flNewProtect,
        PDWORD lpflOldProtect
    );

    LPVOID WINAPI Hooked_VirtualAlloc(
        LPVOID lpAddress,
        SIZE_T dwSize,
        DWORD flAllocationType,
        DWORD flProtect
    );

    BOOL WINAPI Hooked_VirtualProtect(
        LPVOID lpAddress,
        SIZE_T dwSize,
        DWORD flNewProtect,
        PDWORD lpflOldProtect
    );
}

// New forward declarations
void LogBlockedOperation(HookCategory category, const char* functionName, const std::string& reason, const std::string& details);
std::string CalculateSHA256(const BYTE* data, size_t size); 
bool IsPEHeader(const BYTE* data, size_t size);
unsigned char my_tolower_safe(unsigned char c);

// Updated Correlation Data
struct SuspiciousNetworkInfo {
    std::chrono::system_clock::time_point time;
    std::string endpoint; // e.g., "1.2.3.4:80" or "malicious.com:443"
};
extern std::map<DWORD, SuspiciousNetworkInfo> g_threadSuspiciousNetworkActivity; // ThreadID -> Info 