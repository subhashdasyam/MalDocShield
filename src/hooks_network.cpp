#include "../include/OfficeApiHook.h"
#include <windows.h>
#include <wininet.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <string>
#include <sstream>
#include <iomanip>
#include <regex>

#pragma comment(lib, "ws2_32.lib")

// Helper function to get address string from sockaddr structure
std::string GetAddressString(const struct sockaddr* addr, int addrLen) {
    char host[NI_MAXHOST];
    char serv[NI_MAXSERV];
    
    // Use getnameinfo to convert sockaddr to string representation
    int result = getnameinfo(addr, addrLen, host, NI_MAXHOST, serv, NI_MAXSERV, NI_NUMERICHOST | NI_NUMERICSERV);
    
    if (result == 0) {
        std::stringstream ss;
        ss << host << ":" << serv;
        return ss.str();
    }
    
    return "<unknown>";
}

// Hooked connect
int WSAAPI Hooked_connect(
    SOCKET s,
    const struct sockaddr* name,
    int namelen
) {
    // Skip monitoring if network operations are disabled
    if (!g_config.monitorNetworkOperations) {
        return Real_connect(s, name, namelen);
    }
    
    // Extract connection details before making the call
    std::string addressString = GetAddressString(name, namelen);
    int port = 0;
    
    if (name != NULL && namelen >= sizeof(struct sockaddr)) {
        // Extract port based on address family
        if (name->sa_family == AF_INET) {
            const struct sockaddr_in* addr_in = reinterpret_cast<const struct sockaddr_in*>(name);
            port = ntohs(addr_in->sin_port);
        } else if (name->sa_family == AF_INET6) {
            const struct sockaddr_in6* addr_in6 = reinterpret_cast<const struct sockaddr_in6*>(name);
            port = ntohs(addr_in6->sin6_port);
        }
    }
    
    // Combine address and port for detection/correlation
    std::string endpoint = addressString; // Already has host:port
    
    // Check if this connection is to a whitelisted endpoint
    bool isWhitelisted = false;
    for (const auto& pattern : g_config.whitelistedNetwork) {
        try {
            if (std::regex_search(endpoint, pattern)) {
                isWhitelisted = true;
                break;
            }
        } catch (...) { /* Ignore regex errors in whitelist */ }
    }

    // Only proceed with detection/logging if not whitelisted
    bool isSuspicious = false;
    if (!isWhitelisted) {
        isSuspicious = IsSuspiciousNetwork(addressString, port); // Reuse existing check
    }

    // Call original function
    int result = Real_connect(s, name, namelen);
    
    // Build log details
    std::stringstream details;
    details << "Socket: " << s << std::endl;
    details << "Address: " << addressString << std::endl;
    details << "Port: " << port << std::endl;
    details << "Result: " << (result == 0 ? "SUCCESS" : "FAILED") << std::endl;
    
    if (result != 0) {
        details << "ErrorCode: " << WSAGetLastError() << std::endl;
    }
    
    // Log the API call
    LogApiCall(NETWORK_OPERATIONS, "connect", details.str());
    
    // Raise alert or block if connection is suspicious (and not whitelisted) and successful
    if (!isWhitelisted && isSuspicious && result == 0) {
        std::stringstream alertDetails;
        alertDetails << "Suspicious network connection:" << std::endl;
        alertDetails << "Address: " << addressString << std::endl;
        alertDetails << "Port: " << port << std::endl;
        alertDetails << "Process: " << WideToUTF8(GetProcessImageName()) << " (PID: " << GetCurrentProcessId() << ")" << std::endl;
        
        bool shouldBlock = (g_config.actionOnSuspicious >= ACTION_BLOCK_ERROR);
        std::string reason = "Suspicious Network Connection to " + endpoint;

        if (shouldBlock) {
            // Log the block attempt (this function flushes)
            LogBlockedOperation(NETWORK_OPERATIONS, "connect", reason, alertDetails.str());

            // Perform configured action (Note: connect doesn't have an easy 'block')
            // For connect, blocking often means closing the socket immediately after.
            // Termination is still an option if configured.
            closesocket(s); // Close the socket to prevent communication
            result = SOCKET_ERROR; // Simulate failure
            WSASetLastError(WSAECONNREFUSED); // Set appropriate error

            if (g_config.actionOnSuspicious == ACTION_TERMINATE_THREAD) {
                 TerminateThread(GetCurrentThread(), 1); // Exit code 1
            }
            else if (g_config.actionOnSuspicious == ACTION_TERMINATE_PROCESS) {
                 TerminateProcess(GetCurrentProcess(), 1); // Exit code 1
            }
            // If ACTION_BLOCK_ERROR, we already closed the socket and set error

            // Do NOT raise alert here if blocking, LogBlockedOperation handles it.
        } else {
             // Just Log/Alert if action is Log Only
             RaiseAlert(NETWORK_OPERATIONS, reason, alertDetails.str());
        }
        
        // Mark this thread as having recent suspicious network activity (even if blocked)
        DWORD threadId = GetCurrentThreadId();
        g_threadSuspiciousNetworkActivity[threadId] = { std::chrono::system_clock::now(), endpoint };
    }
    
    return result;
}

// Hooked HttpOpenRequestW
HINTERNET WINAPI Hooked_HttpOpenRequestW(
    HINTERNET hConnect,
    LPCWSTR lpszVerb,
    LPCWSTR lpszObjectName,
    LPCWSTR lpszVersion,
    LPCWSTR lpszReferer,
    LPCWSTR* lplpszAcceptTypes,
    DWORD dwFlags,
    DWORD_PTR dwContext
) {
    // Skip monitoring if network operations are disabled
    if (!g_config.monitorNetworkOperations) {
        return Real_HttpOpenRequestW(hConnect, lpszVerb, lpszObjectName, lpszVersion, 
                                     lpszReferer, lplpszAcceptTypes, dwFlags, dwContext);
    }
    
    // Call original function
    HINTERNET hResult = Real_HttpOpenRequestW(hConnect, lpszVerb, lpszObjectName, lpszVersion, 
                                             lpszReferer, lplpszAcceptTypes, dwFlags, dwContext);
    
    // Build log details
    std::stringstream details;
    details << "Connection Handle: 0x" << std::hex << (DWORD_PTR)hConnect << std::dec << std::endl;
    details << "Verb: " << (lpszVerb ? WideToUTF8(lpszVerb) : "GET") << std::endl;
    details << "Object: " << (lpszObjectName ? WideToUTF8(lpszObjectName) : "/") << std::endl;
    details << "Version: " << (lpszVersion ? WideToUTF8(lpszVersion) : "HTTP/1.1") << std::endl;
    details << "Referer: " << (lpszReferer ? WideToUTF8(lpszReferer) : "<NULL>") << std::endl;
    
    // Build flags string
    std::stringstream flagsStr;
    if (dwFlags & INTERNET_FLAG_SECURE) flagsStr << "SECURE ";
    if (dwFlags & INTERNET_FLAG_KEEP_CONNECTION) flagsStr << "KEEP_CONNECTION ";
    if (dwFlags & INTERNET_FLAG_NO_CACHE_WRITE) flagsStr << "NO_CACHE_WRITE ";
    if (dwFlags & INTERNET_FLAG_PRAGMA_NOCACHE) flagsStr << "PRAGMA_NOCACHE ";
    if (dwFlags & INTERNET_FLAG_NO_COOKIES) flagsStr << "NO_COOKIES ";
    
    details << "Flags: 0x" << std::hex << dwFlags << std::dec << " (" << flagsStr.str() << ")" << std::endl;
    details << "Result: " << (hResult ? "SUCCESS" : "FAILED") << std::endl;
    
    if (!hResult) {
        details << "ErrorCode: " << GetLastError() << std::endl;
    }
    
    // Log the API call
    LogApiCall(NETWORK_OPERATIONS, "HttpOpenRequestW", details.str());
    
    // For suspicious detection, we'd need the server name which is not directly available here
    // The full URL is split between InternetConnectW (server) and HttpOpenRequestW (path)
    // For now, we'll just check if the path contains any suspicious keywords
    
    if (lpszObjectName != NULL && hResult != NULL) {
        std::wstring objectName = lpszObjectName;
        std::string utf8ObjectName = WideToUTF8(objectName);
        
        // Check for suspicious objects/paths (simple check for now)
        const char* SUSPICIOUS_PATHS[] = {
            "/shell", "/cmd", "/exec", "/powershell", "/eval", "/admin", 
            "/upload", "/download", "/c2", "/command", "/backdoor", "/exploit"
        };
        
        for (const char* path : SUSPICIOUS_PATHS) {
            if (utf8ObjectName.find(path) != std::string::npos) {
                std::stringstream alertDetails;
                alertDetails << "Suspicious HTTP request path:" << std::endl;
                alertDetails << "Path: " << utf8ObjectName << std::endl;
                alertDetails << "Verb: " << (lpszVerb ? WideToUTF8(lpszVerb) : "GET") << std::endl;
                alertDetails << "Process: " << WideToUTF8(GetProcessImageName()) << " (PID: " << GetCurrentProcessId() << ")" << std::endl;
                
                RaiseAlert(NETWORK_OPERATIONS, "Suspicious HTTP Request", alertDetails.str());
                
                // Mark this thread as having recent suspicious network activity
                DWORD threadId = GetCurrentThreadId();
                std::string request_endpoint_info = "Path: " + utf8ObjectName;
                g_threadSuspiciousNetworkActivity[threadId] = { std::chrono::system_clock::now(), request_endpoint_info };
                break;
            }
        }
    }
    
    return hResult;
}

// Hooked InternetConnectW
HINTERNET WINAPI Hooked_InternetConnectW(
    HINTERNET hInternet,
    LPCWSTR lpszServerName,
    INTERNET_PORT nServerPort,
    LPCWSTR lpszUsername,
    LPCWSTR lpszPassword,
    DWORD dwService,
    DWORD dwFlags,
    DWORD_PTR dwContext
) {
    // Skip monitoring if network operations are disabled
    if (!g_config.monitorNetworkOperations) {
        return Real_InternetConnectW(hInternet, lpszServerName, nServerPort, lpszUsername,
                                    lpszPassword, dwService, dwFlags, dwContext);
    }
    
    // Skip logging/detection for null server names
    if (lpszServerName == NULL) {
        return Real_InternetConnectW(hInternet, lpszServerName, nServerPort, lpszUsername,
                                    lpszPassword, dwService, dwFlags, dwContext);
    }

    std::string serverName = WideToUTF8(lpszServerName);
    std::string endpoint = serverName + ":" + std::to_string(nServerPort);
    
    // Check whitelist
    bool isWhitelisted = false;
    for (const auto& pattern : g_config.whitelistedNetwork) {
         try {
            if (std::regex_search(endpoint, pattern) || std::regex_search(serverName, pattern)) {
                isWhitelisted = true;
                break;
            }
        } catch (...) { /* Ignore regex errors in whitelist */ }
    }
    
    // Check if this is a suspicious connection
    bool isSuspicious = false;
    if (!isWhitelisted) {
        isSuspicious = IsSuspiciousNetwork(serverName, nServerPort);
    }

    // Call original function
    HINTERNET hResult = Real_InternetConnectW(hInternet, lpszServerName, nServerPort, lpszUsername,
                                             lpszPassword, dwService, dwFlags, dwContext);

    // Build log details
    std::stringstream details;
    details << "Internet Handle: 0x" << std::hex << (DWORD_PTR)hInternet << std::dec << std::endl;
    details << "Server: " << serverName << std::endl;
    details << "Port: " << nServerPort << std::endl;
    details << "Service: " << dwService << std::endl;
    
    if (lpszUsername != NULL) {
        details << "Username: " << WideToUTF8(lpszUsername) << std::endl;
    }
    
    if (lpszPassword != NULL) {
        details << "Password: <REDACTED>" << std::endl;  // Don't log actual password
    }
    
    details << "Result: " << (hResult ? "SUCCESS" : "FAILED") << std::endl;
    
    if (!hResult) {
        details << "ErrorCode: " << GetLastError() << std::endl;
    }
    
    // Log the API call
    LogApiCall(NETWORK_OPERATIONS, "InternetConnectW", details.str());
    
    // Raise alert or block if connection is suspicious (and not whitelisted) and successful
    if (!isWhitelisted && isSuspicious && hResult) {
        std::stringstream alertDetails;
        alertDetails << "Suspicious Internet connection:" << std::endl;
        alertDetails << "Server: " << serverName << std::endl;
        alertDetails << "Port: " << nServerPort << std::endl;
        alertDetails << "Service: " << dwService << std::endl;
        alertDetails << "Process: " << WideToUTF8(GetProcessImageName()) << " (PID: " << GetCurrentProcessId() << ")" << std::endl;
        
        bool shouldBlock = (g_config.actionOnSuspicious >= ACTION_BLOCK_ERROR);
        std::string reason = "Suspicious Internet Connection to " + endpoint;

         if (shouldBlock) {
            // Log the block attempt (this function flushes)
            LogBlockedOperation(NETWORK_OPERATIONS, "InternetConnectW", reason, alertDetails.str());

            // Perform configured action
            // To block InternetConnect, we return NULL and set an error
            // We don't have the HINTERNET handle yet if blocking *this* call.
            // Instead, we rely on returning NULL and setting error.
            if (hResult) { InternetCloseHandle(hResult); } // Close handle if it was somehow created
            hResult = NULL; // Simulate failure
            SetLastError(ERROR_INTERNET_CANNOT_CONNECT); // Set appropriate error

             if (g_config.actionOnSuspicious == ACTION_TERMINATE_THREAD) {
                 TerminateThread(GetCurrentThread(), 1);
            }
            else if (g_config.actionOnSuspicious == ACTION_TERMINATE_PROCESS) {
                 TerminateProcess(GetCurrentProcess(), 1);
            }
            // If ACTION_BLOCK_ERROR, we already nulled handle and set error

        } else {
             // Just Log/Alert if action is Log Only
             RaiseAlert(NETWORK_OPERATIONS, reason, alertDetails.str());
        }
        
        // Mark this thread as having recent suspicious network activity (even if blocked)
        DWORD threadId = GetCurrentThreadId();
        g_threadSuspiciousNetworkActivity[threadId] = { std::chrono::system_clock::now(), endpoint };
    }
    
    return hResult;
} 