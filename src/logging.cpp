#include "../include/OfficeApiHook.h"

// Necessary headers (like windows.h, string, fstream, etc.) are included via OfficeApiHook.h

#include <iomanip>
#include <ctime>
#include <cstdarg>
#include <thread>

// Initialize logging files
void InitializeLogging() {
    std::wstring processName = GetProcessImageName();
    std::wstring dllPath = GetDllPath();
    DWORD pid = GetCurrentProcessId();

    if (dllPath.empty()) {
        dllPath = L".\\"; // Fallback to current directory if path is empty
    }

    // Ensure path ends with a backslash
    if (!dllPath.empty() && dllPath.back() != L'\\') {
        dllPath += L'\\';
    }

    // Get current time for log file names
    auto now = std::chrono::system_clock::now();
    std::time_t now_time = std::chrono::system_clock::to_time_t(now);
    std::tm local_tm;
    localtime_s(&local_tm, &now_time);

    wchar_t timeBuffer[32];
    wcsftime(timeBuffer, sizeof(timeBuffer) / sizeof(wchar_t), L"%Y%m%d_%H%M%S", &local_tm);

    // Create API trace log filename
    std::wstringstream apiLogNameStream;
    apiLogNameStream << dllPath << L"api_trace_" << processName << L"_" << timeBuffer << L"_" << pid << L".log";
    std::wstring apiLogName = apiLogNameStream.str();

    g_logFile.open(apiLogName);
    if (!g_logFile.is_open()) {
        MessageBoxW(NULL, L"Failed to create API trace log file. Check permissions or path.", L"OfficeApiHook Log Error", MB_OK | MB_ICONERROR);
    } else {
        // Initialize the API trace log with header information
        g_logFile << "==================================================" << std::endl;
        g_logFile << "OfficeApiHook API Trace Log" << std::endl;
        g_logFile << "Process: " << WideToUTF8(processName) << " (PID: " << pid << ")" << std::endl;
        g_logFile << "Date/Time: " << WideToUTF8(timeBuffer) << std::endl;
        g_logFile << "==================================================" << std::endl << std::endl;
    }

    // Create Debug log if enabled
    if (g_config.enableDebugLog) {
        std::wstringstream debugLogNameStream;
        debugLogNameStream << dllPath << L"debug_trace_" << processName << L"_" << timeBuffer << L"_" << pid << L".log";
        std::wstring debugLogName = debugLogNameStream.str();

        g_debugLogFile.open(debugLogName);
        if (!g_debugLogFile.is_open()) {
            if (g_logFile.is_open()) {
                 g_logFile << "ERROR: Failed to create debug log file: " << WideToUTF8(debugLogName) << std::endl;
            }
        } else {
            // Initialize the debug log with header information
            g_debugLogFile << "==================================================" << std::endl;
            g_debugLogFile << "OfficeApiHook Debug Log" << std::endl;
            g_debugLogFile << "Process: " << WideToUTF8(processName) << " (PID: " << pid << ")" << std::endl;
            g_debugLogFile << "Date/Time: " << WideToUTF8(timeBuffer) << std::endl;
            g_debugLogFile << "==================================================" << std::endl << std::endl;
        }
    }
}

// Close log files
void CloseLogging() {
    std::lock_guard<std::mutex> lock(g_logMutex);
    if (g_logFile.is_open()) {
        g_logFile << std::endl << "==================================================" << std::endl;
        g_logFile << "Logging ended: " << GetCurrentTimeFormatted() << std::endl;
        g_logFile << "==================================================" << std::endl;
        g_logFile.close();
    }

    if (g_debugLogFile.is_open()) {
        g_debugLogFile << std::endl << "==================================================" << std::endl;
        g_debugLogFile << "Debug logging ended: " << GetCurrentTimeFormatted() << std::endl;
        g_debugLogFile << "==================================================" << std::endl;
        g_debugLogFile.close();
    }
}

// Log API call details to the trace log
void LogApiCall(HookCategory category, const char* functionName, const std::string& details) {
    std::lock_guard<std::mutex> lock(g_logMutex);
    if (!g_logFile.is_open()) {
        return;
    }

    if (!g_logFile.good()) {
        g_logFile.clear(); // Attempt to clear error flags
    }

    // Get category name
    std::string categoryName;
    switch (category) {
        case FILE_OPERATIONS:
            categoryName = "File Operations";
            break;
        case REGISTRY_OPERATIONS:
            categoryName = "Registry Operations";
            break;
        case PROCESS_OPERATIONS:
            categoryName = "Process Operations";
            break;
        case NETWORK_OPERATIONS:
            categoryName = "Network Operations";
            break;
        case MEMORY_OPERATIONS:
            categoryName = "Memory Operations";
            break;
        case DLL_OPERATIONS:
            categoryName = "DLL Operations";
            break;
        case CRYPTO_OPERATIONS:
            categoryName = "Crypto Operations";
            break;
        default:
            categoryName = "Unknown Category";
            break;
    }

    // Format the log entry
    std::stringstream headerStream;
    headerStream << "[" << GetCurrentTimeFormatted() << "] ";
    headerStream << "[Thread " << GetCurrentThreadId() << "] ";
    headerStream << "[" << categoryName << "] ";
    headerStream << "[" << functionName << "] ";
    headerStream << std::endl;
    
    g_logFile << headerStream.str();
    if (!g_logFile.good()) {
        return;
    }
    
    // If details are provided, add them with indentation
    if (!details.empty()) {
        std::istringstream detailStream(details);
        std::string line;
        while (std::getline(detailStream, line)) {
            g_logFile << "    " << line << std::endl;
            if (!g_logFile.good()) {
                 break; // Stop trying to write details if stream is bad
            }
        }
    }
    
    g_logFile << std::endl;
    g_logFile.flush();
}

// Log a blocked operation (designed to be called before returning error/terminating)
void LogBlockedOperation(HookCategory category, const char* functionName, const std::string& reason, const std::string& details) {
    std::lock_guard<std::mutex> lock(g_logMutex);
    if (!g_logFile.is_open()) {
        // Attempt to log to debug output as a last resort
        OutputDebugStringA(("[BLOCKED] API Log File Closed! Operation: " + std::string(functionName) + " Reason: " + reason).c_str());
        return;
    }

    if (!g_logFile.good()) {
        g_logFile.clear(); // Attempt to clear error flags
    }

    // Get category name
    std::string categoryName;
    switch (category) {
        case FILE_OPERATIONS: categoryName = "File Operations"; break;
        case REGISTRY_OPERATIONS: categoryName = "Registry Operations"; break;
        case PROCESS_OPERATIONS: categoryName = "Process Operations"; break;
        case NETWORK_OPERATIONS: categoryName = "Network Operations"; break;
        case MEMORY_OPERATIONS: categoryName = "Memory Operations"; break;
        case DLL_OPERATIONS: categoryName = "DLL Operations"; break;
        case CRYPTO_OPERATIONS: categoryName = "Crypto Operations"; break;
        default: categoryName = "Unknown Category"; break;
    }

    // Format the log entry
    g_logFile << "[! BLOCKED OPERATION !]" << std::endl;
    g_logFile << "[" << GetCurrentTimeFormatted() << "] ";
    g_logFile << "[Thread " << GetCurrentThreadId() << "] ";
    g_logFile << "[Category: " << categoryName << "] ";
    g_logFile << "[Function: " << functionName << "]" << std::endl;
    g_logFile << "Reason: " << reason << std::endl;
    
    // If details are provided, add them with indentation
    if (!details.empty()) {
        g_logFile << "--- Details --- " << std::endl;
        std::istringstream detailStream(details);
        std::string line;
        while (std::getline(detailStream, line)) {
            g_logFile << "    " << line << std::endl;
        }
        g_logFile << "--------------- " << std::endl;
    }
    
    g_logFile << std::endl;
    g_logFile.flush(); // Ensure data is written immediately
}

// Log debug messages to the debug log (Renamed from DebugLog)
void HookDebugLog(const char* format, ...) {
    // If debug logging isn't enabled, just return
    if (!g_config.enableDebugLog) {
        return;
    }

    char buffer[4096] = { 0 };
    va_list args;
    va_start(args, format);
    vsnprintf(buffer, sizeof(buffer) - 1, format, args);
    va_end(args);

    // Also send to OutputDebugString
    OutputDebugStringA(buffer);
    OutputDebugStringA("\n");

    std::lock_guard<std::mutex> lock(g_logMutex);
    if (!g_debugLogFile.is_open()) {
        return;
    }

    g_debugLogFile << "[" << GetCurrentTimeFormatted() << "] [Thread " << GetCurrentThreadId() << "] " << buffer << std::endl;
    g_debugLogFile.flush();
}

// Raise alert for suspicious activity
bool RaiseAlert(HookCategory category, const std::string& reason, const std::string& details) {
    // If alerting is disabled or this alert has been raised too many times, ignore it
    std::string alertKey = std::to_string(static_cast<int>(category)) + ":" + reason;
    
    // Check if we've exceeded the maximum alert count for this category
    if (g_alertCount[alertKey] >= g_config.maxAlertsPerCategory) {
        return false;
    }
    
    // Increment the alert count
    g_alertCount[alertKey]++;
    
    // Get category name
    std::string categoryName;
    switch (category) {
        case FILE_OPERATIONS:
            categoryName = "File Operations";
            break;
        case REGISTRY_OPERATIONS:
            categoryName = "Registry Operations";
            break;
        case PROCESS_OPERATIONS:
            categoryName = "Process Operations";
            break;
        case NETWORK_OPERATIONS:
            categoryName = "Network Operations";
            break;
        case MEMORY_OPERATIONS:
            categoryName = "Memory Operations";
            break;
        case DLL_OPERATIONS:
            categoryName = "DLL Operations";
            break;
        case CRYPTO_OPERATIONS:
            categoryName = "Crypto Operations";
            break;
        default:
            categoryName = "Unknown Category";
            break;
    }
    
    // Format alert message
    std::stringstream alertMessage;
    alertMessage << "!!! SUSPICIOUS ACTIVITY DETECTED !!!" << std::endl;
    alertMessage << "Category: " << categoryName << std::endl;
    alertMessage << "Reason: " << reason << std::endl;
    alertMessage << "Details:" << std::endl;
    
    // Split details by line for better formatting
    std::istringstream detailStream(details);
    std::string line;
    while (std::getline(detailStream, line)) {
        alertMessage << "    " << line << std::endl;
    }
    
    // Log the alert to the API trace log if configured
    if (g_config.alertLogLevel & ALERT_LOG_ONLY) {
        std::lock_guard<std::mutex> lock(g_logMutex);
        if (g_logFile.is_open()) {
            g_logFile << alertMessage.str() << std::endl;
            g_logFile.flush();
        }
    }
    
    // Show MessageBox alert if configured
    if ((g_config.alertLogLevel & ALERT_MESSAGEBOX_ONLY) && g_config.showAlerts) {
        std::stringstream msgTitleStream;
        msgTitleStream << "OfficeApiHook Alert: " << categoryName;
        std::string titleStr = msgTitleStream.str();
        std::string messageStr = alertMessage.str();
        
        // Show the message box on a separate thread to avoid blocking the application
        std::thread alertThread([titleStr, messageStr]() {
            MessageBoxA(NULL, messageStr.c_str(), titleStr.c_str(), MB_OK | MB_ICONWARNING);
        });
        alertThread.detach();
    }
    
    return true;
}

// Get the formatted current time for log entries
std::string GetCurrentTimeFormatted() {
    auto now = std::chrono::system_clock::now();
    auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()) % 1000;
    std::time_t now_time = std::chrono::system_clock::to_time_t(now);
    
    std::tm local_tm;
    localtime_s(&local_tm, &now_time);
    
    std::stringstream timeStream;
    timeStream << std::put_time(&local_tm, "%Y-%m-%d %H:%M:%S") << '.' << std::setfill('0') << std::setw(3) << now_ms.count();
    return timeStream.str();
} 