#include "../include/OfficeApiHook.h"
#include <windows.h>
#include <fstream>
#include <sstream>
#include <string>
#include <regex>
#include <algorithm>
#include <cctype>

// Global variables defined in dllmain.cpp
// HookConfig g_config; (already declared extern in header)

// Helper function to trim whitespace from strings
std::string Trim(const std::string& str) {
    auto start = std::find_if_not(str.begin(), str.end(), [](unsigned char c) { return std::isspace(c); });
    auto end = std::find_if_not(str.rbegin(), str.rend(), [](unsigned char c) { return std::isspace(c); }).base();
    return (start < end) ? std::string(start, end) : std::string();
}

// Helper function to convert string to boolean
bool StringToBool(const std::string& value) {
    std::string lowerValue = Trim(value);
    std::transform(lowerValue.begin(), lowerValue.end(), lowerValue.begin(), ::tolower);
    return lowerValue == "true" || lowerValue == "1" || lowerValue == "yes";
}

// Load configuration from config.ini file or set defaults
bool LoadConfiguration() {
    // Set defaults first
    SetDefaultSuspiciousPatterns();

    // Construct the path to config.ini
    std::wstring dllDir = GetDllPath();
    std::wstring configPath = dllDir + L"config.ini";

    std::ifstream configFile(configPath);
    if (!configFile.is_open()) {
        HookDebugLog("Config file not found (%ws), using default configuration", configPath.c_str());
        return false; // Stick with defaults if file doesn't exist
    }

    HookDebugLog("Loading configuration from %ws", configPath.c_str());

    std::string line;
    std::string currentSection;

    while (std::getline(configFile, line)) {
        // Skip empty lines and comments
        line = Trim(line);
        if (line.empty() || line[0] == ';' || line[0] == '#') {
            continue;
        }

        // Check for section header
        if (line[0] == '[' && line[line.length() - 1] == ']') {
            currentSection = line.substr(1, line.length() - 2);
            continue;
        }

        // Find key-value separator
        size_t separatorPos = line.find('=');
        if (separatorPos == std::string::npos) {
            continue;
        }

        std::string key = Trim(line.substr(0, separatorPos));
        std::string value = Trim(line.substr(separatorPos + 1));

        // Process configuration based on section and key
        if (currentSection == "FileOperations") {
            if (key == "Monitor") {
                g_config.monitorFileOperations = StringToBool(value);
            }
            else if (key == "SuspiciousPaths") {
                // Reset the vector first
                g_config.suspiciousPaths.clear();
                
                // Parse comma-separated regex patterns
                std::vector<std::string> patterns = SplitString(value, ',');
                for (const auto& pattern : patterns) {
                    try {
                        // Convert narrow pattern to wide string before creating wregex
                        std::wstring widePattern = UTF8ToWide(pattern);
                        std::wregex regexPattern(widePattern, std::regex::icase);
                        g_config.suspiciousPaths.push_back(regexPattern);
                    }
                    catch (const std::regex_error&) {
                        HookDebugLog("Invalid regex pattern for SuspiciousPaths: %s", pattern.c_str());
                    }
                }
            }
            else if (key == "SuspiciousExtensions") {
                // Reset the vector first
                g_config.suspiciousExtensions.clear();
                
                // Parse comma-separated regex patterns
                std::vector<std::string> patterns = SplitString(value, ',');
                for (const auto& pattern : patterns) {
                    try {
                        // Convert narrow pattern to wide string before creating wregex
                        std::wstring widePattern = UTF8ToWide(pattern);
                        std::wregex regexPattern(widePattern, std::regex::icase);
                        g_config.suspiciousExtensions.push_back(regexPattern);
                    }
                    catch (const std::regex_error&) {
                        HookDebugLog("Invalid regex pattern for SuspiciousExtensions: %s", pattern.c_str());
                    }
                }
            }
            else if (key == "WhitelistedPaths") {
                g_config.whitelistedPaths.clear();
                std::vector<std::string> patterns = SplitString(value, ',');
                for (const auto& pattern : patterns) {
                    try {
                        std::wstring widePattern = UTF8ToWide(pattern);
                        std::wregex regexPattern(widePattern, std::regex::icase);
                        g_config.whitelistedPaths.push_back(regexPattern);
                    }
                    catch (const std::regex_error&) { /* Handle error */ }
                }
            }
        }
        else if (currentSection == "RegistryOperations") {
            if (key == "Monitor") {
                g_config.monitorRegistryOperations = StringToBool(value);
            }
            else if (key == "SuspiciousKeys") {
                // Reset the vector first
                g_config.suspiciousKeys.clear();
                
                // Parse comma-separated regex patterns
                std::vector<std::string> patterns = SplitString(value, ',');
                for (const auto& pattern : patterns) {
                    try {
                        // Convert narrow pattern to wide string before creating wregex
                        std::wstring widePattern = UTF8ToWide(pattern);
                        std::wregex regexPattern(widePattern, std::regex::icase);
                        g_config.suspiciousKeys.push_back(regexPattern);
                    }
                    catch (const std::regex_error&) {
                        HookDebugLog("Invalid regex pattern for SuspiciousKeys: %s", pattern.c_str());
                    }
                }
            }
            else if (key == "WhitelistedKeys") {
                g_config.whitelistedKeys.clear();
                std::vector<std::string> patterns = SplitString(value, ',');
                for (const auto& pattern : patterns) {
                    try {
                        std::wstring widePattern = UTF8ToWide(pattern);
                        std::wregex regexPattern(widePattern, std::regex::icase);
                        g_config.whitelistedKeys.push_back(regexPattern);
                    }
                    catch (const std::regex_error&) { /* Handle error */ }
                }
            }
        }
        else if (currentSection == "ProcessOperations") {
            if (key == "Monitor") {
                g_config.monitorProcessOperations = StringToBool(value);
            }
            else if (key == "SuspiciousProcesses") {
                // Reset the vector first
                g_config.suspiciousProcesses.clear();
                
                // Parse comma-separated process names (will be matched case-insensitively)
                std::vector<std::string> processes = SplitString(value, ',');
                for (auto& process : processes) {
                    g_config.suspiciousProcesses.push_back(Trim(process));
                }
            }
            else if (key == "WhitelistedProcesses") {
                 g_config.whitelistedProcesses.clear();
                g_config.whitelistedProcesses = SplitString(value, ',');
            }
        }
        else if (currentSection == "NetworkOperations") {
            if (key == "Monitor") {
                g_config.monitorNetworkOperations = StringToBool(value);
            }
            else if (key == "SuspiciousAddresses") {
                // Reset the vector first
                g_config.suspiciousAddresses.clear();
                
                // Parse comma-separated regex patterns
                std::vector<std::string> patterns = SplitString(value, ',');
                for (const auto& pattern : patterns) {
                    try {
                        std::regex regexPattern(pattern, std::regex::icase);
                        g_config.suspiciousAddresses.push_back(regexPattern);
                    }
                    catch (const std::regex_error&) {
                        HookDebugLog("Invalid regex pattern: %s", pattern.c_str());
                    }
                }
            }
            else if (key == "SuspiciousPorts") {
                // Reset the vector first
                g_config.suspiciousPorts.clear();
                
                // Parse comma-separated port numbers
                std::vector<std::string> ports = SplitString(value, ',');
                for (const auto& port : ports) {
                    try {
                        int portNum = std::stoi(Trim(port));
                        g_config.suspiciousPorts.push_back(portNum);
                    }
                    catch (const std::exception&) {
                        HookDebugLog("Invalid port number: %s", port.c_str());
                    }
                }
            }
            else if (key == "WhitelistedNetwork") {
                g_config.whitelistedNetwork.clear();
                 std::vector<std::string> patterns = SplitString(value, ',');
                for (const auto& pattern : patterns) {
                    try {
                        std::regex regexPattern(pattern, std::regex::icase);
                        g_config.whitelistedNetwork.push_back(regexPattern);
                    }
                    catch (const std::regex_error&) { /* Handle error */ }
                }
            }
        }
        else if (currentSection == "MemoryOperations") {
            if (key == "Monitor") {
                g_config.monitorMemoryOperations = StringToBool(value);
            }
        }
        else if (currentSection == "DllOperations") {
            if (key == "Monitor") {
                g_config.monitorDllOperations = StringToBool(value);
            }
            else if (key == "SuspiciousDlls") {
                // Reset the vector first
                g_config.suspiciousDlls.clear();
                
                // Parse comma-separated regex patterns
                std::vector<std::string> patterns = SplitString(value, ',');
                for (const auto& pattern : patterns) {
                    try {
                        // Convert narrow pattern to wide string before creating wregex
                        std::wstring widePattern = UTF8ToWide(pattern);
                        std::wregex regexPattern(widePattern, std::regex::icase);
                        g_config.suspiciousDlls.push_back(regexPattern);
                    }
                    catch (const std::regex_error&) {
                        HookDebugLog("Invalid regex pattern for SuspiciousDlls: %s", pattern.c_str());
                    }
                }
            }
            else if (key == "WhitelistedDlls") {
                g_config.whitelistedDlls.clear();
                std::vector<std::string> patterns = SplitString(value, ',');
                for (const auto& pattern : patterns) {
                    try {
                        std::wstring widePattern = UTF8ToWide(pattern);
                        std::wregex regexPattern(widePattern, std::regex::icase);
                        g_config.whitelistedDlls.push_back(regexPattern);
                    }
                    catch (const std::regex_error&) { /* Handle error */ }
                }
            }
        }
        else if (currentSection == "CryptoOperations") {
            if (key == "Monitor") {
                g_config.monitorCryptoOperations = StringToBool(value);
            }
        }
        else if (currentSection == "Alerts") {
            if (key == "ShowAlerts") {
                g_config.showAlerts = StringToBool(value);
            }
            else if (key == "MaxAlertsPerCategory") {
                try {
                    g_config.maxAlertsPerCategory = std::stoi(value);
                }
                catch (const std::exception&) {
                    g_config.maxAlertsPerCategory = 10; // Default if parsing fails
                }
            }
            else if (key == "AlertLogLevel") {
                try {
                    int level = std::stoi(value);
                    g_config.alertLogLevel = static_cast<AlertLevel>(level);
                }
                catch (const std::exception&) {
                    g_config.alertLogLevel = ALERT_LOG_AND_MESSAGEBOX; // Default if parsing fails
                }
            }
        }
        else if (currentSection == "AnalysisOptions") {
             if (key == "AnalyzePEHeaders") {
                g_config.analyzePEHeaders = StringToBool(value);
            }
            else if (key == "HashWrittenFiles") {
                g_config.hashWrittenFiles = StringToBool(value);
            }
        }
        else if (currentSection == "Action") { // New section
             if (key == "OnSuspicious") {
                 try {
                    int actionVal = std::stoi(Trim(value));
                    if (actionVal >= ACTION_LOG_ONLY && actionVal <= ACTION_TERMINATE_PROCESS) {
                        g_config.actionOnSuspicious = static_cast<SuspiciousAction>(actionVal);
                    }
                 } catch (const std::exception&) { /* Keep default */ }
             }
        }
        else if (currentSection == "Debug") {
            if (key == "EnableDebugLogToFile") {
                g_config.enableDebugLog = StringToBool(value);
            }
        }
    }

    configFile.close();
    HookDebugLog("Configuration loaded successfully");
    return true;
}

// Set default configuration values
void SetDefaultSuspiciousPatterns() {
    // Clear existing vectors
    g_config.whitelistedPaths.clear();
    g_config.whitelistedKeys.clear();
    g_config.whitelistedProcesses.clear();
    g_config.whitelistedNetwork.clear();
    g_config.whitelistedDlls.clear();

    // Add some basic whitelists (e.g., allowlist common system processes or paths if needed)
    // Example: g_config.whitelistedProcesses.push_back("explorer.exe");
    // Example: g_config.whitelistedPaths.push_back(std::wregex(L"C:\\Windows\\System32\\.*", std::regex::icase));

    // Analysis Options
    g_config.analyzePEHeaders = true;
    g_config.hashWrittenFiles = true;

    // Action
    g_config.actionOnSuspicious = ACTION_LOG_ONLY; // Default to logging only

    // Default configuration for all categories
    
    // File Operations
    g_config.monitorFileOperations = true;
    g_config.suspiciousPaths.clear();
    g_config.suspiciousPaths.push_back(std::wregex(L".*\\\\system32\\\\.*", std::regex::icase));
    g_config.suspiciousPaths.push_back(std::wregex(L".*\\\\syswow64\\\\.*", std::regex::icase));
    
    g_config.suspiciousExtensions.clear();
    g_config.suspiciousExtensions.push_back(std::wregex(L".*\\.exe$", std::regex::icase));
    g_config.suspiciousExtensions.push_back(std::wregex(L".*\\.dll$", std::regex::icase));
    g_config.suspiciousExtensions.push_back(std::wregex(L".*\\.ps1$", std::regex::icase));
    g_config.suspiciousExtensions.push_back(std::wregex(L".*\\.bat$", std::regex::icase));
    g_config.suspiciousExtensions.push_back(std::wregex(L".*\\.cmd$", std::regex::icase));
    g_config.suspiciousExtensions.push_back(std::wregex(L".*\\.vbs$", std::regex::icase));
    g_config.suspiciousExtensions.push_back(std::wregex(L".*\\.js$", std::regex::icase));
    g_config.suspiciousExtensions.push_back(std::wregex(L".*\\.hta$", std::regex::icase));
    
    // Registry Operations
    g_config.monitorRegistryOperations = true;
    g_config.suspiciousKeys.clear();
    g_config.suspiciousKeys.push_back(std::wregex(L".*\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run.*", std::regex::icase));
    g_config.suspiciousKeys.push_back(std::wregex(L".*\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\RunOnce.*", std::regex::icase));
    g_config.suspiciousKeys.push_back(std::wregex(L".*\\\\SOFTWARE\\\\Microsoft\\\\Windows NT\\\\CurrentVersion\\\\Winlogon\\\\Userinit.*", std::regex::icase));
    g_config.suspiciousKeys.push_back(std::wregex(L".*\\\\SOFTWARE\\\\Microsoft\\\\Windows NT\\\\CurrentVersion\\\\Winlogon\\\\Shell.*", std::regex::icase));
    g_config.suspiciousKeys.push_back(std::wregex(L".*\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Explorer\\\\User Shell Folders.*", std::regex::icase));
    g_config.suspiciousKeys.push_back(std::wregex(L".*\\\\SYSTEM\\\\CurrentControlSet\\\\Services\\\\.*", std::regex::icase));
    
    // Process Operations
    g_config.monitorProcessOperations = true;
    g_config.suspiciousProcesses.clear();
    g_config.suspiciousProcesses.push_back("cmd.exe");
    g_config.suspiciousProcesses.push_back("powershell.exe");
    g_config.suspiciousProcesses.push_back("wscript.exe");
    g_config.suspiciousProcesses.push_back("cscript.exe");
    g_config.suspiciousProcesses.push_back("regsvr32.exe");
    g_config.suspiciousProcesses.push_back("mshta.exe");
    g_config.suspiciousProcesses.push_back("rundll32.exe");
    g_config.suspiciousProcesses.push_back("regedit.exe");
    g_config.suspiciousProcesses.push_back("certutil.exe");
    g_config.suspiciousProcesses.push_back("msiexec.exe");
    
    // Network Operations
    g_config.monitorNetworkOperations = true;
    g_config.suspiciousAddresses.clear(); // Default is empty
    g_config.suspiciousPorts.clear();
    g_config.suspiciousPorts.push_back(4444);  // Common Metasploit port
    g_config.suspiciousPorts.push_back(1337);  // Common "leet" port
    g_config.suspiciousPorts.push_back(31337); // Also common "leet" port
    g_config.suspiciousPorts.push_back(8080);  // Common alternative HTTP port
    
    // Memory Operations
    g_config.monitorMemoryOperations = true;
    
    // DLL Operations
    g_config.monitorDllOperations = true;
    g_config.suspiciousDlls.clear();
    g_config.suspiciousDlls.push_back(std::wregex(L".*inject.*\\.dll$", std::regex::icase));
    g_config.suspiciousDlls.push_back(std::wregex(L".*hook.*\\.dll$", std::regex::icase));
    
    // Crypto Operations
    g_config.monitorCryptoOperations = true;
    
    // Alerts
    g_config.showAlerts = true;
    g_config.maxAlertsPerCategory = 10;
    g_config.alertLogLevel = ALERT_LOG_AND_MESSAGEBOX;
    
    // Debug
    g_config.enableDebugLog = false;
} 