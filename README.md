# MalDocShield

Windows API hooking library that protects against malicious Office documents and PDFs by monitoring suspicious activities. Intercepts critical system calls to detect and block malicious behaviors like file operations, process creation, registry changes, and network connections from document viewers.

## Features

- **API Hooking**: Intercepts critical Windows API calls to monitor for malicious activity
- **Configurable Detection Rules**: Customizable patterns to identify suspicious behavior
- **Alert System**: Visual and logging alerts for detected threats
- **Auto-Injection**: Automatically injects into target processes
- **Minimal Performance Impact**: Optimized for low overhead on monitored applications
- **Detailed Logging**: Comprehensive logging of all monitored activities

## Requirements

- Windows 10/11
- Microsoft Visual C++ Redistributable
- [Microsoft Detours](https://github.com/microsoft/Detours) library

## Installation

1. Download the latest release from the Releases page
2. Extract the files to a directory of your choice
3. Customize `config.ini` as needed for your environment
4. Use one of the following methods to load the DLL:
   - Run `python injector.py <DOCX, PDF, XLSX, PPTX> <DLL> ` to inject into a running process
   - Configure your system to auto-load the DLL with Office applications
   - Use a third-party DLL injection tool

## Usage

MalDocShield works by hooking into Office applications (Word, Excel, PowerPoint) and PDF readers to monitor their API calls. When suspicious activity is detected, it can:

1. Log the activity to a file
2. Display an alert dialog
3. Block the operation (if configured to do so)

## Building from Source

### Prerequisites

- Visual Studio 2019 or newer
- CMake 3.12 or newer
- Microsoft Detours library

### Build Steps

1. Clone this repository
2. Update the `DETOURS_DIR` path in `CMakeLists.txt` to point to your Detours installation
3. Build using CMake:
   ```
   mkdir build
   cd build
   cmake ..
   cmake --build . --config Release
   ```
   
Or using Visual Studio Developer Command Prompt (x64):
   ```
   nmake
   ```

## Configuration

MalDocShield is highly configurable through the `config.ini` file. Below is a detailed explanation of all configuration options:

### General Settings

```ini
[General]
# Enable or disable the entire hook functionality
Enabled=true
# Log file path (relative or absolute)
LogFilePath=maldocshield.log
# Log level: 0=None, 1=Error, 2=Warning, 3=Info, 4=Debug
LogLevel=3
```

### File Operations

```ini
[FileOperations]
# Enable monitoring of file operations
Monitor=true
# File paths matching these regex patterns will trigger alerts
SuspiciousPaths=.*\\Temp\\.*,.*\\AppData\\Local\\Temp\\.*,.*\\Downloads\\.*
# File extensions that are considered suspicious
SuspiciousExtensions=.*\.exe$,.*\.dll$,.*\.bat$,.*\.ps1$,.*\.vbs$,.*\.js$,.*\.hta$
# Files containing these strings (case-insensitive) will be flagged
SuspiciousKeywords=powershell,cmd.exe,wscript,cscript,rundll32,regsvr32
# Paths that should be excluded from monitoring (whitelist)
WhitelistedPaths=C:\\Windows\\System32\\.*,C:\\Program Files\\.*
# Maximum entropy threshold for file contents (0.0-8.0, higher values indicate possible encryption/obfuscation)
EntropyThreshold=7.5
```

### Process Operations

```ini
[ProcessOperations]
# Enable monitoring of process creation
Monitor=true
# Process names that are considered suspicious when launched by Office/PDF applications
SuspiciousProcesses=cmd.exe,powershell.exe,wscript.exe,cscript.exe,rundll32.exe,regsvr32.exe
# Command line arguments that are considered suspicious
SuspiciousCommandArgs=.*-enc.*,.*hidden.*,.*bypass.*,.*-w hidden.*
# Processes that should be excluded from monitoring (whitelist)
WhitelistedProcesses=explorer.exe,iexplore.exe,msedge.exe,chrome.exe
```

### Registry Operations

```ini
[RegistryOperations]
# Enable monitoring of registry operations
Monitor=true
# Registry keys that are considered sensitive
SuspiciousKeys=.*\\Software\\Microsoft\\Windows\\CurrentVersion\\Run.*,.*HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services.*
# Registry values that are considered suspicious
SuspiciousValues=.*\.exe,.*\.dll,.*\.bat,.*\.ps1,.*\.vbs,.*\.js,.*\.hta
# Registry operations that should be excluded from monitoring (whitelist)
WhitelistedKeys=.*\\Software\\Microsoft\\Office.*,.*\\Software\\Adobe\\Acrobat Reader.*
```

### Network Operations

```ini
[NetworkOperations]
# Enable monitoring of network operations
Monitor=true
# IP addresses or domains that are considered suspicious
SuspiciousAddresses=192\.168\..*,10\..*,172\.(1[6-9]|2[0-9]|3[0-1])\..*
# Ports that are considered suspicious
SuspiciousPorts=4444,8080,8888,9999
# Network operations to these destinations should be excluded from monitoring (whitelist)
WhitelistedAddresses=.*\.microsoft\.com,.*\.office\.com,.*\.adobe\.com
# Flag connections when data is sent after receiving less than this many bytes (possible C2)
MinBytesReceivedBeforeSend=10
```

### DLL Operations

```ini
[DLLOperations]
# Enable monitoring of DLL loading
Monitor=true
# DLL names that are considered suspicious
SuspiciousDLLs=.*hacker.*\.dll,.*inject.*\.dll,.*hook.*\.dll
# Paths from which loading DLLs is considered suspicious
SuspiciousDLLPaths=.*\\Temp\\.*,.*\\Downloads\\.*
# DLLs that should be excluded from monitoring (whitelist)
WhitelistedDLLs=ntdll\.dll,kernel32\.dll,user32\.dll
```

### Memory Operations

```ini
[MemoryOperations]
# Enable monitoring of memory operations
Monitor=true
# Flag allocations with these protection flags
SuspiciousProtectionFlags=PAGE_EXECUTE_READWRITE
# Minimum allocation size to monitor (bytes)
MinAllocationSize=4096
# Maximum allocation size to monitor (bytes)
MaxAllocationSize=1048576
# Memory regions that should be excluded from monitoring (address ranges in hex)
WhitelistedAddressRanges=0x10000000-0x20000000
```

### Alerts

```ini
[Alerts]
# How alerts should be displayed: 1=Log only, 2=MessageBox only, 3=Both
AlertLogLevel=3
# Allow blocking operations that are flagged as suspicious
BlockSuspiciousOperations=false
# Correlation threshold - number of suspicious operations before raising a high-priority alert
CorrelationThreshold=3
# Timeout in seconds for correlation window
CorrelationTimeoutSeconds=60
```

### Auto-Injection

```ini
[AutoInjection]
# Enable automatic injection into new processes
Enabled=true
# Target processes for auto-injection
TargetProcesses=WINWORD.EXE,EXCEL.EXE,POWERPNT.EXE,OUTLOOK.EXE,AcroRd32.exe
# Injection method: 1=CreateRemoteThread, 2=SetWindowsHookEx
InjectionMethod=1
```

## Troubleshooting

Common issues and their solutions:

1. **False Positives**: If you're seeing too many alerts for legitimate operations:
   - Add specific paths to the appropriate `WhitelistedPaths` sections
   - Adjust the `SuspiciousPaths` and other detection parameters to be more specific
   - Increase the `CorrelationThreshold` to require more suspicious operations before alerting

2. **Performance Issues**: If monitored applications become slow:
   - Disable monitoring of less critical operation types
   - Make whitelist patterns more comprehensive
   - Reduce the `LogLevel` to minimize disk I/O

3. **DLL Not Loading**: If the DLL fails to inject:
   - Ensure you have the correct bitness (32-bit vs 64-bit) for the target application
   - Verify the DLL and all dependencies are accessible to the target process
   - Check if any anti-virus or security software is blocking the injection

## License



## Acknowledgements

- Microsoft Detours library
- Microsoft Win API Library
- https://opendylan.org/library-reference/win32/index.html
