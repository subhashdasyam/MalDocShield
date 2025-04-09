import os
import sys
import time
import subprocess
import argparse
import glob
import ctypes
from ctypes import wintypes
import pythoncom
import win32com.client
from win32com.client import Dispatch
import win32process
import win32con
import win32gui
import win32event
import psutil

# Windows API constants and functions for DLL injection
PROCESS_ALL_ACCESS = 0x1F0FFF
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
PAGE_READWRITE = 0x04

# Required Windows functions
kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
kernel32.OpenProcess.restype = wintypes.HANDLE
kernel32.VirtualAllocEx.argtypes = [wintypes.HANDLE, wintypes.LPVOID, ctypes.c_size_t, wintypes.DWORD, wintypes.DWORD]
kernel32.VirtualAllocEx.restype = wintypes.LPVOID
kernel32.WriteProcessMemory.argtypes = [wintypes.HANDLE, wintypes.LPVOID, wintypes.LPCVOID, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
kernel32.WriteProcessMemory.restype = wintypes.BOOL
kernel32.CreateRemoteThread.argtypes = [wintypes.HANDLE, wintypes.LPVOID, ctypes.c_size_t, wintypes.LPVOID, wintypes.LPVOID, wintypes.DWORD, wintypes.LPDWORD]
kernel32.CreateRemoteThread.restype = wintypes.HANDLE
kernel32.GetModuleHandleW.argtypes = [wintypes.LPCWSTR]
kernel32.GetModuleHandleW.restype = wintypes.HANDLE
kernel32.GetProcAddress.argtypes = [wintypes.HANDLE, wintypes.LPCSTR]
kernel32.GetProcAddress.restype = wintypes.LPVOID
kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
kernel32.CloseHandle.restype = wintypes.BOOL
kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
kernel32.WaitForSingleObject.restype = wintypes.DWORD

def inject_dll(pid, dll_path):
    """Inject a DLL into a running process"""
    print(f"Attempting to inject DLL '{dll_path}' into process ID {pid}...")

    # Ensure DLL path is absolute
    dll_path = os.path.abspath(dll_path)
    if not os.path.exists(dll_path):
        print(f"Error: DLL not found at path: {dll_path}")
        return False

    # Get a handle to the target process
    h_process = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    if not h_process:
        error = ctypes.get_last_error()
        print(f"Error: OpenProcess failed for PID {pid}. Error code: {error}")
        # Consider adding GetLastError interpretation here for better diagnostics
        return False

    # Allocate memory in the target process for the DLL path
    # Use bytes for path length calculation
    dll_path_bytes = dll_path.encode('utf-8') + b'\0'
    path_len = len(dll_path_bytes)
    path_addr = kernel32.VirtualAllocEx(h_process, None, path_len,
                                         MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE)
    if not path_addr:
        error = ctypes.get_last_error()
        print(f"Error: VirtualAllocEx failed. Error code: {error}")
        kernel32.CloseHandle(h_process)
        return False

    # Write the DLL path to the allocated memory
    bytes_written = ctypes.c_size_t(0)
    result = kernel32.WriteProcessMemory(h_process, path_addr, dll_path_bytes,
                                         path_len, ctypes.byref(bytes_written))
    if not result or bytes_written.value != path_len:
        error = ctypes.get_last_error()
        print(f"Error: WriteProcessMemory failed. Bytes written: {bytes_written.value}/{path_len}. Error code: {error}")
        # Consider freeing allocated memory with VirtualFreeEx on failure
        kernel32.CloseHandle(h_process)
        return False

    # Get the address of LoadLibraryA function (ensure correct encoding for function name)
    h_kernel32 = kernel32.GetModuleHandleW("kernel32.dll")
    load_library_addr = kernel32.GetProcAddress(h_kernel32, b"LoadLibraryA") # Use byte string for function name

    if not load_library_addr:
        error = ctypes.get_last_error()
        print(f"Error: GetProcAddress failed for LoadLibraryA. Error code: {error}")
        kernel32.CloseHandle(h_process)
        return False

    # Create a remote thread that calls LoadLibraryA with the DLL path
    thread_id = wintypes.DWORD(0)
    h_thread = kernel32.CreateRemoteThread(h_process, None, 0, load_library_addr,
                                           path_addr, 0, ctypes.byref(thread_id))
    if not h_thread:
        error = ctypes.get_last_error()
        print(f"Error: CreateRemoteThread failed. Error code: {error}")
        # Consider freeing allocated memory with VirtualFreeEx on failure
        kernel32.CloseHandle(h_process)
        return False

    # Wait for the thread to finish (optional, but good practice)
    print(f"Waiting for remote thread (ID: {thread_id.value}) to execute LoadLibraryA...")
    wait_result = kernel32.WaitForSingleObject(h_thread, 5000) # Wait up to 5 seconds

    if wait_result == 0xFFFFFFFF: # WAIT_FAILED
         error = ctypes.get_last_error()
         print(f"Warning: WaitForSingleObject failed. Error code: {error}")
    elif wait_result == 0x00000102: # WAIT_TIMEOUT
        print("Warning: WaitForSingleObject timed out. DLL injection might still be in progress or failed silently.")
    else:
        print("Remote thread finished.")

    # Cleanup (memory leak if not closed)
    kernel32.CloseHandle(h_thread)
    # Memory allocated by VirtualAllocEx should ideally be freed with VirtualFreeEx,
    # but it's tricky as the remote process might still use it briefly.
    # For simplicity here, we skip freeing it, but in robust code, you'd coordinate.
    kernel32.CloseHandle(h_process)

    print(f"DLL injection initiated for PID {pid}.")
    return True

def find_latest_log_file(dll_directory):
    """Find the most recently created log file in the DLL's directory"""
    if not os.path.isdir(dll_directory):
        print(f"Error: DLL directory '{dll_directory}' not found.")
        return None

    log_pattern = os.path.join(dll_directory, "api_trace_*.log")
    log_files = glob.glob(log_pattern)

    if not log_files:
        print(f"No log files found matching pattern: {log_pattern}")
        return None

    try:
        # Sort by creation time, newest first
        return max(log_files, key=os.path.getctime)
    except FileNotFoundError:
        # Handle race condition where a file might be deleted between glob and getctime
        print("Warning: A log file disappeared during search. Retrying...")
        time.sleep(0.5)
        log_files = glob.glob(log_pattern)
        if not log_files: return None
        try:
            return max(log_files, key=os.path.getctime)
        except FileNotFoundError:
            print("Error: Still couldn't find log file after retry.")
            return None

def get_firefox_path():
    """Attempt to find the path to firefox.exe."""
    # Check common paths first using raw strings
    common_paths = [
        r"C:\Program Files\Mozilla Firefox\firefox.exe",
        r"C:\Program Files (x86)\Mozilla Firefox\firefox.exe"
    ]
    for path in common_paths:
        if os.path.exists(path):
            return path

    # Add more sophisticated checks here if needed (e.g., registry)
    print("Warning: Could not automatically find firefox.exe in common locations.")
    print(f"Using default path: {common_paths[0]}")
    return common_paths[0] # Return the default as a fallback

def open_document_and_inject(file_path, dll_path):
    """Open an Office document or HTML file, inject the DLL, and report log file location."""
    if not os.path.exists(file_path):
        print(f"Error: Document file not found: {file_path}")
        return
    if not os.path.exists(dll_path):
        print(f"Error: DLL file not found: {dll_path}")
        return

    file_ext = os.path.splitext(file_path)[1].lower()
    app_name = None
    process_exe_name = None
    is_office = False
    firefox_path = None

    # Determine the target application
    if file_ext == '.docx':
        app_name = "Word.Application"
        process_exe_name = "WINWORD.EXE"
        is_office = True
        print("Preparing to open Word document...")
    elif file_ext == '.xlsx':
        app_name = "Excel.Application"
        process_exe_name = "EXCEL.EXE"
        is_office = True
        print("Preparing to open Excel workbook...")
    elif file_ext == '.pptx':
        app_name = "PowerPoint.Application"
        process_exe_name = "POWERPNT.EXE"
        is_office = True
        print("Preparing to open PowerPoint presentation...")
    elif file_ext in ['.html', '.htm']:
        app_name = "Firefox"
        process_exe_name = "firefox.exe"
        firefox_path = get_firefox_path()
        if not firefox_path:
             print("Error: Could not determine Firefox path.")
             return
        print(f"Preparing to open HTML file with Firefox ({firefox_path})...")
    else:
        print(f"Unsupported file extension: {file_ext}")
        print("Supported extensions: .docx, .xlsx, .pptx, .html, .htm")
        return

    pid = None
    app = None # COM object for Office
    doc = None # COM object for Office document
    process_handle = None # Handle for subprocess (Firefox)

    try:
        # Initialize COM only if needed for Office
        if is_office:
            pythoncom.CoInitialize()

        # Start the application
        if is_office:
            print(f"Starting {app_name} via COM...")
            app = win32com.client.Dispatch(app_name)
            app.Visible = True
        else:
            print(f"Starting {process_exe_name}...")
            abs_file_path = os.path.abspath(file_path)
            # Launch Firefox with the file path
            process_handle = subprocess.Popen([firefox_path, abs_file_path])
            print(f"Firefox process started (handle: {process_handle.pid})") # Note: this is Popen handle PID, not OS PID yet

        # Find the OS process ID
        print(f"Waiting for {process_exe_name} process to appear...")
        time.sleep(3) # Give the process time to start properly
        found_proc = None
        for proc in psutil.process_iter(['pid', 'name']):
            if proc.info['name'] and proc.info['name'].lower() == process_exe_name.lower():
                # If multiple instances exist, we might need more sophisticated logic
                # For now, take the first one found
                pid = proc.info['pid']
                found_proc = proc
                print(f"Found {process_exe_name} process with OS PID: {pid}")
                break
        else:
             print(f"Error: Could not find running process '{process_exe_name}' after starting.")
             if is_office and app:
                 try:
                     app.Quit() # Try to quit Office
                 except Exception:
                     pass # Ignore errors quitting
             elif process_handle: # Try to terminate Firefox
                 try:
                     process_handle.terminate()
                 except Exception:
                     pass # Ignore errors terminating
             return # Cannot proceed without PID

        # Inject our DLL into the target process
        if not inject_dll(pid, dll_path):
            print("Error: DLL injection failed.")
            if is_office and app:
                try:
                    app.Quit()
                except Exception:
                    pass
            elif process_handle:
                try:
                    process_handle.terminate()
                except Exception:
                    pass
            return

        # Give the DLL time to initialize
        print("Waiting a few seconds for DLL to initialize...")
        time.sleep(3)

        # Find the log file created by our DLL
        dll_directory = os.path.dirname(os.path.abspath(dll_path))
        log_file = find_latest_log_file(dll_directory)

        if log_file:
            print(f"Monitoring DLL active. Log file should be: {log_file}")
            print("NOTE: Alerts (if any) will appear as message boxes from the target process.")
        else:
            print("Warning: Could not locate the DLL's log file yet. It might be created later.")
            print(f"Look for 'api_trace_*.log' files in: {dll_directory}")

        # Open the document (only needed for Office via COM)
        if is_office:
            print(f"Opening document in Office: {file_path}")
            abs_file_path = os.path.abspath(file_path)
            try:
                if file_ext == '.docx':
                    doc = app.Documents.Open(abs_file_path)
                elif file_ext == '.xlsx':
                    doc = app.Workbooks.Open(abs_file_path)
                elif file_ext == '.pptx':
                    doc = app.Presentations.Open(abs_file_path)
                print("Document opened successfully via COM.")
            except Exception as open_error:
                 print(f"Error opening document '{file_path}' via COM: {open_error}")
                 print("Continuing to keep the application open...")
                 # Don't quit here
        else:
            # For Firefox, the document was already opened via command line
            print(f"HTML document ({file_path}) should be open in Firefox.")

        # Keep the application running
        print("\n--------------------------------------------------")
        print(f"The document '{os.path.basename(file_path)}' is open in {app_name} (PID: {pid}).")
        print("The monitoring DLL is injected.")
        print("Check the target application for any security alert message boxes.")
        if log_file:
            print(f"Detailed API logs are being written to: {log_file}")
        else:
             # Log file wasn't found initially, tell user to check DLL directory
             dll_directory = os.path.dirname(os.path.abspath(dll_path)) # Re-calculate for message
             print(f"Look for detailed API logs ('api_trace_*.log' and 'debug_trace_*.log') in: {dll_directory}")
        print("--------------------------------------------------")
        input("Press Enter here to attempt closing the application (Office only) or exit script...")

    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        import traceback
        traceback.print_exc()

    finally:
        # Attempt to close Office application gracefully
        if is_office:
            print("Attempting to close Office application...")
            try:
                if doc:
                    doc.Close(SaveChanges=win32con.wdDoNotSaveChanges) # Or appropriate constant for Excel/PPT
                    print("Office document closed.")
            except Exception as doc_close_err:
                 print(f"Warning: Error closing Office document: {doc_close_err}")
            try:
                if app:
                    app.Quit()
                    print("Office application quit command sent.")
            except Exception as app_quit_err:
                print(f"Warning: Error quitting Office application: {app_quit_err}")
            pythoncom.CoUninitialize()
        else:
            print("Exiting script. Firefox may still be running.")
            # We don't forcefully terminate Firefox by default
            # if process_handle: try: process_handle.terminate(); except Exception: pass

        print("Script finished.")

def main():
    parser = argparse.ArgumentParser(description="Injects a monitoring DLL into an Office application or Firefox. Logs are created in the DLL's directory.")
    parser.add_argument("document", help="Path to the Office document (.docx, .xlsx, .pptx) or HTML file (.html, .htm)")
    parser.add_argument("dll", help="Path to the monitoring DLL file (e.g., Dll1.dll)")

    args = parser.parse_args()

    # Ensure paths are provided
    if not args.document or not args.dll:
        parser.print_help()
        sys.exit(1)

    # Check if files exist before starting
    if not os.path.exists(args.document):
         print(f"Error: Document file not found: {args.document}")
         sys.exit(1)
    if not os.path.exists(args.dll):
         print(f"Error: DLL file not found: {args.dll}")
         sys.exit(1)

    open_document_and_inject(args.document, args.dll)

if __name__ == "__main__":
    main()