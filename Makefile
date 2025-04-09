# Makefile for OfficeApiHook using nmake

# Compiler and linker options
CC = cl
LINK = link
# Re-add explicit SDK paths with potentially better quoting for nmake
WINDOWS_KIT_INCLUDE_DIR = C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0
WINDOWS_KIT_LIB_DIR = C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\um\x64
CFLAGS = /nologo /W3 /O2 /D "UNICODE" /D "_UNICODE" /I"include" "/I$(WINDOWS_KIT_INCLUDE_DIR)\um" "/I$(WINDOWS_KIT_INCLUDE_DIR)\shared" /EHsc /c
LDFLAGS = /NOLOGO /DLL /SUBSYSTEM:WINDOWS /OUT:Dll1.dll /MACHINE:X64 "/LIBPATH:$(WINDOWS_KIT_LIB_DIR)" # Quote LIBPATH too

# Source files
SOURCES = src\dllmain.cpp \
          src\config.cpp \
          src\logging.cpp \
          src\utils.cpp \
          src\detection.cpp \
          src\injection.cpp \
          src\hooks_file.cpp \
          src\hooks_process.cpp \
          src\hooks_registry.cpp \
          src\hooks_network.cpp \
          src\hooks_dll.cpp \
          src\hooks_memory.cpp

# Object files
OBJECTS = $(SOURCES:.cpp=.obj)

# Corrected object list for linker (remove src\ prefix)
LINK_OBJECTS = dllmain.obj \
               config.obj \
               logging.obj \
               utils.obj \
               detection.obj \
               injection.obj \
               hooks_file.obj \
               hooks_process.obj \
               hooks_registry.obj \
               hooks_network.obj \
               hooks_dll.obj \
               hooks_memory.obj

# Libraries - Keep specific libs, SDK libs found via environment or explicit LIBPATH
LIBS = include\detours.lib ws2_32.lib wininet.lib psapi.lib shlwapi.lib Advapi32.lib User32.lib crypt32.lib

all: Dll1.dll

Dll1.dll: $(OBJECTS)
	$(LINK) $(LDFLAGS) $(LINK_OBJECTS) $(LIBS)

.cpp.obj:
	$(CC) $(CFLAGS) $<

clean:
	del *.obj Dll1.dll Dll1.lib Dll1.exp 