cmake_minimum_required(VERSION 3.10)
project(OfficeApiHook)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Enable Unicode for Windows API
add_definitions(-DUNICODE -D_UNICODE)

# Add include directories
include_directories(${CMAKE_SOURCE_DIR}/include)

# Source files
set(SOURCES
    src/dllmain.cpp
    src/config.cpp
    src/logging.cpp
    src/utils.cpp
    src/detection.cpp
    src/injection.cpp
    src/hooks_file.cpp
    src/hooks_process.cpp
    src/hooks_registry.cpp
    src/hooks_network.cpp
    src/hooks_dll.cpp
    src/hooks_memory.cpp
)

# DLL target
add_library(Dll1 SHARED ${SOURCES})

# Set the DLL output name
set_target_properties(Dll1 PROPERTIES
    OUTPUT_NAME "Dll1"
    PREFIX ""
)

# Find detours.lib in the include folder
set(DETOURS_LIB_PATH "${CMAKE_SOURCE_DIR}/include/detours.lib")

# Link against required libraries
target_link_libraries(Dll1
    ${DETOURS_LIB_PATH}
    ws2_32
    wininet
    psapi
    shlwapi
)

# Copy config.ini to build directory
configure_file(${CMAKE_SOURCE_DIR}/config.ini ${CMAKE_BINARY_DIR}/config.ini COPYONLY)

# Install target
install(TARGETS Dll1 DESTINATION bin)
install(FILES ${CMAKE_SOURCE_DIR}/config.ini DESTINATION bin) 