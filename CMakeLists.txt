# ============================================================================
# Jockey's Execution Engine -- Root CMakeLists.txt
# Cross-platform build: Windows (MSVC/MinGW) and Linux (GCC/Clang)
# ============================================================================
cmake_minimum_required(VERSION 3.16)
project(JockeyEngine
    VERSION 1.0.0
    DESCRIPTION "High-performance injection and execution engine"
    LANGUAGES C
)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# ------------------------------------------------------------------
# Compiler flags
# ------------------------------------------------------------------
if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -Wpedantic -Werror -O3")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIC -fno-stack-protector -Wno-unused-parameter")
    set(CMAKE_C_FLAGS_DEBUG "-g -O0 -DDEBUG -DENABLE_LOGGING=1")
    set(CMAKE_C_FLAGS_RELEASE "-O3 -DNDEBUG -DENABLE_LOGGING=1 -s")
elseif(MSVC)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /W4 /WX /O2 /MP")
    set(CMAKE_C_FLAGS_DEBUG "/Zi /Od /DDEBUG /DENABLE_LOGGING=1")
    set(CMAKE_C_FLAGS_RELEASE "/O2 /DNDEBUG /DENABLE_LOGGING=1 /release")
endif()

# ------------------------------------------------------------------
# Include directories
# ------------------------------------------------------------------
include_directories(${CMAKE_SOURCE_DIR}/include)

# ------------------------------------------------------------------
# Source files (common)
# ------------------------------------------------------------------
set(COMMON_SOURCES
    src/api_unhooking.c
    src/byovd_loader.c
    src/inject.c
    src/other_injections.c
    src/process_hollowing.c
    src/reflective_dll.c
)

# ------------------------------------------------------------------
# Platform-specific sources and libs
# ------------------------------------------------------------------
if(WIN32)
    list(APPEND COMMON_SOURCES
        src/pal/pal_win.c
        src/syscalls/syscalls_win.c
    )
    set(PLATFORM_LIBS psapi setupapi advapi32)
    add_definitions(-D_WIN32_WINNT=0x0A00 -DWIN32_LEAN_AND_MEAN)
else()
    list(APPEND COMMON_SOURCES
        src/pal/pal_linux.c
        src/syscalls/syscalls_linux.c
    )
    set(PLATFORM_LIBS dl pthread)
    add_definitions(-D_GNU_SOURCE)
endif()

# ------------------------------------------------------------------
# Static library
# ------------------------------------------------------------------
add_library(jockey STATIC ${COMMON_SOURCES})
target_link_libraries(jockey ${PLATFORM_LIBS})
set_target_properties(jockey PROPERTIES POSITION_INDEPENDENT_CODE ON)

# ------------------------------------------------------------------
# Shared library (optional)
# ------------------------------------------------------------------
add_library(jockey_shared SHARED ${COMMON_SOURCES})
set_target_properties(jockey_shared PROPERTIES OUTPUT_NAME jockey POSITION_INDEPENDENT_CODE ON)
target_link_libraries(jockey_shared ${PLATFORM_LIBS})

# ------------------------------------------------------------------
# Demo executable
# ------------------------------------------------------------------
add_executable(jockey_demo demo/main.c)
target_link_libraries(jockey_demo jockey ${PLATFORM_LIBS})

# ------------------------------------------------------------------
# Tests (optional, if test/ folder exists)
# ------------------------------------------------------------------
if(EXISTS ${CMAKE_SOURCE_DIR}/test)
    enable_testing()
    add_subdirectory(test)
endif()

# ------------------------------------------------------------------
# Install rules
# ------------------------------------------------------------------
install(TARGETS jockey jockey_shared jockey_demo
    ARCHIVE DESTINATION lib
    LIBRARY DESTINATION lib
    RUNTIME DESTINATION bin
)
install(DIRECTORY include/ DESTINATION include)

message(STATUS "Jockey Engine build configured")
message(STATUS "  Platform: ${CMAKE_SYSTEM_NAME}")
message(STATUS "  Compiler: ${CMAKE_C_COMPILER_ID} ${CMAKE_C_COMPILER_VERSION}")
message(STATUS "  Build type: ${CMAKE_BUILD_TYPE}")
