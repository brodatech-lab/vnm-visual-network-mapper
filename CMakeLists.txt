cmake_minimum_required(VERSION 3.20)

project(vnm
    VERSION 0.6.3
    DESCRIPTION "VNM - Visual Network Mapper"
    LANGUAGES C CXX)

# ---------------------------------------------------------------------------
# Global settings
# ---------------------------------------------------------------------------
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

if(WIN32)
    # Keep std::min/std::max (NOMINMAX) and silence MSVC getenv deprecation.
    add_compile_definitions(NOMINMAX _CRT_SECURE_NO_WARNINGS)
endif()

option(VNM_BUILD_CLI    "Build the vnm command line bootstrap" ON)
option(VNM_BUILD_GUI    "Build the native 2D GUI (Dear ImGui)"   OFF)
option(VNM_BUILD_TESTS  "Build unit tests"                        ON)
option(VNM_WERROR       "Treat warnings as errors"                OFF)
option(VNM_ENABLE_PCAP  "Enable passive discovery (libpcap/Npcap)" ON)
set(VNM_NPCAP_SDK_DIR "" CACHE PATH "Path to the Npcap SDK (Windows)")

# ---------------------------------------------------------------------------
# vnm_core: GUI-independent engine (model, net, scan, parse, layout, storage)
# ---------------------------------------------------------------------------
add_library(vnm_core STATIC
    src/core/model.cpp
    src/core/net.cpp
    src/core/scan.cpp
    src/core/parse.cpp
    src/core/layout.cpp
    src/core/diff.cpp
    src/core/storage.cpp
    src/core/platform.cpp
    src/core/passive.cpp
    src/core/export.cpp
    src/core/json.cpp
    src/core/links.cpp
    src/core/live.cpp
    src/core/stb_impl.cpp)

target_include_directories(vnm_core PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party/stb)

# Third-party stb headers are not warning-clean; silence them for that TU only.
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    set_source_files_properties(src/core/stb_impl.cpp PROPERTIES COMPILE_OPTIONS "-w")
elseif(MSVC)
    set_source_files_properties(src/core/stb_impl.cpp PROPERTIES COMPILE_OPTIONS "/w")
endif()

target_include_directories(vnm_core
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>)

target_compile_features(vnm_core PUBLIC cxx_std_20)

if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(vnm_core PRIVATE -Wall -Wextra -Wpedantic)
    if(VNM_WERROR)
        target_compile_options(vnm_core PRIVATE -Werror)
    endif()
elseif(MSVC)
    target_compile_options(vnm_core PRIVATE /W4 /utf-8)
    if(VNM_WERROR)
        target_compile_options(vnm_core PRIVATE /WX)
    endif()
endif()

find_package(Threads REQUIRED)
target_link_libraries(vnm_core PUBLIC Threads::Threads)

if(WIN32)
    target_link_libraries(vnm_core PUBLIC ws2_32 iphlpapi)
endif()

# SQLite: prefer the system package (Linux) and fall back to the amalgamation.
find_package(SQLite3 QUIET)
if(NOT SQLite3_FOUND)
    include(FetchContent)
    message(STATUS "VNM: system SQLite3 not found, fetching the amalgamation...")
    FetchContent_Declare(sqlite3
        URL https://www.sqlite.org/2024/sqlite-amalgamation-3450100.zip
        DOWNLOAD_EXTRACT_TIMESTAMP TRUE)
    FetchContent_MakeAvailable(sqlite3)
    add_library(vnm_sqlite3 STATIC ${sqlite3_SOURCE_DIR}/sqlite3.c)
    target_include_directories(vnm_sqlite3 PUBLIC ${sqlite3_SOURCE_DIR})
    if(WIN32)
        target_link_libraries(vnm_sqlite3 PUBLIC ws2_32)
    endif()
    add_library(SQLite::SQLite3 ALIAS vnm_sqlite3)
endif()

target_link_libraries(vnm_core PUBLIC SQLite::SQLite3)

# ---------------------------------------------------------------------------
# Optional passive discovery (libpcap on Linux, Npcap SDK on Windows)
# ---------------------------------------------------------------------------
if(VNM_ENABLE_PCAP)
    if(CMAKE_CROSSCOMPILING)
        message(STATUS "VNM: cross-compiling - passive discovery disabled "
                       "(set VNM_ENABLE_PCAP=OFF to silence)")
    elseif(WIN32)
        set(VNM_PCAP_INCLUDE_DIR "")
        set(VNM_PCAP_LIBS "")

        if(VNM_NPCAP_SDK_DIR)
            set(VNM_PCAP_INCLUDE_DIR "${VNM_NPCAP_SDK_DIR}/Include")
            find_library(_npcap_wpcap NAMES wpcap
                PATHS "${VNM_NPCAP_SDK_DIR}/Lib/x64" NO_DEFAULT_PATH)
            find_library(_npcap_packet NAMES Packet
                PATHS "${VNM_NPCAP_SDK_DIR}/Lib/x64" NO_DEFAULT_PATH)
            set(VNM_PCAP_LIBS ${_npcap_wpcap} ${_npcap_packet})
        else()
            find_path(VNM_PCAP_INCLUDE_DIR pcap.h)
            find_library(_npcap_wpcap NAMES wpcap)
            find_library(_npcap_packet NAMES Packet)
            set(VNM_PCAP_LIBS ${_npcap_wpcap} ${_npcap_packet})
        endif()

        if(NOT VNM_PCAP_INCLUDE_DIR OR NOT VNM_PCAP_LIBS)
            message(STATUS "VNM: Npcap SDK not found, fetching it (build-time only)...")
            include(FetchContent)
            FetchContent_Declare(npcap_sdk
                URL https://npcap.com/dist/npcap-sdk-1.16.zip
                DOWNLOAD_EXTRACT_TIMESTAMP TRUE)
            FetchContent_MakeAvailable(npcap_sdk)
            set(VNM_PCAP_INCLUDE_DIR "${npcap_sdk_SOURCE_DIR}/Include")
            find_library(_npcap_wpcap NAMES wpcap
                PATHS "${npcap_sdk_SOURCE_DIR}/Lib/x64" NO_DEFAULT_PATH)
            find_library(_npcap_packet NAMES Packet
                PATHS "${npcap_sdk_SOURCE_DIR}/Lib/x64" NO_DEFAULT_PATH)
            set(VNM_PCAP_LIBS ${_npcap_wpcap} ${_npcap_packet})
        endif()

        if(VNM_PCAP_INCLUDE_DIR AND VNM_PCAP_LIBS)
            message(STATUS "VNM: Npcap SDK found - passive discovery enabled")
            target_compile_definitions(vnm_core PUBLIC VNM_HAVE_PCAP WPCAP)
            target_include_directories(vnm_core PRIVATE ${VNM_PCAP_INCLUDE_DIR})
            target_link_libraries(vnm_core PRIVATE ${VNM_PCAP_LIBS})
        else()
            message(STATUS "VNM: Npcap SDK not available - passive discovery disabled")
        endif()
    else()
        find_package(PkgConfig QUIET)
        if(PkgConfig_FOUND)
            pkg_check_modules(PCAP QUIET libpcap)
        endif()

        if(PCAP_FOUND)
            message(STATUS "VNM: libpcap ${PCAP_VERSION} found - passive discovery enabled")
            target_compile_definitions(vnm_core PUBLIC VNM_HAVE_PCAP)
            target_include_directories(vnm_core PRIVATE ${PCAP_INCLUDE_DIRS})
            target_link_directories(vnm_core PRIVATE ${PCAP_LIBRARY_DIRS})
            target_link_libraries(vnm_core PRIVATE ${PCAP_LIBRARIES})
        else()
            find_path(PCAP_INCLUDE_DIR pcap.h)
            find_library(PCAP_LIBRARY NAMES pcap wpcap)
            if(PCAP_INCLUDE_DIR AND PCAP_LIBRARY)
                message(STATUS "VNM: libpcap found - passive discovery enabled")
                target_compile_definitions(vnm_core PUBLIC VNM_HAVE_PCAP)
                target_include_directories(vnm_core PRIVATE ${PCAP_INCLUDE_DIR})
                target_link_libraries(vnm_core PRIVATE ${PCAP_LIBRARY})
            else()
                message(STATUS "VNM: libpcap not found - passive discovery disabled")
            endif()
        endif()
    endif()
endif()

# ---------------------------------------------------------------------------
# vnm: command line bootstrap
# ---------------------------------------------------------------------------
if(VNM_BUILD_CLI)
    add_executable(vnm src/cli/main.cpp)
    target_link_libraries(vnm PRIVATE vnm_core)
    if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
        target_compile_options(vnm PRIVATE -Wall -Wextra -Wpedantic)
    endif()
endif()

# ---------------------------------------------------------------------------
# Optional native GUI
# ---------------------------------------------------------------------------
if(VNM_BUILD_GUI)
    add_subdirectory(src/ui)
endif()

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------
if(VNM_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()
