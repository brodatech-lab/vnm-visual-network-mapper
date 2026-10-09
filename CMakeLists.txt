cmake_minimum_required(VERSION 3.20)

project(vnm
    VERSION 0.1.0
    DESCRIPTION "VNM - Visual Network Mapper"
    LANGUAGES CXX)

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

option(VNM_BUILD_CLI    "Build the vnm command line bootstrap" ON)
option(VNM_BUILD_GUI    "Build the native 2D GUI (Dear ImGui)"   OFF)
option(VNM_BUILD_TESTS  "Build unit tests"                        ON)
option(VNM_WERROR       "Treat warnings as errors"                OFF)

# ---------------------------------------------------------------------------
# vnm_core: GUI-independent engine (model, net, scan, parse, layout, storage)
# ---------------------------------------------------------------------------
add_library(vnm_core STATIC
    src/core/model.cpp
    src/core/net.cpp
    src/core/scan.cpp
    src/core/parse.cpp
    src/core/layout.cpp
    src/core/storage.cpp)

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
    target_compile_options(vnm_core PRIVATE /W4)
    if(VNM_WERROR)
        target_compile_options(vnm_core PRIVATE /WX)
    endif()
endif()

find_package(Threads REQUIRED)
target_link_libraries(vnm_core PUBLIC Threads::Threads)

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
