# ---------------------------------------------------------------------------
# Native 2D GUI (Dear ImGui docking) - milestone v0.3.0
#
# Dear ImGui is vendored via FetchContent from the docking branch because
# distro packages do not ship docking support.
# ---------------------------------------------------------------------------
include(FetchContent)

FetchContent_Declare(imgui
    GIT_REPOSITORY https://github.com/ocornut/imgui.git
    GIT_TAG        v1.92.9b-docking
    GIT_SHALLOW    TRUE)

message(STATUS "VNM: fetching Dear ImGui (docking)...")
FetchContent_MakeAvailable(imgui)

# GLFW: system package on Linux, FetchContent on Windows.
if(WIN32)
    message(STATUS "VNM: fetching GLFW (Windows)...")
    set(GLFW_BUILD_DOCS OFF CACHE BOOL "" FORCE)
    set(GLFW_BUILD_TESTS OFF CACHE BOOL "" FORCE)
    set(GLFW_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
    FetchContent_Declare(glfw
        GIT_REPOSITORY https://github.com/glfw/glfw.git
        GIT_TAG        3.4
        GIT_SHALLOW    TRUE)
    FetchContent_MakeAvailable(glfw)
    set(VNM_GLFW glfw)
else()
    find_package(glfw3 REQUIRED)
    set(VNM_GLFW glfw)
endif()

find_package(OpenGL REQUIRED)

add_library(vnm_imgui STATIC
    ${imgui_SOURCE_DIR}/imgui.cpp
    ${imgui_SOURCE_DIR}/imgui_draw.cpp
    ${imgui_SOURCE_DIR}/imgui_tables.cpp
    ${imgui_SOURCE_DIR}/imgui_widgets.cpp
    ${imgui_SOURCE_DIR}/backends/imgui_impl_glfw.cpp
    ${imgui_SOURCE_DIR}/backends/imgui_impl_opengl3.cpp)

target_include_directories(vnm_imgui PUBLIC
    ${imgui_SOURCE_DIR}
    ${imgui_SOURCE_DIR}/backends)
target_link_libraries(vnm_imgui PUBLIC ${VNM_GLFW} OpenGL::GL)

add_executable(vnm_gui
    main.cpp
    topology_view.cpp)

target_link_libraries(vnm_gui PRIVATE vnm_core vnm_imgui ${VNM_GLFW} OpenGL::GL)
target_include_directories(vnm_gui PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(vnm_gui PRIVATE -Wall -Wextra -Wpedantic)
elseif(MSVC)
    target_compile_options(vnm_gui PRIVATE /W4 /utf-8)
endif()
