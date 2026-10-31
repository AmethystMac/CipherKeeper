cmake_minimum_required(VERSION 3.25)

project(CipherKeeper VERSION 0.1.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

option(CK_BUILD_TESTS "Build the test suite (needs the vcpkg 'tests' feature)" ON)
option(CK_BUILD_GUI "Build the Qt 6 desktop app (needs the vcpkg 'gui' feature)" OFF)
option(CK_SANITIZE "Build with AddressSanitizer (+ UBSan on GCC/Clang)" OFF)
option(CK_CLANG_TIDY "Run clang-tidy on every translation unit" OFF)

if(CK_CLANG_TIDY)
    find_program(CK_CLANG_TIDY_EXE NAMES clang-tidy REQUIRED)
    set(CMAKE_CXX_CLANG_TIDY "${CK_CLANG_TIDY_EXE}")
endif()

# Warnings and sanitizer flags shared by every CipherKeeper target (never applied to vcpkg dependencies).
add_library(ck_options INTERFACE)
if(MSVC)
    target_compile_options(ck_options INTERFACE /W4 /WX /permissive- /utf-8)
else()
    target_compile_options(ck_options INTERFACE -Wall -Wextra -Wpedantic -Wconversion -Wsign-conversion -Wshadow -Werror)
endif()

if(CK_SANITIZE)
    if(MSVC)
        # MSVC has no UBSan. The annotation defines stop LNK2038 mismatches against vcpkg libraries built without ASan.
        target_compile_options(ck_options INTERFACE /fsanitize=address)
        target_compile_definitions(ck_options INTERFACE _DISABLE_VECTOR_ANNOTATION _DISABLE_STRING_ANNOTATION)
    else()
        target_compile_options(ck_options INTERFACE -fsanitize=address,undefined -fno-omit-frame-pointer -fno-sanitize-recover=all)
        target_link_options(ck_options INTERFACE -fsanitize=address,undefined)
    endif()
endif()

add_subdirectory(core)
add_subdirectory(cli)

if(CK_BUILD_GUI)
    add_subdirectory(gui)
endif()

if(CK_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()
