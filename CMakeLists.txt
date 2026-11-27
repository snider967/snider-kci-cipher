# KCI-20 cross-platform build (tested in CI: Linux, macOS, ctest). The Makefile is the main build.
# Copyright 2026 snider967. Licensed under the Apache License, Version 2.0.
cmake_minimum_required(VERSION 3.16)
project(kci VERSION 0.4.0 LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

add_library(kci STATIC
    src/core/kci_round.c
    src/core/kci_deck.c
    src/core/kci_stream.c
    src/core/kci_poly1305.c
    src/core/kci_aead.c
    src/core/kci_sha256.c
    src/simd/kci_avx2.c
    src/util/kci_wipe.c)
target_include_directories(kci PUBLIC include)

if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(kci PRIVATE -Wall -Wextra -Wpedantic -Wconversion -Wshadow)
elseif(MSVC)
    target_compile_options(kci PRIVATE /W4)
endif()

add_executable(kci_cli cli/kci.c cli/platform.c)
set_target_properties(kci_cli PROPERTIES OUTPUT_NAME kci)
target_link_libraries(kci_cli PRIVATE kci)
if(WIN32)
    target_link_libraries(kci_cli PRIVATE bcrypt)
endif()

include(CTest)
if(BUILD_TESTING)
    add_executable(test_kci tests/test_kci.c)
    target_link_libraries(test_kci PRIVATE kci)
    add_test(NAME test_kci COMMAND test_kci)
endif()
