cmake_minimum_required(VERSION 3.16)

# Keep the application CRT consistent with the x64-windows-static vcpkg
# triplet. This makes the release executable independent of the MSVC
# redistributable DLLs as well as sqlite3.dll.
if(POLICY CMP0091)
    cmake_policy(SET CMP0091 NEW)
endif()
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

project(qq_dump_db VERSION 2.0.1 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT WIN32)
    message(FATAL_ERROR "qq_dump_db C++ implementation requires Windows APIs.")
endif()

if(NOT DEFINED VCPKG_TARGET_TRIPLET OR
   NOT "${VCPKG_TARGET_TRIPLET}" STREQUAL "x64-windows-static")
    message(FATAL_ERROR
        "Configure with vcpkg triplet x64-windows-static to avoid a runtime sqlite3.dll dependency. "
        "Pass -DVCPKG_TARGET_TRIPLET=x64-windows-static.")
endif()

# SQLite is linked statically for the standalone Windows release. The
# delivery archive omits third_party/; install the vcpkg static triplet first:
#   vcpkg install sqlite3:x64-windows-static
find_package(unofficial-sqlite3 CONFIG REQUIRED)

add_executable(qq_dump_db
    main.cpp
    cpp/src/cli.cpp
    cpp/src/i18n/catalog.cpp
    cpp/src/utils/hex.cpp
    cpp/src/crypto/sqlcipher.cpp
    cpp/src/platform/win32/processes.cpp
    cpp/src/platform/win32/handles.cpp
    cpp/src/platform/win32/memory.cpp
    cpp/src/discovery/qq_instances.cpp
    cpp/src/discovery/databases.cpp
    cpp/src/services/keymap_writer.cpp
    cpp/src/services/waiter.cpp
    cpp/src/services/decryptor.cpp
    cpp/src/services/workflow.cpp
)

target_include_directories(qq_dump_db PRIVATE cpp/include)
target_link_libraries(qq_dump_db PRIVATE unofficial::sqlite3::sqlite3 bcrypt shell32)
target_compile_definitions(qq_dump_db PRIVATE UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX)

if(MSVC)
    target_compile_options(qq_dump_db PRIVATE /utf-8 /W4 /permissive-)
else()
    target_compile_options(qq_dump_db PRIVATE -Wall -Wextra -Wpedantic)
endif()

install(TARGETS qq_dump_db RUNTIME DESTINATION bin)


include(CTest)
if(BUILD_TESTING)
    add_executable(qq_dump_db_cli_tests
        tests/cpp/test_cli.cpp
        cpp/src/cli.cpp
        cpp/src/i18n/catalog.cpp
        cpp/src/utils/hex.cpp
    )
    target_include_directories(qq_dump_db_cli_tests PRIVATE cpp/include)
    target_compile_definitions(qq_dump_db_cli_tests PRIVATE UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX)
    if(MSVC)
        target_compile_options(qq_dump_db_cli_tests PRIVATE /utf-8 /W4 /permissive-)
    else()
        target_compile_options(qq_dump_db_cli_tests PRIVATE -Wall -Wextra -Wpedantic)
    endif()
    add_test(NAME qq_dump_db_cli_contract COMMAND qq_dump_db_cli_tests)
endif()
