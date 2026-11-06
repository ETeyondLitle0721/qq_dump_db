cmake_minimum_required(VERSION 3.16)
project(qq_dump_db VERSION 2.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT WIN32)
    message(FATAL_ERROR "qq_dump_db C++ implementation requires Windows APIs.")
endif()

# The delivery archive omits third_party/. Install SQLite through vcpkg or
# provide a system SQLite development package before configuring this project.
find_package(SQLite3 REQUIRED)

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
target_link_libraries(qq_dump_db PRIVATE SQLite::SQLite3 bcrypt shell32)
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
