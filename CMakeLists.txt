cmake_minimum_required(VERSION 3.14)
project(qq_dump_db VERSION 0.1.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ── SQLite3 ──────────────────────────────────────────────────────────────────
# Option 1: system / vcpkg install  (vcpkg install sqlite3:x64-windows)
# Option 2: amalgamation in third_party/sqlite3/
find_package(SQLite3 QUIET)

if(SQLite3_FOUND)
    set(SQLITE3_TARGET SQLite::SQLite3)
    message(STATUS "Using system SQLite3: ${SQLite3_VERSION}")
elseif(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/third_party/sqlite3/sqlite3.c")
    add_library(sqlite3_lib STATIC third_party/sqlite3/sqlite3.c)
    target_include_directories(sqlite3_lib PUBLIC third_party/sqlite3)
    set(SQLITE3_TARGET sqlite3_lib)
    message(STATUS "Using bundled SQLite3 amalgamation")
else()
    message(FATAL_ERROR
        "SQLite3 not found. Either:\n"
        "  1) vcpkg install sqlite3:x64-windows\n"
        "  2) Download https://www.sqlite.org/download.html amalgamation,\n"
        "     place sqlite3.c + sqlite3.h in third_party/sqlite3/")
endif()

# ── Main target ──────────────────────────────────────────────────────────────
add_executable(qq_dump_db main.cpp)
target_link_libraries(qq_dump_db PRIVATE ${SQLITE3_TARGET} bcrypt)

if(MSVC)
    target_compile_options(qq_dump_db PRIVATE /utf-8)
endif()

