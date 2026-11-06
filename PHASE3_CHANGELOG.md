# Phase 3 change log — C++ modularization

## Scope

- Replaced the 56 KB single-file `main.cpp` implementation with a small Windows CLI entry point.
- Split the C++ implementation into headers under `cpp/include/qq_dump_db/` and implementations under `cpp/src/`.
- Retained the existing Win32 process/handle discovery, page-HMAC validation, memory scanning, and SQLCipher page transform algorithms. No new extraction mechanism was added.
- Aligned the C++ command line and key-map output with shared contract v1.
- C++ and Python UI languages are limited to Simplified Chinese (`zh-CN`) and English (`en-US`), with `auto` language selection.
- Delivery continues to exclude `third_party/`.

## C++ module map

| Module | Responsibility |
|---|---|
| `main.cpp` | Convert the Windows Unicode command line to UTF-8 and dispatch |
| `cli.cpp` | Parse and validate options; help/version output |
| `i18n/catalog.cpp` | Chinese/English message catalog and language resolution |
| `utils/hex.cpp` | Hex encoding/decoding and UTF-8 path formatting |
| `platform/win32/processes.cpp` | QQ process discovery and process ancestry |
| `platform/win32/handles.cpp` | File-handle inspection and owner/path mapping |
| `platform/win32/memory.cpp` | Process memory region scanning |
| `discovery/qq_instances.cpp` | Account path parsing and instance selection |
| `discovery/databases.cpp` | Database discovery and page-1 salt collection |
| `crypto/sqlcipher.cpp` | BCrypt PBKDF2, HMAC, AES-CBC, and page HMAC validation |
| `services/decryptor.cpp` | Database page transformation and SQLite validation |
| `services/keymap_writer.cpp` | Versioned JSON output with UTC timestamp and atomic replace |
| `services/waiter.cpp` | Wait for selected QQ process(es), or skip with warning |
| `services/workflow.cpp` | Application workflow and stable exit codes |

## Contract alignment

- Added `--output-dir`, `--lang`, `--no-wait`, `--help`, and `--version`.
- Preserved `--qq`, `--pid`, `--db-dir`, `-o/--output`.
- Added Chinese/English localized CLI and progress messages.
- Default output root is `<current working directory>/output/<QQ号>/`.
- Relative `--output` paths resolve under the output root; absolute paths are used as-is.
- Key maps now contain `schema_version: 1`, `key_map`, and a UTC RFC 3339 `_generated` timestamp.
- Key-map writes use a sibling temporary file and `MoveFileExW` atomic replacement.
- Decrypted databases are written to temporary files, opened and queried through SQLite, then atomically replaced into the final path.
- Filename collisions and input/output path collisions are rejected instead of silently overwriting a source database.
- Full and partial recovered key material is no longer printed in progress logs.
- Stable exit codes follow `shared/error-codes.md` for CLI, process, mapping, discovery, recovery, output, and decryption outcomes.

## Build dependency

The source archive does not include `third_party/`. CMake now requires a system SQLite development package. On Windows, the documented build path uses:

```powershell
vcpkg install sqlite3:x64-windows
cmake -B build -A x64 -DCMAKE_TOOLCHAIN_FILE="$env:VCPKG_INSTALLATION_ROOT/scripts/buildsystems/vcpkg.cmake"
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
```

The GitHub Actions release workflow installs SQLite with vcpkg before configuring CMake.

## Verification

- All C++ translation units (including the CLI test) compiled to object files with Clang C++17 and local Win32 API declaration stubs plus the host SQLite header.
- The C++ CLI contract test executable ran successfully with a host-side Windows language stub.
- CMake configured successfully with the complete target and CTest definition.
- Actual MSVC/Windows linking, the Windows CTest run, Win32 process/handle behavior, real QQ database handling, and end-to-end decryption were not executable in the Linux build environment; these remain Windows acceptance tests.
- Python phase-2 files and tests were retained without modification.

## Delivery

`third_party/`, build outputs, local data, Python bytecode, and temporary files are excluded from the phase-3 source archive. C++ users must provide SQLite separately through vcpkg or another system installation.
