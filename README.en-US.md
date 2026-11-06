# qq_dump_db

A Windows-only local database utility with C++ and Python implementations. Use it only with QQ accounts and local data you own or are authorized to access.

## Implementations

- **C++**: modular native implementation; the root `main.cpp` remains the entry point and modules live under `cpp/src/` and `cpp/include/`.
- **Python**: a modular package under `python/qq_dump_db/`; the root `dump_qq_key_auto.py` remains as a compatibility launcher.

The Python CLI supports Simplified Chinese and English only (`zh-CN`, `en-US`). Language selection never changes JSON keys, CLI option names, error IDs, or exit codes. The `read_db.py` viewer also accepts `--lang zh-CN|en-US|auto`.

## Python installation

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e .
```

Run either entry point:

```powershell
qq-dump-db --qq <QQ-number> --lang en-US
python dump_qq_key_auto.py --qq <QQ-number> --lang zh-CN
python -m qq_dump_db --qq <QQ-number> --lang auto
```

If the package is not installed, use the compatibility launcher. Run from a terminal with the Windows permissions required to inspect the selected QQ process.

## Python options

```text
--qq <QQ-number>          Required target account
--pid <PID>               Optional diagnostic scan PID override
--db-dir <directory>      Optional account database directory
-o, --output <path>       Key-map JSON path (relative to output directory)
--output-dir <directory>  Output root (default: ./output/<QQ-number>)
--lang <auto|zh-CN|en-US>
--no-wait                 Skip waiting for QQ to exit before re-reading databases
-h, --help                Show help
--version                 Show version
```

By default, the program asks you to close the selected QQ process and waits for it to exit before rediscovering database files. Press Enter during the wait or use `--no-wait` to continue early; either can produce an incomplete view if the WAL has not been checkpointed.

## Language selection

1. Explicit `--lang zh-CN` or `--lang en-US`.
2. `QQ_DUMP_DB_LANG` environment variable (`zh-CN` or `en-US`).
3. Detected Windows UI language or system locale, mapped to Chinese or English.
4. Fallback to `zh-CN`.

## Database viewer

```powershell
python read_db.py --qq <QQ-number> --lang en-US
python read_db.py --qq <QQ-number> --lang zh-CN --db nt_msg.db
```

## Output

By default, all Python outputs are written under:

```text
./output/<QQ-number>/
    key_map.json
    <decrypted database files>
```

New key maps use `schema_version: 1` and a UTC `_generated` timestamp. The file contains sensitive decryption key material. Keep it private; do not commit it to Git or share it publicly.

## Project layout

```text
python/qq_dump_db/
  cli.py                 CLI parsing
  app.py                 application boundary and exit codes
  i18n.py                Chinese/English messages
  errors.py              stable error IDs and exit statuses
  platform/win32/        Windows process, handle, and memory APIs
  discovery/             QQ instance and database discovery
  crypto/                SQLCipher page verification/decryption
  services/              workflow, output, and decrypt orchestration
shared/                  cross-language CLI / JSON / workflow contracts
```

## Dependencies

The Python package requires `cryptography`. The source archive intentionally excludes `third_party/`. The C++ implementation uses Windows APIs, Windows BCrypt, and SQLite installed separately (for example through vcpkg).

## C++ build

Install SQLite with vcpkg first:

```powershell
vcpkg install sqlite3:x64-windows
cmake -B build -A x64 -DCMAKE_TOOLCHAIN_FILE="$env:VCPKG_INSTALLATION_ROOT/scripts/buildsystems/vcpkg.cmake"
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
```

The C++ CLI also supports `--lang zh-CN|en-US|auto`, `--output-dir`, and `--no-wait`. Relative `--output` paths are resolved under the output directory; the default output root is `./output/<QQ number>/`.

## Development tests

```powershell
python -m pip install -e .
python -m unittest discover -s tests/python -v
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
```

See [`shared/`](shared/README.md) for the cross-language contract.

## License

MIT. Original project: https://github.com/NapNeko/qq_dump_db
