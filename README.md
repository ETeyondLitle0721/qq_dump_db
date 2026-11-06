# qq_dump_db

A Windows-only local database utility with C++ and Python implementations. Use it only with QQ accounts and local data you own or are authorized to access.

## Implementations

- **C++**: existing native implementation (`main.cpp`).
- **Python**: modular package under `python/qq_dump_db/`; the legacy `dump_qq_key_auto.py` remains as a compatible launcher.

The Python CLI supports Simplified Chinese and English (`zh-CN`, `en-US`). The language does not change JSON keys, CLI option names, error IDs, or exit codes. The `read_db.py` viewer also accepts `--lang zh-CN|en-US|auto`.

## Python setup

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e .
```

You can then run either entry point:

```powershell
qq-dump-db --qq <QQ号> --lang zh-CN
python dump_qq_key_auto.py --qq <QQ号> --lang en-US
python -m qq_dump_db --qq <QQ号> --lang auto
```

If the package is not installed, use the legacy launcher above. Run from an elevated terminal when Windows process permissions require it.

### Python options

```text
--qq <QQ号>             Required target account number
--pid <PID>             Optional diagnostic scan PID override
--db-dir <directory>    Optional account database directory
-o, --output <path>     Key-map JSON path (relative to output directory)
--output-dir <directory> Output root (default: ./output/<QQ号>)
--lang <auto|zh-CN|en-US>
--no-wait               Skip waiting for QQ to exit before re-reading database files
-h, --help              Show help
--version               Show version
```

`--no-wait` can produce an incomplete view of database files if QQ has not checkpointed its WAL. By default, the program asks you to close the selected QQ process and waits for it to exit before re-discovering the database files.

### Language selection

1. Explicit `--lang zh-CN` or `--lang en-US`.
2. `QQ_DUMP_DB_LANG` environment variable (`zh-CN` or `en-US`).
3. Detected Windows UI language or system locale, mapped to Chinese or English.
4. Fallback to `zh-CN`.

## Database viewer

```powershell
python read_db.py --qq <QQ号> --lang zh-CN
python read_db.py --qq <QQ号> --lang en-US --db nt_msg.db
```

## Output

By default, all Python outputs are written under:

```text
./output/<QQ号>/
    key_map.json
    <decrypted database files>
```

New key maps use `schema_version: 1` and a UTC `_generated` timestamp. The file contains sensitive decryption key material; keep it private and do not commit it to source control or share it publicly.

## Project layout

```text
python/qq_dump_db/
  cli.py                 CLI parsing and compatibility options
  app.py                 application boundary and exit codes
  i18n.py                Chinese/English messages
  errors.py              stable error IDs and exit statuses
  platform/win32/        Windows process, handle, and memory APIs
  discovery/             QQ instance and database discovery
  crypto/                SQLCipher page verification/decryption
  services/              workflow, output, and decrypt orchestration
shared/                  cross-language CLI / JSON / workflow contracts
```

## Third-party dependencies

The Python package requires `cryptography`. The source delivery archive intentionally omits `third_party/`; the C++ CMake target expects the SQLite amalgamation to be supplied separately under `third_party/sqlite3/` before building.

## C++ build

```powershell
cmake -B build -A x64
cmake --build build --config Release
```

## Development checks

```powershell
python -m pip install -e .
python -m unittest discover -s tests/python -v
```

See [`shared/`](shared/README.md) for the cross-language contract.

## License

MIT. Original project: https://github.com/NapNeko/qq_dump_db
