# Phase 2 change log

## Scope

Phase 2 modularizes the Python implementation and limits Python UI localization to Simplified Chinese and English. The C++ source (`main.cpp`) and CMake layout are retained unchanged in this phase.

## Python package

- Moved Win32 API declarations and process/memory/handle operations into `python/qq_dump_db/platform/win32/`.
- Split QQ instance resolution and database discovery into `discovery/`.
- Moved SQLCipher verification and page/database decryption into `crypto/sqlcipher.py`.
- Moved the application workflow, key-map writer, and decrypt orchestration into `services/`.
- Added `cli.py`, `app.py`, `errors.py`, `i18n.py`, and package entry points.
- Kept `dump_qq_key_auto.py` as a backwards-compatible launcher.
- Added the installable package metadata in `pyproject.toml` and `requirements.txt`.

## Localization

- Supported UI languages: `zh-CN` and `en-US`.
- `auto` selects from `QQ_DUMP_DB_LANG`, then Windows UI language / system locale, with `zh-CN` fallback.
- The `read_db.py` viewer uses the same two-language catalog.
- CLI parameter names, JSON keys, error IDs, and exit codes remain language-neutral.

## Python behavior aligned to shared contract v1

- Added `--output-dir`, `--lang`, `--no-wait`, and `--version`.
- Default output root is `<current working directory>/output/<QQ号>/`.
- New key maps use `schema_version: 1` and UTC `_generated` timestamps.
- Key-map and decrypted DB writes use temporary files and atomic replacement after validation.
- Same-name output DB collisions are reported instead of silently overwritten.
- The default flow waits for selected QQ processes to exit; Enter during the wait and `--no-wait` both allow early continuation with a WAL warning.

## Verification performed

- Python unit tests: 13 passed.
- Python source compilation (`compileall`): passed.
- Wheel build: passed (`qq_dump_db-2.0.0-py3-none-any.whl`).
- Installed-wheel `--help` and `--version`: passed.
- Generated `key_map.json`: validated against `shared/key-map.schema.json`.

Windows-only process enumeration, real QQ WAL behavior, and real database decryption were not end-to-end tested in the build environment and must be verified on a Windows machine with a test account.

## Delivery packaging

The phase-2 source archive intentionally excludes `third_party/`, build outputs, Python cache files, and local output data. The C++ target can use a system SQLite installation or requires the SQLite amalgamation to be provided separately under `third_party/sqlite3/`.
