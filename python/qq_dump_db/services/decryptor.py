"""Map verified salts to rediscovered files and decrypt without name collisions."""
from __future__ import annotations

import os
from pathlib import Path

from ..crypto.sqlcipher import decrypt_db
from ..i18n import tr


def build_decrypt_jobs(global_dbs, account_db_map, key_map):
    jobs = {}
    for _account, source_path, page1 in global_dbs:
        salt_hex = page1[:16].hex()
        key_hex = key_map.get(salt_hex)
        if key_hex:
            jobs[os.path.abspath(source_path)] = bytes.fromhex(key_hex)
    for salt_hex, entries in account_db_map.items():
        key_hex = key_map.get(salt_hex)
        if not key_hex:
            continue
        key_bytes = bytes.fromhex(key_hex)
        for _account, source_path, _page1 in entries:
            jobs[os.path.abspath(source_path)] = key_bytes
    return jobs


def decrypt_databases(global_dbs, account_db_map, key_map, output_dir):
    jobs = build_decrypt_jobs(global_dbs, account_db_map, key_map)
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    by_name = {}
    for source_path, key_bytes in jobs.items():
        by_name.setdefault(Path(source_path).name.casefold(), []).append((source_path, key_bytes))

    ok_count = 0
    fail_count = 0
    for name_key, entries in sorted(by_name.items()):
        target_name = Path(entries[0][0]).name
        if len(entries) > 1:
            print(tr("decrypt.conflict", name=target_name))
            fail_count += len(entries)
            continue

        source_path, key_bytes = entries[0]
        target_path = output_dir / target_name
        if os.path.normcase(os.path.abspath(source_path)) == os.path.normcase(str(target_path.resolve())):
            print(tr("decrypt.fail", name=target_name))
            fail_count += 1
            continue

        success = decrypt_db(source_path, target_path, key_bytes)
        if success:
            size_kb = target_path.stat().st_size / 1024
            print(tr("decrypt.ok", name=target_name, size=size_kb))
            ok_count += 1
        else:
            print(tr("decrypt.fail", name=target_name))
            fail_count += 1

    return ok_count, fail_count, len(jobs)
