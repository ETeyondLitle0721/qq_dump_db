"""Top-level business workflow for the Python implementation."""
from __future__ import annotations

import ctypes
import json
import os
import sys
import time
from pathlib import Path

from ..crypto.sqlcipher import PRE_LOGIN_KEY, derive_enc_key, verify_key_hmac
from ..discovery.databases import collect_db_info, find_db_dirs
from ..discovery.qq_instances import select_qq_instance
from ..errors import (
    QQDumpError, EXIT_PLATFORM_UNSUPPORTED, EXIT_QQ_PROCESS_NOT_FOUND,
    EXIT_INSTANCE_MAPPING_FAILED, EXIT_DATABASE_NOT_FOUND,
    EXIT_KEY_NOT_RECOVERED, EXIT_OUTPUT_IO_FAILED, EXIT_DECRYPT_FAILED,
)
from ..i18n import tr
from ..platform.win32.api import (
    PROCESS_VM_READ, PROCESS_QUERY_INFORMATION, get_kernel32,
)
from ..platform.win32.handles import find_qq_instance_mappings
from ..platform.win32.memory import scan_by_salt
from ..platform.win32.processes import find_qq_pids, find_qq_wrapper_pids
from .decryptor import decrypt_databases
from .keymap_writer import resolve_output_paths, write_key_map


def _raise(code, message):
    error_ids = {
        EXIT_PLATFORM_UNSUPPORTED: "PLATFORM_UNSUPPORTED",
        EXIT_QQ_PROCESS_NOT_FOUND: "QQ_PROCESS_NOT_FOUND",
        EXIT_INSTANCE_MAPPING_FAILED: "INSTANCE_MAPPING_FAILED",
        EXIT_DATABASE_NOT_FOUND: "DATABASE_NOT_FOUND",
        EXIT_KEY_NOT_RECOVERED: "KEY_NOT_RECOVERED",
        EXIT_OUTPUT_IO_FAILED: "OUTPUT_IO_FAILED",
        EXIT_DECRYPT_FAILED: "DECRYPT_FAILED",
    }
    raise QQDumpError(code, error_ids[code], message)


def _wait_for_process_exit(scan_pids):
    targets = {int(pid) for pid in scan_pids if int(pid) > 0}
    if not targets:
        return

    interactive = sys.stdin.isatty()
    if interactive:
        import msvcrt
        print(tr("wait.prompt"))
    else:
        msvcrt = None

    print(tr("wait.waiting", pids=sorted(targets)))
    while targets.intersection(find_qq_pids()):
        if msvcrt is not None and msvcrt.kbhit():
            pressed = msvcrt.getwch()
            if pressed in ("\r", "\n"):
                print(tr("warning.prefix", message=tr("wait.skipped")))
                return
        time.sleep(0.1 if interactive else 1.0)
    print(tr("wait.done"))


def _print_mapping_summary(global_results, account_results, global_dbs, account_map, total_salts):
    all_results = {**global_results, **account_results}
    line = "=" * 72
    print(tr("result.header", line=line, found=len(all_results), total=total_salts))
    for salt_hex in sorted(global_results):
        names = ", ".join(os.path.basename(e[1]) for e in global_dbs if e[2][:16].hex() == salt_hex)
        print(tr("result.global", salt=salt_hex, names=names))
    for salt_hex in sorted(account_results):
        names = ", ".join(os.path.basename(e[1]) for e in account_map.get(salt_hex, []))
        print(tr("result.account", salt=salt_hex, names=names))
    unresolved = [salt for salt in account_map if salt not in account_results]
    if unresolved:
        print(tr("result.unresolved", count=len(unresolved)))
        for salt_hex in unresolved:
            names = ", ".join(os.path.basename(e[1]) for e in account_map[salt_hex])
            print(f"  {salt_hex} ({names})")
    return all_results


def run_workflow(args):
    if os.name != "nt":
        _raise(EXIT_PLATFORM_UNSUPPORTED, tr("app.platform_error"))

    # 1. Discover QQ processes and correlate the target account with its wrapper.
    qq_pids = find_qq_pids()
    wrapper_pids = find_qq_wrapper_pids(qq_pids)
    if not wrapper_pids and not args.pid:
        _raise(EXIT_QQ_PROCESS_NOT_FOUND, tr("process.none"))

    handle_owner_pids = list(qq_pids)
    if args.pid and args.pid not in handle_owner_pids:
        handle_owner_pids.append(args.pid)

    mappings = []
    try:
        if handle_owner_pids:
            mappings = find_qq_instance_mappings(handle_owner_pids, wrapper_pids)
    except RuntimeError as exc:
        if not args.db_dir:
            _raise(EXIT_INSTANCE_MAPPING_FAILED, tr("mapping.failed", detail=str(exc)))
        print(tr("warning.prefix", message=tr("mapping.failed", detail=str(exc))))

    account_db_dir = None
    if args.db_dir:
        mapped_pids = sorted({
            item["wrapper_pid"] for item in mappings
            if item["account"] == str(args.qq) and item["wrapper_pid"]
        })
        scan_pids = mapped_pids or wrapper_pids
        if not mapped_pids:
            print(tr("warning.prefix", message=tr("workflow.db_dir_unmapped")))
        if args.pid and not scan_pids:
            scan_pids = [args.pid]
    else:
        try:
            account_db_dir, scan_pids = select_qq_instance(args.qq, mappings)
            print(tr("mapping.db_selected", qq=args.qq, path=account_db_dir))
            print(tr("mapping.pids_selected", pids=scan_pids))
        except RuntimeError as exc:
            _raise(EXIT_INSTANCE_MAPPING_FAILED, tr("mapping.failed", detail=str(exc)))

    if args.pid:
        scan_pids = [args.pid]
        print(tr("mapping.manual_pid", pid=args.pid))
        known = [item for item in mappings if item["wrapper_pid"] == args.pid]
        if known:
            for item in known:
                if item["account"] != str(args.qq):
                    print(tr("warning.prefix", message=tr("mapping.manual_mismatch", pid=args.pid, mapped=item["account"], requested=args.qq)))
        else:
            print(tr("warning.prefix", message=tr("mapping.manual_unconfirmed", pid=args.pid)))
    else:
        print(tr("mapping.scan_pids", count=len(scan_pids), qq=args.qq))

    # 2. Find current database files and read their page-1 salts.
    try:
        db_dirs = find_db_dirs(args.qq, account_db_dir, args.db_dir)
        global_dbs, account_db_map = collect_db_info(db_dirs)
    except (OSError, RuntimeError) as exc:
        _raise(EXIT_DATABASE_NOT_FOUND, str(exc))
    if not global_dbs and not account_db_map:
        _raise(EXIT_DATABASE_NOT_FOUND, tr("db.none"))

    account_file_count = sum(len(entries) for entries in account_db_map.values())
    print(tr("db.summary", global_count=len(global_dbs), file_count=account_file_count, salt_count=len(account_db_map)))

    # 3. Derive and validate global database keys.
    global_results = {}
    for _account, file_path, page1 in global_dbs:
        salt = page1[:16]
        enc_key = derive_enc_key(PRE_LOGIN_KEY, salt)
        if verify_key_hmac(page1, enc_key):
            global_results[salt.hex()] = enc_key.hex()
            print(tr("db.global_ok", name=os.path.basename(file_path)))
        else:
            print(tr("db.global_bad", name=os.path.basename(file_path)))

    # 4. Scan only selected wrapper processes; validate every candidate using page-1 HMAC.
    account_results = {}
    if account_db_map:
        all_scan_hits = {}
        salt_list = list(account_db_map.keys())
        kernel32 = get_kernel32()
        for pid in scan_pids:
            handle = kernel32.OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid)
            if not handle:
                print(tr("warning.prefix", message=tr("memory.cannot_open", pid=pid, error=ctypes.get_last_error())))
                continue
            print(tr("memory.scanning", pid=pid, count=len(salt_list)))
            try:
                process_hits = scan_by_salt(handle, pid, salt_list)
            finally:
                kernel32.CloseHandle(handle)
            for salt_hex, candidates in process_hits.items():
                merged = all_scan_hits.setdefault(salt_hex, [])
                for candidate in candidates:
                    if not any(existing[2] == candidate[2] for existing in merged):
                        merged.append(candidate)

        total_candidates = sum(len(items) for items in all_scan_hits.values())
        print(tr("memory.combined", found=len(all_scan_hits), total=len(salt_list), candidates=total_candidates, processes=len(scan_pids)))
        for salt_hex, candidates in all_scan_hits.items():
            db_entries = account_db_map.get(salt_hex, [])
            verified = False
            rejected = 0
            for pid, address, key_hex in candidates:
                enc_key = bytes.fromhex(key_hex)
                verified_entry = next((entry for entry in db_entries if verify_key_hmac(entry[2], enc_key)), None)
                if verified_entry is not None:
                    account_results[salt_hex] = key_hex
                    print(tr("memory.hit", name=os.path.basename(verified_entry[1]), pid=pid, address=address, tested=rejected + 1))
                    verified = True
                    break
                rejected += 1
            if not verified and db_entries:
                names = ", ".join(os.path.basename(entry[1]) for entry in db_entries)
                print(tr("memory.miss_candidates", names=names, count=len(candidates)))
        for salt_hex, db_entries in account_db_map.items():
            if salt_hex not in all_scan_hits:
                names = ", ".join(os.path.basename(entry[1]) for entry in db_entries)
                print(tr("memory.miss_none", names=names))

    all_results = _print_mapping_summary(
        global_results, account_results, global_dbs, account_db_map,
        len({e[2][:16].hex() for e in global_dbs} | set(account_db_map)),
    )
    if not all_results:
        _raise(EXIT_KEY_NOT_RECOVERED, tr("result.none"))

    # 5. Persist a versioned key map before the optional WAL wait.
    output_dir, key_map_path = resolve_output_paths(args)
    input_paths = {os.path.normcase(os.path.abspath(item[1])) for item in global_dbs}
    input_paths.update(os.path.normcase(os.path.abspath(item[1])) for entries in account_db_map.values() for item in entries)
    if os.path.normcase(str(key_map_path)) in input_paths:
        _raise(EXIT_OUTPUT_IO_FAILED, tr("workflow.output_db_collision"))
    try:
        output_dir.mkdir(parents=True, exist_ok=True)
        write_key_map(key_map_path, all_results)
    except (OSError, ValueError) as exc:
        _raise(EXIT_OUTPUT_IO_FAILED, str(exc))
    print(tr("result.saved", path=key_map_path))

    # 6. Wait for QQ to close so the on-disk database can checkpoint its WAL.
    if args.no_wait:
        print(tr("warning.prefix", message=tr("wait.skipped")))
    else:
        _wait_for_process_exit(scan_pids)

    # 7. Rediscover files after the wait; do not rely on stale pre-wait file lists.
    try:
        refreshed_dirs = find_db_dirs(args.qq, account_db_dir, args.db_dir)
        refreshed_global_dbs, refreshed_account_db_map = collect_db_info(refreshed_dirs)
    except (OSError, RuntimeError) as exc:
        _raise(EXIT_DECRYPT_FAILED, str(exc))

    # 8. Decrypt each rediscovered database matching a validated salt.
    print(tr("decrypt.header", directory=output_dir))
    try:
        ok_count, fail_count, job_count = decrypt_databases(
            refreshed_global_dbs, refreshed_account_db_map, all_results, output_dir,
        )
    except OSError as exc:
        _raise(EXIT_OUTPUT_IO_FAILED, str(exc))
    missing_count = max(0, len(all_results) - job_count)
    total_failures = fail_count + missing_count
    print(tr("decrypt.summary", ok=ok_count, failed=total_failures, directory=output_dir))
    if total_failures or job_count == 0:
        _raise(EXIT_DECRYPT_FAILED, tr("decrypt.summary", ok=ok_count, failed=total_failures, directory=output_dir))
    return 0
