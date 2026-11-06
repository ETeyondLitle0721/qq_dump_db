"""Read-only inspection of QQ-owned database file handles."""
import ctypes
import ntpath
import ctypes.wintypes as wt
from .api import (
    SYSTEM_EXTENDED_HANDLE_INFORMATION, SYSTEM_HANDLE_INFORMATION_EX,
    SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX, PROCESS_DUP_HANDLE,
    DUPLICATE_SAME_ACCESS, FILE_TYPE_DISK, FILE_NAME_NORMALIZED,
    VOLUME_NAME_DOS, get_kernel32, get_ntdll,
)
from .processes import find_qq_process_parent_map
from ...discovery.qq_instances import parse_qq_account_from_db_path, resolve_wrapper_pid_for_handle_owner
from ...i18n import tr

def find_qq_instance_mappings(input_pids, wrapper_pids):
    """Map wrapper.node PID -> QQ number using nt_msg.db handle ownership.

    The actual account number is parsed from the handle's resolved file path.
    A handle owner is associated with a wrapper process only when the QQ.exe
    parent/child tree identifies a unique relationship.
    """
    if not input_pids:
        raise RuntimeError("No QQ process IDs available for handle inspection.")

    ntdll = get_ntdll()
    query_system_information = ntdll.NtQuerySystemInformation
    query_system_information.argtypes = [
        wt.ULONG, ctypes.c_void_p, wt.ULONG, ctypes.POINTER(wt.ULONG)
    ]
    query_system_information.restype = ctypes.c_long

    status_info_length_mismatch = ctypes.c_long(0xC0000004).value
    status_buffer_too_small = ctypes.c_long(0xC0000023).value
    buffer_size = 1024 * 1024
    handle_buffer = None
    for _ in range(12):
        handle_buffer = ctypes.create_string_buffer(buffer_size)
        returned_length = wt.ULONG(0)
        status = query_system_information(
            SYSTEM_EXTENDED_HANDLE_INFORMATION,
            handle_buffer,
            buffer_size,
            ctypes.byref(returned_length),
        )
        if status >= 0:
            break
        if status not in (status_info_length_mismatch, status_buffer_too_small):
            raise RuntimeError(
                f"NtQuerySystemInformation failed (NTSTATUS 0x{status & 0xFFFFFFFF:08X})."
            )
        buffer_size = returned_length.value if returned_length.value > buffer_size else buffer_size * 2
    else:
        raise RuntimeError("Could not allocate a large enough system handle table.")

    info = ctypes.cast(
        handle_buffer, ctypes.POINTER(SYSTEM_HANDLE_INFORMATION_EX)
    ).contents
    entry_offset = SYSTEM_HANDLE_INFORMATION_EX.Handles.offset
    entry_size = ctypes.sizeof(SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX)
    max_entries = max(0, (buffer_size - entry_offset) // entry_size)
    handle_count = min(int(info.NumberOfHandles), max_entries)
    entries_type = SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX * handle_count
    entries = ctypes.cast(
        ctypes.addressof(handle_buffer) + entry_offset,
        ctypes.POINTER(entries_type),
    ).contents

    kernel32 = get_kernel32()

    process_handles = {}
    for pid in set(int(p) for p in input_pids):
        process = kernel32.OpenProcess(PROCESS_DUP_HANDLE, False, pid)
        if process:
            process_handles[pid] = process
    if not process_handles:
        raise RuntimeError(
            "Cannot open any QQ process for handle inspection. Run with sufficient permissions."
        )

    current_process = kernel32.GetCurrentProcess()
    found_handles = set()  # (owner PID, normalized path)
    try:
        for entry in entries:
            owner_pid = int(entry.UniqueProcessId)
            source_process = process_handles.get(owner_pid)
            if not source_process:
                continue

            duplicated = wt.HANDLE()
            source_handle = wt.HANDLE(int(entry.HandleValue))
            ok = kernel32.DuplicateHandle(
                source_process, source_handle, current_process,
                ctypes.byref(duplicated), 0, False, DUPLICATE_SAME_ACCESS,
            )
            if not ok:
                continue
            try:
                if kernel32.GetFileType(duplicated) != FILE_TYPE_DISK:
                    continue
                path_buffer = ctypes.create_unicode_buffer(32768)
                length = kernel32.GetFinalPathNameByHandleW(
                    duplicated, path_buffer, len(path_buffer),
                    FILE_NAME_NORMALIZED | VOLUME_NAME_DOS,
                )
                if length == 0 or length >= len(path_buffer):
                    continue
                path = ntpath.normpath(path_buffer.value)
                if parse_qq_account_from_db_path(path) is not None:
                    found_handles.add((owner_pid, path))
            finally:
                kernel32.CloseHandle(duplicated)
    finally:
        for process in process_handles.values():
            kernel32.CloseHandle(process)

    if not found_handles:
        raise RuntimeError(
            "No QQ-owned nt_msg.db handle with the expected "
            "Tencent Files/<QQ>/nt_qq/nt_db layout was found. "
            "Make sure QQ is logged in and its message database is open."
        )

    parent_map = find_qq_process_parent_map()
    mappings = []
    for owner_pid, path in sorted(found_handles):
        account = parse_qq_account_from_db_path(path)
        wrapper_pid = resolve_wrapper_pid_for_handle_owner(
            owner_pid, wrapper_pids, parent_map)
        mappings.append({
            'account': account,
            'wrapper_pid': wrapper_pid,
            'handle_pid': owner_pid,
            'db_path': path,
        })

    print(tr("mapping.detected_header"))
    for item in mappings:
        if item['wrapper_pid']:
            print(tr("mapping.detected", wrapper_pid=item['wrapper_pid'], account=item['account'], handle_pid=item['handle_pid']))
        else:
            print(tr("mapping.unmatched", account=item['account'], handle_pid=item['handle_pid']))
    return mappings

