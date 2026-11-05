"""
Auto-dump NTQQ SQLCipher database keys from a running QQ process.

Zero prior knowledge required - no hardcoded PIDs, keys, addresses, or salts.
Finds the QQ main process (wrapper.node), scans memory for x'key_salt' patterns.

Usage (run as Administrator):
    python dump_qq_key_auto.py --qq 10001
    python dump_qq_key_auto.py --qq 10001 --pid 12345
"""

import ctypes
import ctypes.wintypes as wt
from ctypes import windll, byref, sizeof, create_string_buffer
import struct, hashlib, hmac as hmac_mod, os, sys, re, time, json, argparse, sqlite3
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# ── Windows API ──────────────────────────────────────────────────────────────

PROCESS_VM_READ           = 0x0010
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_DUP_HANDLE        = 0x0040
DUPLICATE_SAME_ACCESS     = 0x00000002
FILE_TYPE_DISK            = 0x0001
FILE_NAME_NORMALIZED      = 0x00000000
VOLUME_NAME_DOS           = 0x00000000
SYSTEM_EXTENDED_HANDLE_INFORMATION = 64
TH32CS_SNAPPROCESS        = 0x00000002
TH32CS_SNAPMODULE         = 0x00000008
TH32CS_SNAPMODULE32       = 0x00000010
MEM_COMMIT                = 0x1000
READABLE_PROTS            = {0x02, 0x04, 0x06, 0x08, 0x20, 0x40, 0x60, 0x80}
MAX_REGION                = 256 * 1024 * 1024

class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ('BaseAddress',       ctypes.c_void_p),
        ('AllocationBase',    ctypes.c_void_p),
        ('AllocationProtect', wt.DWORD),
        ('RegionSize',        ctypes.c_size_t),
        ('State',             wt.DWORD),
        ('Protect',           wt.DWORD),
        ('Type',              wt.DWORD),
    ]

class PROCESSENTRY32(ctypes.Structure):
    _fields_ = [
        ('dwSize',              wt.DWORD),
        ('cntUsage',            wt.DWORD),
        ('th32ProcessID',       wt.DWORD),
        ('th32DefaultHeapID',   ctypes.POINTER(ctypes.c_ulong)),
        ('th32ModuleID',        wt.DWORD),
        ('cntThreads',          wt.DWORD),
        ('th32ParentProcessID', wt.DWORD),
        ('pcPriClassBase',      ctypes.c_long),
        ('dwFlags',             wt.DWORD),
        ('szExeFile',           ctypes.c_char * 260),
    ]

class MODULEENTRY32(ctypes.Structure):
    _fields_ = [
        ('dwSize',        wt.DWORD),
        ('th32ModuleID',  wt.DWORD),
        ('th32ProcessID', wt.DWORD),
        ('GlblcntUsage',  wt.DWORD),
        ('ProccntUsage',  wt.DWORD),
        ('modBaseAddr',   ctypes.POINTER(ctypes.c_byte)),
        ('modBaseSize',   wt.DWORD),
        ('hModule',       wt.HMODULE),
        ('szModule',      ctypes.c_char * 256),
        ('szExePath',     ctypes.c_char * 260),
    ]


class SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX(ctypes.Structure):
    _fields_ = [
        ('Object',                 ctypes.c_void_p),
        ('UniqueProcessId',        ctypes.c_size_t),
        ('HandleValue',            ctypes.c_size_t),
        ('GrantedAccess',          wt.ULONG),
        ('CreatorBackTraceIndex',  wt.USHORT),
        ('ObjectTypeIndex',        wt.USHORT),
        ('HandleAttributes',       wt.ULONG),
        ('Reserved',               wt.ULONG),
    ]


class SYSTEM_HANDLE_INFORMATION_EX(ctypes.Structure):
    _fields_ = [
        ('NumberOfHandles', ctypes.c_size_t),
        ('Reserved',        ctypes.c_size_t),
        ('Handles',         SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX * 1),
    ]


# Declare pointer-sized Win32 handles explicitly. Without these declarations,
# ctypes defaults HANDLE-returning APIs to a 32-bit int on 64-bit Python.
_kernel32 = windll.kernel32
_kernel32.CreateToolhelp32Snapshot.argtypes = [wt.DWORD, wt.DWORD]
_kernel32.CreateToolhelp32Snapshot.restype = wt.HANDLE
_kernel32.Process32First.argtypes = [wt.HANDLE, ctypes.POINTER(PROCESSENTRY32)]
_kernel32.Process32First.restype = wt.BOOL
_kernel32.Process32Next.argtypes = [wt.HANDLE, ctypes.POINTER(PROCESSENTRY32)]
_kernel32.Process32Next.restype = wt.BOOL
_kernel32.Module32First.argtypes = [wt.HANDLE, ctypes.POINTER(MODULEENTRY32)]
_kernel32.Module32First.restype = wt.BOOL
_kernel32.Module32Next.argtypes = [wt.HANDLE, ctypes.POINTER(MODULEENTRY32)]
_kernel32.Module32Next.restype = wt.BOOL
_kernel32.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
_kernel32.OpenProcess.restype = wt.HANDLE
_kernel32.CloseHandle.argtypes = [wt.HANDLE]
_kernel32.CloseHandle.restype = wt.BOOL
_kernel32.ReadProcessMemory.argtypes = [
    wt.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_size_t),
]
_kernel32.ReadProcessMemory.restype = wt.BOOL
_kernel32.VirtualQueryEx.argtypes = [
    wt.HANDLE, ctypes.c_void_p, ctypes.POINTER(MEMORY_BASIC_INFORMATION),
    ctypes.c_size_t,
]
_kernel32.VirtualQueryEx.restype = ctypes.c_size_t

# ── SQLCipher constants ──────────────────────────────────────────────────────

EXT_HEADER  = 1024
PAGE_SIZE   = 4096
SALT_SIZE   = 16
KEY_SIZE    = 32
IV_SIZE     = 16
HMAC_SIZE   = 20
RESERVE     = 48
HMAC_MASK   = 0x3a
KDF_ITER    = 4000
FAST_ITER   = 2

PRE_LOGIN_KEY = b"BD156D6710D54D8782F4"  # hardcoded in wrapper.node

# ── Process helpers ──────────────────────────────────────────────────────────

def find_qq_pids():
    snapshot = _kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snapshot in (ctypes.c_void_p(-1).value, -1):
        return []
    pe = PROCESSENTRY32()
    pe.dwSize = sizeof(PROCESSENTRY32)
    pids = []
    if _kernel32.Process32First(snapshot, byref(pe)):
        while True:
            name = pe.szExeFile.decode('utf-8', errors='replace').lower()
            if name == 'qq.exe':
                pids.append(pe.th32ProcessID)
            if not _kernel32.Process32Next(snapshot, byref(pe)):
                break
    _kernel32.CloseHandle(snapshot)
    return pids


def pid_has_module(pid, module_name):
    snapshot = _kernel32.CreateToolhelp32Snapshot(
        TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid)
    if snapshot in (ctypes.c_void_p(-1).value, -1, 0):
        return False
    me = MODULEENTRY32()
    me.dwSize = sizeof(MODULEENTRY32)
    found = False
    if _kernel32.Module32First(snapshot, byref(me)):
        while True:
            mod = me.szModule.decode('utf-8', errors='replace').lower()
            if mod == module_name.lower():
                found = True
                break
            if not _kernel32.Module32Next(snapshot, byref(me)):
                break
    _kernel32.CloseHandle(snapshot)
    return found


def find_qq_main_pid():
    pids = find_qq_pids()
    if not pids:
        return None
    print(f"QQ PIDs: {pids}")
    for pid in pids:
        if pid_has_module(pid, 'wrapper.node'):
            print(f"  PID {pid} has wrapper.node -> main process")
            return pid
    print(f"  WARNING: wrapper.node not found, trying first PID {pids[0]}")
    return pids[0]


def read_mem(handle, addr, size):
    buf = create_string_buffer(size)
    n = ctypes.c_size_t(0)
    if _kernel32.ReadProcessMemory(handle, ctypes.c_void_p(addr), buf, size, byref(n)):
        return buf.raw[:n.value]
    return None


def find_qq_message_db_directory(qq_number, input_pids):
    """Find an open nt_msg.db handle owned by a running QQ.exe process.

    SystemExtendedHandleInformation is a Windows Native API information class.
    The returned directory comes from GetFinalPathNameByHandleW; no fixed
    USERPROFILE/Documents path is assumed.
    """
    if not input_pids:
        raise RuntimeError("No QQ process IDs available for handle inspection.")

    ntdll = ctypes.WinDLL('ntdll')
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
        if returned_length.value > buffer_size:
            buffer_size = returned_length.value
        else:
            buffer_size *= 2
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

    kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel32.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
    kernel32.OpenProcess.restype = wt.HANDLE
    kernel32.DuplicateHandle.argtypes = [
        wt.HANDLE, wt.HANDLE, wt.HANDLE, ctypes.POINTER(wt.HANDLE),
        wt.DWORD, wt.BOOL, wt.DWORD,
    ]
    kernel32.DuplicateHandle.restype = wt.BOOL
    kernel32.GetCurrentProcess.argtypes = []
    kernel32.GetCurrentProcess.restype = wt.HANDLE
    kernel32.GetFileType.argtypes = [wt.HANDLE]
    kernel32.GetFileType.restype = wt.DWORD
    kernel32.GetFinalPathNameByHandleW.argtypes = [
        wt.HANDLE, wt.LPWSTR, wt.DWORD, wt.DWORD,
    ]
    kernel32.GetFinalPathNameByHandleW.restype = wt.DWORD
    kernel32.CloseHandle.argtypes = [wt.HANDLE]
    kernel32.CloseHandle.restype = wt.BOOL

    process_handles = {}
    for pid in set(int(p) for p in input_pids):
        process = kernel32.OpenProcess(PROCESS_DUP_HANDLE, False, pid)
        if process:
            process_handles[pid] = process
    if not process_handles:
        raise RuntimeError(
            "Cannot open any QQ process for handle inspection. "
            "Run with sufficient permissions."
        )

    found_paths = set()
    current_process = kernel32.GetCurrentProcess()
    try:
        for entry in entries:
            pid = int(entry.UniqueProcessId)
            source_process = process_handles.get(pid)
            if not source_process:
                continue

            duplicated = wt.HANDLE()
            source_handle = wt.HANDLE(int(entry.HandleValue))
            ok = kernel32.DuplicateHandle(
                source_process,
                source_handle,
                current_process,
                ctypes.byref(duplicated),
                0,
                False,
                DUPLICATE_SAME_ACCESS,
            )
            if not ok:
                continue  # The original handle may have closed after the snapshot.

            try:
                if kernel32.GetFileType(duplicated) != FILE_TYPE_DISK:
                    continue
                path_buffer = ctypes.create_unicode_buffer(32768)
                length = kernel32.GetFinalPathNameByHandleW(
                    duplicated,
                    path_buffer,
                    len(path_buffer),
                    FILE_NAME_NORMALIZED | VOLUME_NAME_DOS,
                )
                if length == 0 or length >= len(path_buffer):
                    continue
                path = path_buffer.value
                if os.path.basename(path).lower() == 'nt_msg.db':
                    found_paths.add(os.path.normpath(path))
            finally:
                kernel32.CloseHandle(duplicated)
    finally:
        for process in process_handles.values():
            kernel32.CloseHandle(process)

    if not found_paths:
        raise RuntimeError(
            "No open nt_msg.db file handle was found in QQ processes. "
            "Make sure the target QQ account is logged in and its message database is open."
        )

    def contains_account_component(path):
        parts = path.replace('/', '\\').split('\\')
        return any(part.lower() == str(qq_number).lower() for part in parts)

    account_matches = sorted(p for p in found_paths if contains_account_component(p))
    if len(account_matches) == 1:
        selected = account_matches[0]
    elif len(account_matches) > 1:
        raise RuntimeError(
            "Multiple nt_msg.db paths matched this QQ account:\n  " +
            "\n  ".join(account_matches)
        )
    elif len(found_paths) == 1:
        # Some NTQQ versions do not use the visible QQ number as the folder name.
        selected = next(iter(found_paths))
    else:
        raise RuntimeError(
            "Multiple nt_msg.db files are open, but none could be associated "
            f"with QQ account {qq_number}:\n  " + "\n  ".join(sorted(found_paths))
        )

    db_directory = os.path.dirname(selected)
    print(f"  Located nt_msg.db: {selected}")
    print(f"  Account DB directory: {db_directory}")
    return db_directory


def find_db_dirs(qq_number, account_db_dir=None, custom_db_dir=None):
    if custom_db_dir:
        if not os.path.isdir(custom_db_dir):
            raise RuntimeError(f"--db-dir path not found: {custom_db_dir}")
        return [(qq_number, custom_db_dir)]

    if not account_db_dir or not os.path.isdir(account_db_dir):
        raise RuntimeError("Account DB directory was not discovered from QQ process handles.")

    # Expected layout: <data_root>/<account>/nt_qq/nt_db.
    # Derive the shared root from the located nt_msg.db path.
    account_nt_qq_dir = os.path.dirname(account_db_dir)
    account_root = os.path.dirname(account_nt_qq_dir)
    data_root = os.path.dirname(account_root)
    global_dir = os.path.join(data_root, 'nt_qq', 'global', 'nt_db')

    candidates = []
    if os.path.isdir(global_dir):
        candidates.append(('global', global_dir))
    else:
        print(f"WARNING: Global DB directory not found: {global_dir}")
    candidates.append((qq_number, account_db_dir))
    return candidates

def collect_db_info(db_dirs):
    global_dbs = []
    pa_map = {}
    for account, d in db_dirs:
        for fn in os.listdir(d):
            if not fn.lower().endswith('.db'):
                continue
            fp = os.path.join(d, fn)
            try:
                with open(fp, 'rb') as f:
                    hdr = f.read(EXT_HEADER + PAGE_SIZE)
                if len(hdr) < EXT_HEADER + PAGE_SIZE:
                    continue
                if hdr[:16] != b'SQLite header 3\x00':
                    continue
                page1 = hdr[EXT_HEADER: EXT_HEADER + PAGE_SIZE]
                salt_hex = page1[:SALT_SIZE].hex()
                if account == 'global':
                    global_dbs.append((account, fp, page1))
                else:
                    pa_map.setdefault(salt_hex, []).append((account, fp, page1))
            except (OSError, PermissionError):
                continue
    return global_dbs, pa_map


# ── Crypto helpers ───────────────────────────────────────────────────────────

def verify_key_hmac(page1_data, enc_key_bytes):
    """Validate enc_key against page 1 HMAC-SHA1."""
    salt = page1_data[:SALT_SIZE]
    hmac_salt = bytes(b ^ HMAC_MASK for b in salt)
    hmac_key = hashlib.pbkdf2_hmac('sha512', enc_key_bytes, hmac_salt, FAST_ITER, KEY_SIZE)
    data_end = PAGE_SIZE - RESERVE            # 4048
    # Page 1 HMAC skips the 16-byte salt prefix
    content  = page1_data[SALT_SIZE:data_end]
    iv       = page1_data[data_end:data_end + IV_SIZE]
    stored   = page1_data[data_end + IV_SIZE:data_end + IV_SIZE + HMAC_SIZE]
    # Page number is little-endian (not big-endian as RE doc states)
    computed = hmac_mod.new(hmac_key, content + iv + struct.pack('<I', 1), hashlib.sha1).digest()
    return hmac_mod.compare_digest(computed, stored)


def derive_enc_key(passphrase, salt):
    return hashlib.pbkdf2_hmac('sha512', passphrase, salt, KDF_ITER, KEY_SIZE)


def derive_hmac_key(enc_key_bytes, salt):
    hmac_salt = bytes(b ^ HMAC_MASK for b in salt)
    return hashlib.pbkdf2_hmac('sha512', enc_key_bytes, hmac_salt, FAST_ITER, KEY_SIZE)


def decrypt_page(page_data, enc_key, skip_salt=0):
    """Decrypt a single SQLCipher page (AES-256-CBC)."""
    data = page_data[skip_salt:]
    encrypted = data[:len(data) - RESERVE]
    iv = data[len(data) - RESERVE:len(data) - RESERVE + IV_SIZE]
    cipher = Cipher(algorithms.AES(enc_key), modes.CBC(iv))
    dec = cipher.decryptor()
    return dec.update(encrypted) + dec.finalize()


def decrypt_db(input_path, output_path, enc_key_bytes):
    """Decrypt a full SQLCipher DB to a plain SQLite file."""
    with open(input_path, 'rb') as f:
        file_data = f.read()

    sc_data = file_data[EXT_HEADER:]
    if len(sc_data) < PAGE_SIZE:
        return False

    total_pages = len(sc_data) // PAGE_SIZE
    output = bytearray()

    for pgno in range(1, total_pages + 1):
        page_start = (pgno - 1) * PAGE_SIZE
        page_raw = sc_data[page_start:page_start + PAGE_SIZE]
        skip = SALT_SIZE if pgno == 1 else 0
        decrypted = decrypt_page(page_raw, enc_key_bytes, skip_salt=skip)

        if pgno == 1:
            hdr = bytearray(b'SQLite format 3\x00')
            full = bytearray(hdr + decrypted)
            full[16:18] = struct.pack('>H', PAGE_SIZE)
            full[20] = 0  # no reserved space in output
            full = bytes(full[:PAGE_SIZE])
            if len(full) < PAGE_SIZE:
                full += b'\x00' * (PAGE_SIZE - len(full))
            output.extend(full)
        else:
            output.extend(decrypted)
            pad = PAGE_SIZE - len(decrypted)
            if pad > 0:
                output.extend(b'\x00' * pad)

    with open(output_path, 'wb') as f:
        f.write(output)

    # Quick validation
    try:
        conn = sqlite3.connect(output_path)
        cur = conn.cursor()
        cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = [r[0] for r in cur.fetchall()]
        conn.close()
        return len(tables) > 0
    except Exception:
        return False


# ── Memory scanner ───────────────────────────────────────────────────────────

HEX_CHARS = set(b'0123456789abcdefABCDEF')


def scan_by_salt(handle, salt_hexes):
    """Targeted scan: search memory for known salt hex strings, extract keys.

    Pattern in memory: x'<64hex_key><32hex_salt>'
    We search for the 32-char salt hex (ASCII) via bytes.find() (C-fast),
    then back up 66 bytes to verify x' prefix + 64 hex key chars.
    """
    # Pre-compute salt needles as ASCII bytes
    needles = [(sh.encode('ascii'), sh) for sh in salt_hexes]
    results = {}  # salt_hex -> (addr, key_hex)
    total = 0
    t0 = time.time()
    mbi = MEMORY_BASIC_INFORMATION()
    addr = 0
    while True:
        ret = _kernel32.VirtualQueryEx(handle, ctypes.c_void_p(addr), byref(mbi), sizeof(mbi))
        if ret == 0:
            break
        base = mbi.BaseAddress or 0
        size = mbi.RegionSize
        if (mbi.State == MEM_COMMIT and
                (mbi.Protect & 0xFF) in READABLE_PROTS and
                0 < size <= MAX_REGION):
            data = read_mem(handle, base, size)
            if data:
                total += len(data)
                for needle, sh in needles:
                    if sh in results:
                        continue
                    off = 0
                    while True:
                        idx = data.find(needle, off)
                        if idx == -1:
                            break
                        # Verify: x'<64hex_key><32hex_salt>'
                        # salt starts at idx, key starts at idx-64, x' at idx-66
                        if idx >= 66 and idx + 33 <= len(data):
                            if (data[idx - 66:idx - 64] == b"x'" and
                                    data[idx + 32:idx + 33] == b"'" and
                                    all(c in HEX_CHARS for c in data[idx - 64:idx])):
                                key_hex = data[idx - 64:idx].decode('ascii').lower()
                                hit_addr = base + idx - 66
                                results[sh] = (hit_addr, key_hex)
                                break
                        off = idx + 1
        nxt = base + size
        if nxt <= addr or nxt >= 0x7FFFFFFFFFFF:
            break
        addr = nxt
    elapsed = time.time() - t0
    print(f"  Scanned {total / 1048576:.0f} MB in {elapsed:.1f}s -> {len(results)}/{len(salt_hexes)} salts matched")
    return results


# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(description="Dump NTQQ database keys from QQ memory")
    ap.add_argument('--qq', required=True, help='QQ number (account directory name)')
    ap.add_argument('--pid', type=int, default=0, help='QQ.exe PID (auto-detect)')
    ap.add_argument('-o', '--output', default='key_map.json', help='Output JSON')
    ap.add_argument('--db-dir', default='', help='Manually specify the database directory')
    args = ap.parse_args()

    # 1. Find QQ main process
    if args.pid:
        main_pid = args.pid
        print(f"Using PID: {main_pid}")
    else:
        main_pid = find_qq_main_pid()
        if not main_pid:
            print("ERROR: No QQ.exe found. Start QQ or use --pid.")
            sys.exit(1)

    # 2. Discover DB location from a live QQ file handle (unless explicitly overridden).
    account_db_dir = None
    if not args.db_dir:
        qq_pids = find_qq_pids()
        if args.pid and args.pid not in qq_pids:
            qq_pids.append(args.pid)
        try:
            account_db_dir = find_qq_message_db_directory(args.qq, qq_pids)
        except RuntimeError as exc:
            print(f"ERROR: {exc}")
            sys.exit(1)

    # 3. Discover DB files from the located directories.
    try:
        db_dirs = find_db_dirs(args.qq, account_db_dir, args.db_dir)
    except RuntimeError as exc:
        print(f"ERROR: {exc}")
        sys.exit(1)
    global_dbs, pa_salt_map = collect_db_info(db_dirs)
    print(f"\nGlobal DBs: {len(global_dbs)}  (fixed key, no scan)")
    print(f"Per-account: {sum(len(v) for v in pa_salt_map.values())} files, "
          f"{len(pa_salt_map)} unique salts")

    if not pa_salt_map and not global_dbs:
        print("ERROR: No NTQQ databases found.")
        sys.exit(1)

    # 3. Global DBs: fixed PRE_LOGIN_KEY
    global_results = {}
    for account, fp, page1 in global_dbs:
        salt = page1[:SALT_SIZE]
        enc_key = derive_enc_key(PRE_LOGIN_KEY, salt)
        fn = os.path.basename(fp)
        if verify_key_hmac(page1, enc_key):
            global_results[salt.hex()] = enc_key.hex()
            print(f"  [global] {fn}: OK")
        else:
            print(f"  [global] {fn}: HMAC mismatch")

    # 4. Per-account DBs: memory scan
    results = {}
    if pa_salt_map:
        handle = _kernel32.OpenProcess(
            PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, main_pid)
        if not handle:
            print(f"Cannot open PID {main_pid} (err {ctypes.GetLastError()})")
            sys.exit(1)

        # Targeted salt search: find known salt hex strings in memory
        print(f"\n-- Scanning PID {main_pid} for {len(pa_salt_map)} known salts --")
        scan_hits = scan_by_salt(handle, list(pa_salt_map.keys()))

        for salt_hex, (addr, key_hex) in scan_hits.items():
            enc_key = bytes.fromhex(key_hex)
            page1 = pa_salt_map[salt_hex][0][2]
            if verify_key_hmac(page1, enc_key):
                results[salt_hex] = key_hex
                fn = os.path.basename(pa_salt_map[salt_hex][0][1])
                print(f"  [hit] {fn}: key={key_hex[:16]}.. @ 0x{addr:X}")

        _kernel32.CloseHandle(handle)

    # 5. Output
    all_results = {**global_results, **results}
    total_salts = len(set(p[2][:SALT_SIZE].hex() for p in global_dbs)) + len(pa_salt_map)

    print(f"\n{'=' * 72}")
    print(f"RESULTS: {len(all_results)}/{total_salts} database keys recovered")
    print(f"{'=' * 72}")

    for sh, kh in sorted(global_results.items()):
        names = ', '.join(os.path.basename(e[1]) for e in global_dbs if e[2][:SALT_SIZE].hex() == sh)
        print(f"  [global] {sh} -> {kh[:32]}..  ({names})")
    for sh, kh in sorted(results.items()):
        names = ', '.join(os.path.basename(e[1]) for e in pa_salt_map.get(sh, []))
        print(f"  [acct]   {sh} -> {kh[:32]}..  ({names})")

    unresolved = [sh for sh in pa_salt_map if sh not in results]
    if unresolved:
        print(f"\nUnresolved ({len(unresolved)}):")
        for sh in unresolved:
            names = ', '.join(os.path.basename(e[1]) for e in pa_salt_map[sh])
            print(f"  {sh}  ({names})")

    if all_results:
        with open(args.output, 'w') as f:
            json.dump({'key_map': all_results, '_generated': time.strftime('%Y-%m-%d %H:%M:%S')}, f, indent=2)
        print(f"\nSaved to {args.output}")

    # 6. Decrypt all recovered DBs to output folder
    out_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'output', args.qq)
    os.makedirs(out_dir, exist_ok=True)
    print(f"\n-- Decrypting to {out_dir} --")
    ok_count = 0
    fail_count = 0

    # Build unified file list: (source_path, salt_hex, enc_key_bytes)
    decrypt_jobs = []
    for account, fp, page1 in global_dbs:
        sh = page1[:SALT_SIZE].hex()
        if sh in global_results:
            decrypt_jobs.append((fp, bytes.fromhex(global_results[sh])))
    for sh, kh in results.items():
        for account, fp, page1 in pa_salt_map[sh]:
            decrypt_jobs.append((fp, bytes.fromhex(kh)))

    for src_path, enc_key in decrypt_jobs:
        fn = os.path.basename(src_path)
        dst_path = os.path.join(out_dir, fn)
        ok = decrypt_db(src_path, dst_path, enc_key)
        if ok:
            sz = os.path.getsize(dst_path) / 1024
            print(f"  OK  {fn} ({sz:.0f} KB)")
            ok_count += 1
        else:
            print(f"  FAIL {fn}")
            fail_count += 1

    print(f"\nDecrypted: {ok_count} OK, {fail_count} failed -> {out_dir}")


if __name__ == '__main__':
    main()
