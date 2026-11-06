"""Read-only process-memory candidate scanner."""
import ctypes
import re
import time
from ctypes import byref, sizeof, create_string_buffer
from ...i18n import tr
from .api import (
    MEMORY_BASIC_INFORMATION, MEM_COMMIT, SCAN_CHUNK_SIZE, SCAN_OVERLAP,
    get_kernel32,
)

KEY_BLOB_RE = re.compile(rb"[xX]([\"'])([0-9a-fA-F]{64})([0-9a-fA-F]{32})\1")

def read_mem(handle, addr, size):
    buf = create_string_buffer(size)
    n = ctypes.c_size_t(0)
    get_kernel32().ReadProcessMemory(
        handle, ctypes.c_void_p(addr), buf, size, byref(n))
    return buf.raw[:n.value] if n.value else None


def scan_by_salt(handle, pid, salt_hexes):
    """Find every distinct key blob matching a known database salt.

    Memory is read in 4 MiB chunks. A 98-byte overlap preserves a complete
    99-byte x'<key><salt>' candidate split across adjacent chunks.
    Returns {salt_hex: [(pid, address, key_hex), ...]}.
    """
    wanted_salts = {sh.lower() for sh in salt_hexes}
    results = {}
    total = 0
    t0 = time.time()
    mbi = MEMORY_BASIC_INFORMATION()
    addr = 0

    while True:
        ret = get_kernel32().VirtualQueryEx(
            handle, ctypes.c_void_p(addr), byref(mbi), sizeof(mbi))
        if ret == 0:
            break

        base = mbi.BaseAddress or 0
        size = mbi.RegionSize
        protection = int(mbi.Protect)
        base_protection = protection & 0xFF
        readable_candidate = (
            mbi.State == MEM_COMMIT and
            base_protection != 0x01 and  # PAGE_NOACCESS
            not (protection & 0x100)    # PAGE_GUARD
        )

        if readable_candidate and size > 0:
            carry = b''
            region_offset = 0
            while region_offset < size:
                request = min(SCAN_CHUNK_SIZE, size - region_offset)
                chunk = read_mem(handle, base + region_offset, request)
                if not chunk:
                    region_offset += request
                    carry = b''
                    continue

                total += len(chunk)
                window = carry + chunk
                window_address = base + region_offset - len(carry)
                for match in KEY_BLOB_RE.finditer(window):
                    salt_hex = match.group(3).decode('ascii').lower()
                    if salt_hex not in wanted_salts:
                        continue
                    key_hex = match.group(2).decode('ascii').lower()
                    candidates = results.setdefault(salt_hex, [])
                    if not any(existing[2] == key_hex for existing in candidates):
                        candidates.append((pid, window_address + match.start(), key_hex))

                keep = min(SCAN_OVERLAP, len(window))
                carry = window[-keep:] if keep else b''
                region_offset += len(chunk)
                if len(chunk) < request:
                    # A short read leaves a gap; do not bridge it with carry.
                    region_offset += request - len(chunk)
                    carry = b''

        nxt = base + size
        if nxt <= addr or nxt >= 0x7FFFFFFFFFFF:
            break
        addr = nxt

    candidate_count = sum(len(items) for items in results.values())
    elapsed = time.time() - t0
    print(tr("scan.summary", pid=pid, mb=total / 1048576, elapsed=elapsed,
             found=len(results), total=len(wanted_salts), candidates=candidate_count))
    return results

