"""Win32 constants, structures, and lazily initialized API handles."""
import ctypes
import ctypes.wintypes as wt
import os
from functools import lru_cache

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
SCAN_CHUNK_SIZE           = 4 * 1024 * 1024
KEY_BLOB_SIZE              = 99
SCAN_OVERLAP               = KEY_BLOB_SIZE - 1
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


def _require_windows():
    if os.name != "nt":
        raise OSError("This operation requires Windows.")


@lru_cache(maxsize=1)
def get_kernel32():
    """Return kernel32 with pointer-safe ctypes signatures configured."""
    _require_windows()
    dll = ctypes.WinDLL("kernel32", use_last_error=True)
    dll.CreateToolhelp32Snapshot.argtypes = [wt.DWORD, wt.DWORD]
    dll.CreateToolhelp32Snapshot.restype = wt.HANDLE
    dll.Process32First.argtypes = [wt.HANDLE, ctypes.POINTER(PROCESSENTRY32)]
    dll.Process32First.restype = wt.BOOL
    dll.Process32Next.argtypes = [wt.HANDLE, ctypes.POINTER(PROCESSENTRY32)]
    dll.Process32Next.restype = wt.BOOL
    dll.Module32First.argtypes = [wt.HANDLE, ctypes.POINTER(MODULEENTRY32)]
    dll.Module32First.restype = wt.BOOL
    dll.Module32Next.argtypes = [wt.HANDLE, ctypes.POINTER(MODULEENTRY32)]
    dll.Module32Next.restype = wt.BOOL
    dll.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
    dll.OpenProcess.restype = wt.HANDLE
    dll.CloseHandle.argtypes = [wt.HANDLE]
    dll.CloseHandle.restype = wt.BOOL
    dll.ReadProcessMemory.argtypes = [
        wt.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t,
        ctypes.POINTER(ctypes.c_size_t),
    ]
    dll.ReadProcessMemory.restype = wt.BOOL
    dll.VirtualQueryEx.argtypes = [
        wt.HANDLE, ctypes.c_void_p, ctypes.POINTER(MEMORY_BASIC_INFORMATION),
        ctypes.c_size_t,
    ]
    dll.VirtualQueryEx.restype = ctypes.c_size_t
    dll.DuplicateHandle.argtypes = [
        wt.HANDLE, wt.HANDLE, wt.HANDLE, ctypes.POINTER(wt.HANDLE),
        wt.DWORD, wt.BOOL, wt.DWORD,
    ]
    dll.DuplicateHandle.restype = wt.BOOL
    dll.GetCurrentProcess.argtypes = []
    dll.GetCurrentProcess.restype = wt.HANDLE
    dll.GetFileType.argtypes = [wt.HANDLE]
    dll.GetFileType.restype = wt.DWORD
    dll.GetFinalPathNameByHandleW.argtypes = [wt.HANDLE, wt.LPWSTR, wt.DWORD, wt.DWORD]
    dll.GetFinalPathNameByHandleW.restype = wt.DWORD
    return dll


@lru_cache(maxsize=1)
def get_ntdll():
    _require_windows()
    return ctypes.WinDLL("ntdll", use_last_error=True)
