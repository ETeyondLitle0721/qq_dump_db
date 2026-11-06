"""Windows process enumeration helpers."""
import ctypes
from ctypes import byref, sizeof
from ...i18n import tr
from .api import (
    TH32CS_SNAPPROCESS, TH32CS_SNAPMODULE, TH32CS_SNAPMODULE32,
    PROCESSENTRY32, MODULEENTRY32, get_kernel32,
)

def find_qq_pids():
    kernel32 = get_kernel32()
    snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snapshot in (ctypes.c_void_p(-1).value, -1):
        return []
    pe = PROCESSENTRY32()
    pe.dwSize = sizeof(PROCESSENTRY32)
    pids = []
    if kernel32.Process32First(snapshot, byref(pe)):
        while True:
            name = pe.szExeFile.decode('utf-8', errors='replace').lower()
            if name == 'qq.exe':
                pids.append(pe.th32ProcessID)
            if not kernel32.Process32Next(snapshot, byref(pe)):
                break
    kernel32.CloseHandle(snapshot)
    return pids


def pid_has_module(pid, module_name):
    kernel32 = get_kernel32()
    snapshot = kernel32.CreateToolhelp32Snapshot(
        TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid)
    if snapshot in (ctypes.c_void_p(-1).value, -1, 0):
        return False
    me = MODULEENTRY32()
    me.dwSize = sizeof(MODULEENTRY32)
    found = False
    if kernel32.Module32First(snapshot, byref(me)):
        while True:
            mod = me.szModule.decode('utf-8', errors='replace').lower()
            if mod == module_name.lower():
                found = True
                break
            if not kernel32.Module32Next(snapshot, byref(me)):
                break
    kernel32.CloseHandle(snapshot)
    return found


def find_qq_wrapper_pids(pids=None):
    if pids is None:
        pids = find_qq_pids()
    print(tr("process.qq_pids", pids=pids))
    wrapper_pids = []
    for pid in pids:
        if pid_has_module(pid, 'wrapper.node'):
            wrapper_pids.append(pid)
            print(tr("process.wrapper_found", pid=pid))
    return wrapper_pids


def find_qq_process_parent_map():
    """Return {QQ.exe PID: parent PID} from one Toolhelp process snapshot."""
    kernel32 = get_kernel32()
    snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snapshot in (ctypes.c_void_p(-1).value, -1):
        return {}
    pe = PROCESSENTRY32()
    pe.dwSize = sizeof(PROCESSENTRY32)
    parents = {}
    if kernel32.Process32First(snapshot, byref(pe)):
        while True:
            name = pe.szExeFile.decode('utf-8', errors='replace').lower()
            if name == 'qq.exe':
                parents[int(pe.th32ProcessID)] = int(pe.th32ParentProcessID)
            if not kernel32.Process32Next(snapshot, byref(pe)):
                break
    kernel32.CloseHandle(snapshot)
    return parents

