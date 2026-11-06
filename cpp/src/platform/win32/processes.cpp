#include "qq_dump_db/platform/win32/processes.hpp"
#include "qq_dump_db/i18n/catalog.hpp"
#include <cwctype>

namespace qq_dump_db {
 std::vector<DWORD> find_qq_pids()
{
    std::vector<DWORD> pids;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return pids;

    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);
    if (Process32FirstW(snap, &pe)) {
        do {
            std::wstring name(pe.szExeFile);
            std::transform(name.begin(), name.end(), name.begin(), ::towlower);
            if (name == L"qq.exe")
                pids.push_back(pe.th32ProcessID);
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return pids;
}

 bool pid_has_module(DWORD pid, const wchar_t* module_name)
{
    HANDLE snap = CreateToolhelp32Snapshot(
        TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snap == INVALID_HANDLE_VALUE) return false;

    std::wstring target(module_name);
    std::transform(target.begin(), target.end(), target.begin(), ::towlower);

    MODULEENTRY32W me{};
    me.dwSize = sizeof(me);
    bool found = false;
    if (Module32FirstW(snap, &me)) {
        do {
            std::wstring mod(me.szModule);
            std::transform(mod.begin(), mod.end(), mod.begin(), ::towlower);
            if (mod == target) { found = true; break; }
        } while (Module32NextW(snap, &me));
    }
    CloseHandle(snap);
    return found;
}

 std::vector<DWORD> find_qq_wrapper_pids(const std::vector<DWORD>& pids)
{
    std::vector<DWORD> wrapper_pids;

    std::cout << tr("process.pids");
    for (DWORD pid : pids) std::cout << " " << pid;
    std::cout << "\n";

    for (DWORD pid : pids) {
        if (pid_has_module(pid, L"wrapper.node")) {
            wrapper_pids.push_back(pid);
            std::cout << "  PID " << pid << " " << tr("process.wrapper") << "\n";
        }
    }
    return wrapper_pids;
}

 std::map<DWORD, DWORD> get_qq_parent_map()
{
    std::map<DWORD, DWORD> parents;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return parents;

    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);
    if (Process32FirstW(snap, &pe)) {
        do {
            std::wstring name(pe.szExeFile);
            std::transform(name.begin(), name.end(), name.begin(), ::towlower);
            if (name == L"qq.exe")
                parents[pe.th32ProcessID] = pe.th32ParentProcessID;
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return parents;
}

 bool is_process_alive(DWORD pid)
{
    HANDLE h = OpenProcess(SYNCHRONIZE, FALSE, pid);
    if (!h) return false;
    DWORD ret = WaitForSingleObject(h, 0);
    CloseHandle(h);
    return ret == WAIT_TIMEOUT;   // still running
}

} // namespace qq_dump_db
