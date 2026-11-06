#include "qq_dump_db/platform/win32/handles.hpp"
#include "qq_dump_db/platform/win32/processes.hpp"
#include "qq_dump_db/discovery/qq_instances.hpp"
#include "qq_dump_db/utils/hex.hpp"
#include "qq_dump_db/i18n/catalog.hpp"

namespace qq_dump_db {
// SystemExtendedHandleInformation (SystemInformationClass = 64) is a
// Windows Native API information class. Keep the declarations local so the
// code builds with the regular Windows SDK without depending on private SDK
// headers.
using NtQuerySystemInformationFn = LONG (NTAPI*)(
    ULONG, PVOID, ULONG, PULONG);

struct SystemHandleEntryExLocal {
    PVOID       Object;
    ULONG_PTR   UniqueProcessId;
    ULONG_PTR   HandleValue;
    ULONG       GrantedAccess;
    USHORT      CreatorBackTraceIndex;
    USHORT      ObjectTypeIndex;
    ULONG       HandleAttributes;
    ULONG       Reserved;
};

struct SystemHandleInformationExLocal {
    ULONG_PTR NumberOfHandles;
    ULONG_PTR Reserved;
    SystemHandleEntryExLocal Handles[1];
};

static bool get_final_path_from_handle(HANDLE file_handle, fs::path& result)
{
    constexpr DWORD flags = FILE_NAME_NORMALIZED | VOLUME_NAME_DOS;
    DWORD capacity = 512;

    while (capacity <= 32768) {
        std::vector<wchar_t> buffer(capacity, L'\0');
        DWORD length = GetFinalPathNameByHandleW(
            file_handle, buffer.data(), capacity, flags);
        if (length == 0)
            return false;
        if (length < capacity) {
            result = fs::path(std::wstring(buffer.data(), length));
            return true;
        }
        if (length >= 32768)
            break;
        capacity = length + 1;
    }
    return false;
}

 bool find_qq_instance_mappings(
    const std::vector<DWORD>& input_pids,
    const std::vector<DWORD>& input_wrapper_pids,
    std::vector<QqInstanceMapping>& mappings)
{
    mappings.clear();
    if (input_pids.empty()) {
        std::cerr << tr("handle.no_pids") << "\n";
        return false;
    }

    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    auto query_system_information = ntdll
        ? reinterpret_cast<NtQuerySystemInformationFn>(
              GetProcAddress(ntdll, "NtQuerySystemInformation"))
        : nullptr;
    if (!query_system_information) {
        std::cerr << tr("handle.ntdll") << "\n";
        return false;
    }

    constexpr ULONG SYSTEM_EXTENDED_HANDLE_INFORMATION = 64;
    constexpr LONG STATUS_INFO_LENGTH_MISMATCH_VALUE =
        static_cast<LONG>(0xC0000004L);
    constexpr LONG STATUS_BUFFER_TOO_SMALL_VALUE =
        static_cast<LONG>(0xC0000023L);

    std::vector<uint8_t> handle_buffer;
    ULONG buffer_size = 1u * 1024u * 1024u;
    bool queried = false;
    for (int attempt = 0; attempt < 12; ++attempt) {
        handle_buffer.resize(buffer_size);
        ULONG returned_length = 0;
        LONG status = query_system_information(
            SYSTEM_EXTENDED_HANDLE_INFORMATION,
            handle_buffer.data(), buffer_size, &returned_length);
        if (status >= 0) {
            queried = true;
            break;
        }
        if (status != STATUS_INFO_LENGTH_MISMATCH_VALUE &&
            status != STATUS_BUFFER_TOO_SMALL_VALUE) {
            std::cerr << tr("handle.ntquery_failed") << "0x"
                      << std::hex << static_cast<uint32_t>(status) << std::dec << "\n";
            return false;
        }
        if (returned_length > buffer_size) {
            buffer_size = returned_length;
        } else {
            if (buffer_size > std::numeric_limits<ULONG>::max() / 2) {
                std::cerr << tr("handle.too_large") << "\n";
                return false;
            }
            buffer_size *= 2;
        }
    }
    if (!queried) {
        std::cerr << tr("handle.alloc_failed") << "\n";
        return false;
    }

    const size_t handles_offset =
        offsetof(SystemHandleInformationExLocal, Handles);
    if (handle_buffer.size() < handles_offset) {
        std::cerr << tr("handle.invalid") << "\n";
        return false;
    }

    const auto* handle_info = reinterpret_cast<
        const SystemHandleInformationExLocal*>(handle_buffer.data());
    const size_t max_entries =
        (handle_buffer.size() - handles_offset) /
        sizeof(SystemHandleEntryExLocal);
    const size_t handle_count = static_cast<size_t>(
        std::min<ULONG_PTR>(handle_info->NumberOfHandles, max_entries));

    std::set<DWORD> qq_pid_set(input_pids.begin(), input_pids.end());
    std::map<DWORD, HANDLE> process_handles;
    for (DWORD pid : qq_pid_set) {
        HANDLE process = OpenProcess(PROCESS_DUP_HANDLE, FALSE, pid);
        if (process)
            process_handles.emplace(pid, process);
    }
    if (process_handles.empty()) {
        std::cerr << tr("handle.cannot_open") << "\n";
        return false;
    }

    const std::set<DWORD> wrapper_set(
        input_wrapper_pids.begin(), input_wrapper_pids.end());
    const auto parent_map = get_qq_parent_map();
    const HANDLE current_process = GetCurrentProcess();

    // Keep PID + path together. A path-only set loses the crucial ownership
    // information needed to map a QQ instance to its account.
    std::set<std::pair<DWORD, fs::path>> found_handles;
    for (size_t i = 0; i < handle_count; ++i) {
        const auto& entry = handle_info->Handles[i];
        if (entry.UniqueProcessId > std::numeric_limits<DWORD>::max())
            continue;
        const DWORD owner_pid = static_cast<DWORD>(entry.UniqueProcessId);
        const auto process_it = process_handles.find(owner_pid);
        if (process_it == process_handles.end())
            continue;

        HANDLE duplicated = nullptr;
        const HANDLE source = reinterpret_cast<HANDLE>(entry.HandleValue);
        if (!DuplicateHandle(process_it->second, source, current_process,
                             &duplicated, 0, FALSE, DUPLICATE_SAME_ACCESS))
            continue;

        if (GetFileType(duplicated) == FILE_TYPE_DISK) {
            fs::path file_path;
            std::string account;
            if (get_final_path_from_handle(duplicated, file_path) &&
                parse_qq_account_from_db_path(file_path, account)) {
                found_handles.emplace(owner_pid, std::move(file_path));
            }
        }
        CloseHandle(duplicated);
    }

    for (auto& [pid, process] : process_handles) {
        (void)pid;
        CloseHandle(process);
    }

    for (const auto& [owner_pid, path] : found_handles) {
        std::string account;
        if (!parse_qq_account_from_db_path(path, account))
            continue;
        const DWORD wrapper_pid = resolve_wrapper_pid_for_handle_owner(
            owner_pid, wrapper_set, parent_map);
        mappings.push_back({account, wrapper_pid, owner_pid, path});
    }

    if (mappings.empty()) {
        std::cerr << tr("handle.none") << "\n";
        return false;
    }

    // De-duplicate repeated handle observations while retaining ownership.
    std::sort(mappings.begin(), mappings.end(),
              [](const QqInstanceMapping& a, const QqInstanceMapping& b) {
                  if (a.account != b.account) return a.account < b.account;
                  if (a.db_path != b.db_path) return a.db_path < b.db_path;
                  if (a.wrapper_pid != b.wrapper_pid) return a.wrapper_pid < b.wrapper_pid;
                  return a.handle_pid < b.handle_pid;
              });
    mappings.erase(std::unique(mappings.begin(), mappings.end(),
        [](const QqInstanceMapping& a, const QqInstanceMapping& b) {
            return a.account == b.account && a.db_path == b.db_path &&
                   a.wrapper_pid == b.wrapper_pid && a.handle_pid == b.handle_pid;
        }), mappings.end());

    std::cout << tr("mapping.header") << "\n";
    for (const auto& mapping : mappings) {
        if (mapping.wrapper_pid) {
            std::cout << tr("mapping.line_pid") << mapping.wrapper_pid << tr("mapping.to_qq")
                      << mapping.account << tr("mapping.owner") << mapping.handle_pid
                      << tr("mapping.owner_end") << "\n";
        } else {
            std::cout << tr("mapping.unmatched") << mapping.account
                      << tr("mapping.unmatched_end") << mapping.handle_pid
                      << tr("mapping.no_wrapper") << "\n";
        }
    }
    return true;
}

} // namespace qq_dump_db
