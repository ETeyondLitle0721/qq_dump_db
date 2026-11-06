#include "qq_dump_db/discovery/qq_instances.hpp"
#include "qq_dump_db/utils/hex.hpp"
#include "qq_dump_db/i18n/catalog.hpp"
#include <cwctype>

namespace qq_dump_db {
static bool equals_ignore_case(const std::wstring& a, const wchar_t* b)
{
    const std::wstring rhs(b ? b : L"");
    if (a.size() != rhs.size()) return false;
    for (size_t i = 0; i < a.size(); ++i)
        if (std::towlower(a[i]) != std::towlower(rhs[i])) return false;
    return true;
}

 bool parse_qq_account_from_db_path(const fs::path& db_path,
                                          std::string& account)
{
    // Expected NTQQ layout:
    // <data root>\\Tencent Files\\<QQ number>\\nt_qq\\nt_db\\nt_msg.db
    if (!equals_ignore_case(db_path.filename().wstring(), L"nt_msg.db"))
        return false;

    const fs::path db_dir = db_path.parent_path();
    const fs::path nt_qq_dir = db_dir.parent_path();
    const fs::path account_dir = nt_qq_dir.parent_path();
    const fs::path tencent_files_dir = account_dir.parent_path();

    if (!equals_ignore_case(db_dir.filename().wstring(), L"nt_db") ||
        !equals_ignore_case(nt_qq_dir.filename().wstring(), L"nt_qq") ||
        !equals_ignore_case(tencent_files_dir.filename().wstring(), L"Tencent Files"))
        return false;

    const std::wstring account_w = account_dir.filename().wstring();
    if (account_w.empty() || account_w == L"." || account_w == L"..")
        return false;

    // QQ account directory names are normally decimal. Reject unexpected
    // path components rather than accidentally treating a directory as an ID.
    if (!std::all_of(account_w.begin(), account_w.end(),
                     [](wchar_t c) { return c >= L'0' && c <= L'9'; }))
        return false;

    account.clear();
    account.reserve(account_w.size());
    for (wchar_t c : account_w)
        account.push_back(static_cast<char>(c));
    return true;
}

 DWORD resolve_wrapper_pid_for_handle_owner(
    DWORD owner_pid,
    const std::set<DWORD>& wrapper_pids,
    const std::map<DWORD, DWORD>& parent_map)
{
    if (wrapper_pids.find(owner_pid) != wrapper_pids.end())
        return owner_pid;

    // First, walk upward: a QQ helper process may inherit its instance from
    // a wrapper.node-bearing QQ parent.
    std::set<DWORD> visited;
    DWORD current = owner_pid;
    while (visited.insert(current).second) {
        const auto it = parent_map.find(current);
        if (it == parent_map.end() || it->second == 0)
            break;
        current = it->second;
        if (wrapper_pids.find(current) != wrapper_pids.end())
            return current;
    }

    // Then walk upward from wrapper processes to see whether the handle owner
    // is their QQ.exe ancestor. Only accept exactly one descendant wrapper;
    // choosing the "nearest" of several clients could silently mis-map an ID.
    DWORD matched_pid = 0;
    for (DWORD candidate : wrapper_pids) {
        std::set<DWORD> candidate_visited;
        DWORD node = candidate;
        while (candidate_visited.insert(node).second) {
            const auto it = parent_map.find(node);
            if (it == parent_map.end() || it->second == 0)
                break;
            node = it->second;
            if (node == owner_pid) {
                if (matched_pid != 0 && matched_pid != candidate)
                    return 0;
                matched_pid = candidate;
                break;
            }
        }
    }
    return matched_pid;
}

 bool select_qq_instance(
    const std::string& qq_number,
    const std::vector<QqInstanceMapping>& mappings,
    fs::path& db_directory,
    std::vector<DWORD>& matched_wrapper_pids)
{
    std::vector<fs::path> account_paths;
    for (const auto& mapping : mappings) {
        if (mapping.account == qq_number)
            account_paths.push_back(mapping.db_path);
    }
    std::sort(account_paths.begin(), account_paths.end());
    account_paths.erase(std::unique(account_paths.begin(), account_paths.end()),
                        account_paths.end());

    if (account_paths.empty()) {
        std::cerr << tr("mapping.not_found") << qq_number << ".\n";
        return false;
    }
    if (account_paths.size() != 1) {
        std::cerr << tr("mapping.multiple") << "\n";
        for (const auto& path : account_paths)
            std::cerr << "  " << path_to_utf8(path) << "\n";
        return false;
    }

    db_directory = account_paths.front().parent_path();
    std::set<DWORD> unique_pids;
    for (const auto& mapping : mappings) {
        if (mapping.account == qq_number && mapping.db_path == account_paths.front() &&
            mapping.wrapper_pid != 0)
            unique_pids.insert(mapping.wrapper_pid);
    }
    matched_wrapper_pids.assign(unique_pids.begin(), unique_pids.end());

    std::cout << tr("mapping.select") << qq_number << tr("mapping.database_label")
              << path_to_utf8(account_paths.front()) << "\n";
    if (matched_wrapper_pids.empty()) {
        std::cout << tr("warning.prefix") << tr("mapping.no_wrapper_match") << "\n";
    } else {
        std::cout << tr("mapping.pids");
        for (DWORD pid : matched_wrapper_pids)
            std::cout << " " << pid;
        std::cout << "\n";
    }
    return true;
}

} // namespace qq_dump_db
