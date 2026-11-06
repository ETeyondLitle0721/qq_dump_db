#pragma once
#include "qq_dump_db/common.hpp"
namespace qq_dump_db {
bool parse_qq_account_from_db_path(const fs::path& db_path, std::string& account);
DWORD resolve_wrapper_pid_for_handle_owner(
    DWORD owner_pid, const std::set<DWORD>& wrapper_pids,
    const std::map<DWORD, DWORD>& parent_map);
bool select_qq_instance(const std::string& qq_number,
    const std::vector<QqInstanceMapping>& mappings, fs::path& db_directory,
    std::vector<DWORD>& matched_wrapper_pids);
}
