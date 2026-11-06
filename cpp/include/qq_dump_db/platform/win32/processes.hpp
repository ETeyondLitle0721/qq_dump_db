#pragma once
#include "qq_dump_db/common.hpp"
namespace qq_dump_db {
std::vector<DWORD> find_qq_pids();
bool pid_has_module(DWORD pid, const wchar_t* module_name);
std::vector<DWORD> find_qq_wrapper_pids(const std::vector<DWORD>& pids);
std::map<DWORD, DWORD> get_qq_parent_map();
bool is_process_alive(DWORD pid);
}
