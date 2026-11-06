#pragma once
#include "qq_dump_db/common.hpp"
namespace qq_dump_db {
bool find_qq_instance_mappings(
    const std::vector<DWORD>& input_pids,
    const std::vector<DWORD>& input_wrapper_pids,
    std::vector<QqInstanceMapping>& mappings);
}
