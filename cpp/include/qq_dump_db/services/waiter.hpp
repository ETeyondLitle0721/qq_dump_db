#pragma once
#include "qq_dump_db/common.hpp"
namespace qq_dump_db {
void wait_for_qq_exit(const std::vector<DWORD>& target_pids, bool no_wait);
}
