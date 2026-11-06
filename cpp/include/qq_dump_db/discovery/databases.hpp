#pragma once
#include "qq_dump_db/common.hpp"
namespace qq_dump_db {
DbCollection find_and_collect_dbs(
    const std::string& qq_number,
    const fs::path& custom_db_dir = {},
    const fs::path& discovered_account_db_dir = {});
}
