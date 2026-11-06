#pragma once
#include "qq_dump_db/common.hpp"
namespace qq_dump_db {
bool write_key_map(const std::map<std::string, std::string>& key_map,
                   const fs::path& output_path, std::string& error_message);
}
