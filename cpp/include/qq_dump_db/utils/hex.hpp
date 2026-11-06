#pragma once
#include "qq_dump_db/common.hpp"
namespace qq_dump_db {
std::string to_hex(const uint8_t* data, size_t len);
std::vector<uint8_t> from_hex(const std::string& hex);
bool is_hex_char(uint8_t c);
std::string path_to_utf8(const fs::path& path);
}
