#pragma once
#include "qq_dump_db/common.hpp"
namespace qq_dump_db {
bool decrypt_db(const fs::path& input_path, const fs::path& output_path,
                const uint8_t* enc_key);
}
