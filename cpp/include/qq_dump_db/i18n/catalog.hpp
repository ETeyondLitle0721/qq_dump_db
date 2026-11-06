#pragma once
#include "qq_dump_db/common.hpp"
namespace qq_dump_db {
std::string resolve_language(const std::string& requested);
void set_language(const std::string& language);
const std::string& current_language();
std::string tr(const std::string& message_id);
}
