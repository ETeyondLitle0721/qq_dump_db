#pragma once
#include "qq_dump_db/common.hpp"
namespace qq_dump_db {
struct CliResult {
    Args args;
    bool show_help = false;
    bool show_version = false;
    int exit_code = 0;
    std::string error_id;
    std::string error_message;
};
CliResult parse_args(const std::vector<std::string>& arguments);
void print_help();
void print_cli_error(const CliResult& result);
}
