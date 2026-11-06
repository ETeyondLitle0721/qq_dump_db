/*
 * C++ application entry point.
 * Implementation is split across cpp/src modules; this file only adapts the
 * Windows command line to UTF-8 and starts the CLI/application layers.
 */
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <shellapi.h>

#include <string>
#include <vector>

#include "qq_dump_db/cli.hpp"
#include "qq_dump_db/i18n/catalog.hpp"
#include "qq_dump_db/services/workflow.hpp"

namespace {
std::string wide_to_utf8(const std::wstring& value) {
    if (value.empty()) return {};
    const int required = WideCharToMultiByte(
        CP_UTF8, WC_ERR_INVALID_CHARS, value.c_str(), -1,
        nullptr, 0, nullptr, nullptr);
    if (required <= 0) return {};
    std::string result(static_cast<size_t>(required), '\0');
    if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.c_str(), -1,
                            result.data(), required, nullptr, nullptr) <= 0)
        return {};
    result.resize(static_cast<size_t>(required - 1));
    return result;
}

std::vector<std::string> command_line_arguments() {
    int argc = 0;
    LPWSTR* wide_argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    std::vector<std::string> arguments;
    if (!wide_argv) return arguments;
    for (int i = 1; i < argc; ++i)
        arguments.push_back(wide_to_utf8(wide_argv[i]));
    LocalFree(wide_argv);
    return arguments;
}
}

int main() {
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);

    const auto arguments = command_line_arguments();
    const auto parsed = qq_dump_db::parse_args(arguments);
    if (parsed.show_help) {
        qq_dump_db::print_help();
        return 0;
    }
    if (parsed.show_version) {
        std::cout << "qq_dump_db C++ " << qq_dump_db::APP_VERSION << "\n";
        return 0;
    }
    if (parsed.exit_code != 0) {
        qq_dump_db::print_cli_error(parsed);
        return parsed.exit_code;
    }
    return qq_dump_db::run_workflow(parsed.args);
}
