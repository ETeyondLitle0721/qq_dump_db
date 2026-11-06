#include "qq_dump_db/cli.hpp"
#include "qq_dump_db/i18n/catalog.hpp"
#include "qq_dump_db/utils/hex.hpp"

namespace qq_dump_db {
namespace {
bool is_digits(const std::string& value) {
    return !value.empty() && std::all_of(value.begin(), value.end(), [](unsigned char c) {
        return c >= '0' && c <= '9';
    });
}
}

CliResult parse_args(const std::vector<std::string>& raw_arguments) {
    CliResult result;
    std::vector<std::string> arguments;
    arguments.reserve(raw_arguments.size() + 2);
    for (const auto& item : raw_arguments) {
        if (item.rfind("--lang=", 0) == 0) {
            arguments.emplace_back("--lang");
            arguments.push_back(item.substr(7));
        } else {
            arguments.push_back(item);
        }
    }
    std::string requested_language = "auto";
    for (size_t i = 0; i < arguments.size(); ++i) {
        if (arguments[i] == "--lang" && i + 1 < arguments.size())
            requested_language = arguments[i + 1];
    }
    const std::string language = resolve_language(requested_language);
    if (language.empty()) {
        result.exit_code = 2;
        result.error_id = "CLI_USAGE";
        result.error_message = tr("cli.invalid_lang");
        set_language("zh-CN");
        return result;
    }
    set_language(language);
    result.args.lang = language;

    auto fail = [&](int code, const std::string& id, const std::string& message) {
        result.exit_code = code;
        result.error_id = id;
        result.error_message = message;
    };

    for (size_t i = 0; i < arguments.size(); ++i) {
        const std::string& option = arguments[i];
        if (option == "--help" || option == "-h") {
            result.show_help = true;
            return result;
        }
        if (option == "--version") {
            result.show_version = true;
            return result;
        }
        if (option == "--no-wait") {
            result.args.no_wait = true;
            continue;
        }

        const bool takes_value = option == "--qq" || option == "--pid" ||
            option == "--db-dir" || option == "--output-dir" ||
            option == "--output" || option == "-o" || option == "--lang";
        if (!takes_value) {
            fail(2, "CLI_USAGE", tr("cli.unknown_option") + option);
            return result;
        }
        if (i + 1 >= arguments.size()) {
            fail(2, "CLI_USAGE", tr("cli.missing_value") + option);
            return result;
        }
        const std::string value = arguments[++i];
        if (option == "--qq") {
            result.args.qq = value;
        } else if (option == "--pid") {
            try {
                size_t consumed = 0;
                const unsigned long parsed = std::stoul(value, &consumed, 10);
                if (consumed != value.size() || parsed == 0 || parsed > MAXDWORD) {
                    fail(2, "CLI_USAGE", tr("cli.invalid_pid"));
                    return result;
                }
                result.args.pid = static_cast<DWORD>(parsed);
            } catch (...) {
                fail(2, "CLI_USAGE", tr("cli.invalid_pid"));
                return result;
            }
        } else if (option == "--db-dir") {
            result.args.db_dir = fs::u8path(value);
        } else if (option == "--output-dir") {
            result.args.output_dir = fs::u8path(value);
        } else if (option == "--output" || option == "-o") {
            result.args.output = fs::u8path(value);
        } else if (option == "--lang") {
            if (value != "auto" && value != "zh-CN" && value != "en-US") {
                fail(2, "CLI_USAGE", tr("cli.invalid_lang"));
                return result;
            }
            result.args.lang = resolve_language(value);
            if (result.args.lang.empty()) {
                fail(2, "CLI_USAGE", tr("cli.invalid_lang"));
                return result;
            }
            set_language(result.args.lang);
        }
    }

    if (result.args.qq.empty()) {
        fail(2, "CLI_USAGE", tr("cli.required_qq"));
        return result;
    }
    if (!is_digits(result.args.qq)) {
        fail(2, "CLI_USAGE", tr("cli.invalid_qq"));
        return result;
    }
    if (!result.args.db_dir.empty() && !fs::is_directory(result.args.db_dir)) {
        fail(13, "DATABASE_NOT_FOUND", tr("db.custom_missing") + path_to_utf8(result.args.db_dir));
        return result;
    }
    if (result.args.output_dir.empty())
        result.args.output_dir = fs::current_path() / "output" / fs::u8path(result.args.qq);
    else if (result.args.output_dir.is_relative())
        result.args.output_dir = fs::absolute(result.args.output_dir);
    return result;
}

void print_help() {
    std::cout << tr("app.description") << "\n\n" << tr("cli.usage") << "\n\n"
              << "  --qq <QQ>          " << tr("cli.qq") << "\n"
              << "  --pid <PID>        " << tr("cli.pid") << "\n"
              << "  --db-dir <DIR>     " << tr("cli.db_dir") << "\n"
              << "  -o, --output <FILE> " << tr("cli.output") << "\n"
              << "  --output-dir <DIR> " << tr("cli.output_dir") << "\n"
              << "  --lang <LANG>      " << tr("cli.lang") << "\n"
              << "  --no-wait          " << tr("cli.no_wait") << "\n"
              << "  -h, --help         " << tr("cli.help") << "\n"
              << "  --version          " << tr("cli.version") << "\n";
}

void print_cli_error(const CliResult& result) {
    std::cerr << tr("error.label") << "[" << result.error_id << "]: " << result.error_message << "\n";
    if (result.exit_code == 2) std::cerr << tr("cli.usage") << "\n";
}
} // namespace qq_dump_db
