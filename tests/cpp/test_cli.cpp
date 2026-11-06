#include "qq_dump_db/cli.hpp"
#include "qq_dump_db/i18n/catalog.hpp"

#include <iostream>
#include <string>
#include <vector>

using namespace qq_dump_db;

int main() {
    int failures = 0;
    const auto expect = [&](bool condition, const char* name) {
        if (!condition) {
            std::cerr << "FAILED: " << name << '\n';
            ++failures;
        }
    };

    {
        const auto result = parse_args({"--qq", "10001", "--lang", "zh-CN"});
        expect(result.exit_code == 0, "Chinese CLI arguments are accepted");
        expect(result.args.qq == "10001", "QQ account is parsed");
        expect(result.args.lang == "zh-CN", "Chinese language is selected");
        expect(result.args.output_dir.filename() == fs::u8path("10001"),
               "default output directory includes the QQ account");
        expect(tr("error.label") == "错误 ", "Chinese error label is translated");
    }
    {
        const auto result = parse_args({"--qq", "10002", "--lang=en-US",
                                        "--output-dir", "test-output",
                                        "--output", "keys/custom.json", "--no-wait"});
        expect(result.exit_code == 0, "English CLI arguments are accepted");
        expect(result.args.lang == "en-US", "English language is selected");
        expect(result.args.no_wait, "--no-wait is parsed");
        expect(result.args.output == fs::u8path("keys/custom.json"),
               "relative output path is retained for workflow resolution");
        expect(result.args.output_dir.is_absolute(), "relative output root is normalized");
        expect(tr("error.label") == "ERROR ", "English error label is translated");
    }
    {
        const auto result = parse_args({"--qq", "not-a-number"});
        expect(result.exit_code == 2, "invalid QQ uses CLI exit code");
        expect(result.error_id == "CLI_USAGE", "invalid QQ uses stable CLI error ID");
    }
    {
        const auto result = parse_args({"--qq", "10003", "--pid", "0"});
        expect(result.exit_code == 2, "zero PID is rejected");
        expect(result.error_id == "CLI_USAGE", "invalid PID uses stable CLI error ID");
    }
    {
        const auto result = parse_args({"--qq", "10004", "--lang", "ja-JP"});
        expect(result.exit_code == 2, "languages other than Chinese and English are rejected");
        expect(result.error_id == "CLI_USAGE", "invalid language uses stable CLI error ID");
    }
    {
        const auto result = parse_args({"--help"});
        expect(result.show_help, "--help is recognized");
        expect(result.exit_code == 0, "--help exits successfully");
    }
    {
        const auto result = parse_args({"--version"});
        expect(result.show_version, "--version is recognized");
        expect(result.exit_code == 0, "--version exits successfully");
    }

    if (failures != 0) {
        std::cerr << failures << " C++ CLI contract test(s) failed.\n";
        return 1;
    }
    std::cout << "C++ CLI contract tests passed.\n";
    return 0;
}
