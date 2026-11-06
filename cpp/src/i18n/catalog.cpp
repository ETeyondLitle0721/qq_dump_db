#include "qq_dump_db/i18n/catalog.hpp"
#include <cstdlib>

namespace qq_dump_db {
namespace {
std::string g_language = "zh-CN";
using Catalog = std::map<std::string, std::string>;
const Catalog kChinese = {
 {"error.label", "错误 "}, {"warning.prefix", "警告："},
 {"app.description", "从正在运行的 QQ 进程读取并验证本地数据库密钥。"},
 {"cli.qq", "目标 QQ 号（数字账号目录名）"}, {"cli.pid", "诊断用途：显式指定扫描 PID"},
 {"cli.output", "密钥 JSON 路径；相对路径相对于输出目录"}, {"cli.db_dir", "手动指定账号数据库目录"},
 {"cli.output_dir", "输出根目录；默认 ./output/<QQ号>"}, {"cli.lang", "界面语言：auto、zh-CN 或 en-US"},
 {"cli.no_wait", "跳过等待 QQ 退出；数据库可能尚未完成 WAL checkpoint"},
 {"cli.help", "显示此帮助信息并退出"}, {"cli.version", "显示版本信息并退出"},
 {"cli.usage", "用法：qq_dump_db --qq <QQ号> [--pid PID] [--db-dir 目录] [-o 文件] [--output-dir 目录] [--lang auto|zh-CN|en-US] [--no-wait]"},
 {"cli.invalid_qq", "QQ 号必须是非空数字字符串。"}, {"cli.invalid_pid", "PID 必须是大于 0 的十进制整数。"},
 {"cli.invalid_lang", "语言仅支持 auto、zh-CN 和 en-US。"}, {"cli.missing_value", "参数缺少值："},
 {"cli.unknown_option", "未知参数："}, {"cli.required_qq", "必须指定 --qq。"},
 {"process.pids", "QQ 进程 PID："}, {"process.wrapper", "包含 wrapper.node"},
 {"process.not_found", "未找到包含 wrapper.node 的 QQ.exe 进程。请启动 QQ，或指定 --pid。"},
 {"mapping.header", "\n检测到的 QQ 进程/账号映射："}, {"mapping.detected", "  PID "},
 {"mapping.unmatched", "  PID ? -> QQ "}, {"mapping.select", "  已选择 QQ "},
 {"mapping.pids", "  匹配的 wrapper.node PID："}, {"mapping.multiple", "目标 QQ 账号关联到多个 nt_msg.db 路径，无法安全选择："},
 {"mapping.not_found", "没有运行中的 QQ 实例映射到账号 "},
 {"mapping.unmapped", "数据库路径已识别，但无法将 wrapper.node PID 关联到目标 QQ。"},
 {"mapping.manual", "使用显式扫描 PID："}, {"mapping.mismatch", "该 PID 映射到其他 QQ 账号："},
 {"mapping.unconfirmed", "该 PID 未通过文件句柄映射确认；因显式指定而继续。"},
 {"db.global_missing", "未找到全局数据库目录："}, {"db.account_missing", "未能从 QQ 进程句柄发现账号数据库目录。"},
 {"db.custom_missing", "--db-dir 指定的目录不存在："}, {"db.none", "未发现符合预期格式的 NTQQ 数据库。"},
 {"db.summary_global", "\n全局数据库："}, {"db.summary_fixed", "（固定密钥，无需扫描）\n账号数据库："},
 {"db.summary_files", " 个文件，"}, {"db.summary_salts", " 个不同 salt\n"},
 {"memory.cannot_open", "无法以读取权限打开 PID "}, {"memory.scanning", "\n-- 正在扫描 PID "},
 {"memory.scanning_suffix", "，查找已知 salt --\n"}, {"memory.summary_prefix", "  PID "},
 {"memory.summary_scanned", "：扫描 "}, {"memory.summary_mb", " MB，用时 "}, {"memory.summary_hit", "s -> 命中 "},
 {"memory.summary_candidates", " 个不同候选\n"}, {"memory.combined", "\n合并扫描结果："},
 {"memory.combined_salts", " 个 salt，"}, {"memory.combined_candidates", " 个不同候选，涉及 "},
 {"memory.processes", " 个进程。\n"}, {"memory.hit", "  [命中] "},
 {"memory.hit_verified", "：候选通过 HMAC 验证（PID "}, {"memory.address", "，地址 0x"},
 {"memory.tested", "，共验证 "}, {"memory.candidate", " 个候选）\n"}, {"memory.miss", "  [未命中] "},
 {"memory.miss_candidates", "：发现候选，但均未通过 HMAC\n"}, {"memory.miss_none", "：扫描进程中没有匹配的密钥数据\n"},
 {"result.header", "\n结果：恢复 "}, {"result.of", "/"}, {"result.keys", " 个数据库密钥\n"},
 {"result.global", "  [global] "}, {"result.account", "  [账号] "}, {"result.arrow", " -> "},
 {"result.unresolved", "\n尚未恢复的 salt（"}, {"result.unresolved_end", "）：\n"}, {"result.saved", "\n密钥映射已保存："},
 {"result.none", "没有密钥候选通过数据库第一页 HMAC 验证。"},
 {"wait.prompt", "\n请关闭目标 QQ，程序将等待相关进程退出；按 Enter 可提前继续（WAL 可能尚未刷新），按 Ctrl+C 取消。\n"},
 {"wait.waiting", "正在等待目标 QQ 进程退出："}, {"wait.done", "目标 QQ 进程已退出。\n"},
 {"wait.skipped", "已跳过等待。数据库可能尚未完成 WAL checkpoint，输出可能不完整。\n"},
 {"wait.noninteractive", "当前不是交互式终端，无法等待 QQ 退出；请确认 QQ 已关闭，或使用 --no-wait。\n"},
 {"decrypt.header", "\n-- 正在解密到 "}, {"decrypt.ok", "  成功 "}, {"decrypt.fail", "  失败 "},
 {"decrypt.conflict", "目标文件名冲突，拒绝覆盖："}, {"decrypt.summary", "\n解密结果："},
 {"decrypt.ok_count", " 成功，"}, {"decrypt.fail_count", " 失败 -> "}, {"exit.complete", "处理完成。\n"},
 {"error.no_qq", "未找到可用的 QQ.exe 进程。"}, {"error.mapping", "无法可靠地将 QQ 账号与进程关联。"},
 {"error.database", "数据库目录或数据库文件不可用。"}, {"error.output", "无法写入密钥 JSON 文件。"},
 {"error.decrypt", "一个或多个数据库解密或验证失败。"}, {"error.internal", "发生未预期的内部错误。"},
 {"output.collision", "密钥 JSON 输出路径不能覆盖输入数据库。"}, {"output.mkdir", "无法创建输出目录："},
 {"handle.no_pids", "没有可用于句柄检查的 QQ 进程 PID。"},
 {"handle.ntdll", "无法获取 NtQuerySystemInformation 系统 API。"},
 {"handle.ntquery_failed", "NtQuerySystemInformation 调用失败，NTSTATUS："},
 {"handle.too_large", "系统句柄表过大。"}, {"handle.alloc_failed", "无法分配足够大的系统句柄表。"},
 {"handle.invalid", "系统句柄表响应无效。"}, {"handle.cannot_open", "无法打开任何 QQ 进程进行句柄检查，请使用足够的权限运行。"},
 {"handle.none", "未找到符合 Tencent Files/<QQ>/nt_qq/nt_db 目录结构的 QQ nt_msg.db 句柄。请确认 QQ 已登录且消息数据库已打开。"},
 {"mapping.line_pid", "  PID "}, {"mapping.to_qq", " -> QQ "},
 {"mapping.owner", "（nt_msg.db 句柄所有者 PID "}, {"mapping.owner_end", "）"},
 {"mapping.unmatched_end", "（句柄所有者 PID "}, {"mapping.no_wrapper", "；无法关联 wrapper.node 进程）"},
 {"mapping.database_label", " 数据库："}, {"mapping.no_wrapper_match", "无法将该数据库句柄所有者关联到 wrapper.node PID。"},
 {"workflow.scan_prefix", "将扫描映射到 QQ "}, {"workflow.scan_middle", " 的 "}, {"workflow.scan_suffix", " 个 wrapper.node 进程。\n"},
 {"workflow.reread", "\n-- 正在重新读取数据库文件 --\n"},
 {"workflow.matched_prefix", "  已将 "}, {"workflow.matched_suffix", " 个数据库文件匹配到已验证的密钥。\n"}
};
const Catalog kEnglish = {
 {"error.label", "ERROR "}, {"warning.prefix", "Warning: "},
 {"app.description", "Read and validate local database keys from a running QQ process."},
 {"cli.qq", "Target QQ account number (numeric account directory)"}, {"cli.pid", "Diagnostic override: explicitly select a scan PID"},
 {"cli.output", "Key-map JSON path; relative paths are resolved under the output directory"}, {"cli.db_dir", "Manually specify the account database directory"},
 {"cli.output_dir", "Output root; defaults to ./output/<QQ number>"}, {"cli.lang", "UI language: auto, zh-CN, or en-US"},
 {"cli.no_wait", "Skip waiting for QQ to exit; WAL may not be checkpointed"},
 {"cli.help", "Show this help message and exit"}, {"cli.version", "Show version information and exit"},
 {"cli.usage", "Usage: qq_dump_db --qq <QQ_NUMBER> [--pid PID] [--db-dir DIR] [-o FILE] [--output-dir DIR] [--lang auto|zh-CN|en-US] [--no-wait]"},
 {"cli.invalid_qq", "QQ number must be a non-empty string of digits."}, {"cli.invalid_pid", "PID must be a positive decimal integer."},
 {"cli.invalid_lang", "Language must be auto, zh-CN, or en-US."}, {"cli.missing_value", "Missing value for option: "},
 {"cli.unknown_option", "Unknown option: "}, {"cli.required_qq", "The --qq option is required."},
 {"process.pids", "QQ process PIDs: "}, {"process.wrapper", "contains wrapper.node"},
 {"process.not_found", "No QQ.exe process with wrapper.node was found. Start QQ or specify --pid."},
 {"mapping.header", "\nDetected QQ process/account mappings:"}, {"mapping.detected", "  PID "},
 {"mapping.unmatched", "  PID ? -> QQ "}, {"mapping.select", "  Selected QQ "}, {"mapping.pids", "  Matching wrapper.node PID(s): "},
 {"mapping.multiple", "Multiple nt_msg.db paths were mapped to the target QQ account; refusing to guess:"},
 {"mapping.not_found", "No running QQ instance was mapped to account "},
 {"mapping.unmapped", "The database path was identified, but no wrapper.node PID could be mapped to the target QQ."},
 {"mapping.manual", "Using explicit scan PID: "}, {"mapping.mismatch", "The PID maps to another QQ account: "},
 {"mapping.unconfirmed", "No file-handle mapping was confirmed for this PID; proceeding because --pid was explicit."},
 {"db.global_missing", "Global DB directory not found: "}, {"db.account_missing", "Account DB directory was not discovered from QQ process handles."},
 {"db.custom_missing", "The --db-dir path does not exist: "}, {"db.none", "No NTQQ databases with the expected format were found."},
 {"db.summary_global", "\nGlobal DBs: "}, {"db.summary_fixed", " (fixed key, no scan)\nPer-account: "},
 {"db.summary_files", " files, "}, {"db.summary_salts", " unique salts\n"},
 {"memory.cannot_open", "Cannot open PID "}, {"memory.scanning", "\n-- Scanning PID "},
 {"memory.scanning_suffix", " for known salts --\n"}, {"memory.summary_prefix", "  PID "},
 {"memory.summary_scanned", ": scanned "}, {"memory.summary_mb", " MB in "}, {"memory.summary_hit", "s -> found "},
 {"memory.summary_candidates", " distinct candidates\n"}, {"memory.combined", "\nCombined scan results: "},
 {"memory.combined_salts", " salts, "}, {"memory.combined_candidates", " distinct candidates across "},
 {"memory.processes", " process(es).\n"}, {"memory.hit", "  [hit] "},
 {"memory.hit_verified", ": candidate passed HMAC (PID "}, {"memory.address", ", address 0x"},
 {"memory.tested", ", tested "}, {"memory.candidate", " candidate(s))\n"}, {"memory.miss", "  [miss] "},
 {"memory.miss_candidates", ": candidates found, none passed HMAC\n"}, {"memory.miss_none", ": no matching key data found in scanned process(es)\n"},
 {"result.header", "\nRecovered "}, {"result.of", "/"}, {"result.keys", " database key(s)\n"},
 {"result.global", "  [global] "}, {"result.account", "  [account] "}, {"result.arrow", " -> "},
 {"result.unresolved", "\nUnresolved salts ("}, {"result.unresolved_end", "):\n"}, {"result.saved", "\nKey map saved to: "},
 {"result.none", "No candidate passed the database page-1 HMAC validation."},
 {"wait.prompt", "\nClose QQ. The program waits for related processes; press Enter to continue early (WAL may not be flushed), or Ctrl+C to cancel.\n"},
 {"wait.waiting", "Waiting for target QQ processes to exit: "}, {"wait.done", "Target QQ processes have exited.\n"},
 {"wait.skipped", "Waiting was skipped. WAL may not be checkpointed; output may be incomplete.\n"},
 {"wait.noninteractive", "Non-interactive console: cannot wait for QQ to exit. Confirm QQ is closed, or use --no-wait.\n"},
 {"decrypt.header", "\n-- Decrypting to "}, {"decrypt.ok", "  OK "}, {"decrypt.fail", "  FAIL "},
 {"decrypt.conflict", "Output filename collision; refusing to overwrite: "}, {"decrypt.summary", "\nDecrypted: "},
 {"decrypt.ok_count", " OK, "}, {"decrypt.fail_count", " failed -> "}, {"exit.complete", "Completed.\n"},
 {"error.no_qq", "No usable QQ.exe process was found."}, {"error.mapping", "Could not reliably map the QQ account to a process."},
 {"error.database", "The database directory or database files are unavailable."}, {"error.output", "Could not write the key-map JSON file."},
 {"error.decrypt", "One or more databases failed to decrypt or validate."}, {"error.internal", "An unexpected internal error occurred."},
 {"output.collision", "The key-map output path must not overwrite an input database."}, {"output.mkdir", "Could not create output directory: "},
 {"handle.no_pids", "No QQ process IDs are available for handle inspection."},
 {"handle.ntdll", "NtQuerySystemInformation is unavailable."},
 {"handle.ntquery_failed", "NtQuerySystemInformation failed, NTSTATUS: "},
 {"handle.too_large", "The system handle table is too large."}, {"handle.alloc_failed", "Could not allocate a large enough system handle table."},
 {"handle.invalid", "The system handle table response is invalid."}, {"handle.cannot_open", "Cannot open any QQ process for handle inspection. Run with sufficient permissions."},
 {"handle.none", "No QQ-owned nt_msg.db handle with the expected Tencent Files/<QQ>/nt_qq/nt_db layout was found. Make sure QQ is logged in and its message database is open."},
 {"mapping.line_pid", "  PID "}, {"mapping.to_qq", " -> QQ "},
 {"mapping.owner", " (nt_msg.db handle owner PID "}, {"mapping.owner_end", ")"},
 {"mapping.unmatched_end", " (handle owner PID "}, {"mapping.no_wrapper", "; wrapper.node process could not be correlated)"},
 {"mapping.database_label", " database: "}, {"mapping.no_wrapper_match", "The database handle owner could not be correlated to a wrapper.node PID."},
 {"workflow.scan_prefix", "Will scan "}, {"workflow.scan_middle", " wrapper.node process(es) mapped to QQ "},
 {"workflow.scan_suffix", ".\n"}, {"workflow.reread", "\n-- Re-reading database files --\n"},
 {"workflow.matched_prefix", "  Matched "}, {"workflow.matched_suffix", " database file(s) to verified keys.\n"}
};
}

std::string resolve_language(const std::string& requested) {
    if (requested == "zh-CN" || requested == "en-US") return requested;
    if (!requested.empty() && requested != "auto") return {};
    if (const char* env = std::getenv("QQ_DUMP_DB_LANG")) {
        const std::string value(env);
        if (value == "zh-CN" || value == "en-US") return value;
    }
    const WORD primary = PRIMARYLANGID(GetUserDefaultUILanguage());
    if (primary == LANG_CHINESE) return "zh-CN";
    if (primary == LANG_ENGLISH) return "en-US";
    return "zh-CN";
}
void set_language(const std::string& language) { g_language = language == "en-US" ? "en-US" : "zh-CN"; }
const std::string& current_language() { return g_language; }
std::string tr(const std::string& message_id) {
    const auto& catalog = g_language == "en-US" ? kEnglish : kChinese;
    const auto it = catalog.find(message_id);
    return it == catalog.end() ? message_id : it->second;
}
} // namespace qq_dump_db
