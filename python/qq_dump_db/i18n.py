"""Small built-in Chinese/English message catalog for the CLI."""
from __future__ import annotations

import locale
import os

SUPPORTED_LANGUAGES = ("zh-CN", "en-US")
_CURRENT_LANGUAGE = "zh-CN"

_MESSAGES = {
    "zh-CN": {
        "app.description": "从正在运行的 QQ 进程读取并验证本地数据库密钥。",
        "cli.qq": "目标 QQ 号（数字账号目录名）",
        "cli.pid": "诊断用途：显式指定扫描 PID",
        "cli.output": "密钥 JSON 路径；相对路径相对于输出目录",
        "cli.db_dir": "手动指定账号数据库目录",
        "cli.output_dir": "输出根目录；默认 ./output/<QQ号>",
        "cli.lang": "界面语言：auto、zh-CN 或 en-US",
        "cli.no_wait": "不等待 QQ 退出；数据库可能尚未完成 WAL checkpoint",
        "cli.help": "显示此帮助信息并退出",
        "cli.version": "显示版本信息并退出",
        "cli.invalid_qq": "QQ 号必须是非空数字字符串。",
        "cli.invalid_pid": "PID 必须是大于 0 的整数。",
        "cli.db_dir_missing": "数据库目录不存在：{path}",
        "cli.usage_error": "命令行参数错误：{detail}",
        "app.version": "qq_dump_db Python {version}",
        "app.platform_error": "此功能仅支持 Windows。",
        "app.internal_error": "发生未预期错误。详情：{detail}",
        "app.interrupted": "用户中断。",
        "error.prefix": "错误 [{code}]：{message}",
        "warning.prefix": "警告：{message}",
        "process.qq_pids": "QQ 进程 PID：{pids}",
        "process.wrapper_found": "  PID {pid} 包含 wrapper.node",
        "process.none": "未找到包含 wrapper.node 的 QQ.exe 进程。请启动 QQ，或指定 --pid。",
        "mapping.failed": "无法可靠地将 QQ 账号与进程关联：{detail}",
        "mapping.detected_header": "\n检测到的 QQ 进程/账号映射：",
        "mapping.detected": "  PID {wrapper_pid} -> QQ {account}（nt_msg.db 句柄所有者 PID {handle_pid}）",
        "mapping.unmatched": "  PID ? -> QQ {account}（句柄所有者 PID {handle_pid}；无法关联 wrapper.node）",
        "mapping.db_selected": "  已选择 QQ {qq} 数据库：{path}",
        "mapping.pids_selected": "  匹配的 wrapper.node PID：{pids}",
        "mapping.manual_pid": "使用显式扫描 PID：{pid}",
        "mapping.manual_mismatch": "PID {pid} 映射到 QQ {mapped}，而请求的账号是 QQ {requested}。",
        "mapping.manual_unconfirmed": "PID {pid} 未能通过文件句柄映射确认；因显式指定而继续。",
        "mapping.scan_pids": "将扫描映射到 QQ {qq} 的 {count} 个 wrapper.node 进程。",
        "db.global_missing": "未找到全局数据库目录：{path}",
        "db.summary": "\n全局数据库：{global_count}（固定密钥，无需扫描）\n账号数据库：{file_count} 个文件，{salt_count} 个不同 salt",
        "db.none": "未发现符合预期格式的 NTQQ 数据库。",
        "db.no_account_dir": "未能从 QQ 进程句柄发现账号数据库目录。",
        "db.custom_missing": "--db-dir 指定的目录不存在：{path}",
        "workflow.db_dir_unmapped": "无法将 --db-dir 与目标账号关联；改为扫描当前可用的 wrapper.node 进程。",
        "workflow.output_db_collision": "密钥 JSON 输出路径不能覆盖输入数据库。",
        "db.global_ok": "  [global] {name}：验证通过",
        "db.global_bad": "  [global] {name}：HMAC 验证失败",
        "memory.cannot_open": "无法以读取权限打开 PID {pid}（错误 {error}），跳过。",
        "memory.scanning": "\n-- 正在扫描 PID {pid}，查找 {count} 个已知 salt --",
        "memory.summary": "  PID {pid}：扫描 {mb:.0f} MB，用时 {elapsed:.1f}s -> 命中 {found}/{total} 个 salt，{candidates} 个不同候选",
        "memory.combined": "\n合并扫描结果：{found}/{total} 个 salt，{candidates} 个不同候选，涉及 {processes} 个进程。",
        "memory.hit": "  [命中] {name}：候选通过 HMAC 验证（PID {pid}，地址 0x{address:X}，共验证 {tested} 个候选）",
        "memory.miss_candidates": "  [未命中] {names}：发现 {count} 个候选，均未通过 HMAC",
        "memory.miss_none": "  [未命中] {names}：扫描进程中没有匹配的密钥数据",
        "result.header": "\n{line}\n结果：恢复 {found}/{total} 个数据库密钥\n{line}",
        "result.global": "  [global] {salt} -> {names}",
        "result.account": "  [账号] {salt} -> {names}",
        "result.unresolved": "\n尚未恢复的 salt（{count}）：",
        "result.saved": "\n密钥映射已保存：{path}",
        "result.none": "没有密钥候选通过数据库第一页 HMAC 验证。",
        "wait.prompt": "\n请关闭目标 QQ，程序将等待相关进程退出；等待期间按 Enter 可提前继续（WAL 可能尚未刷新），按 Ctrl+C 取消。",
        "wait.noninteractive": "当前不是交互式终端，无法等待 QQ 退出；继续处理前请确认 QQ 已关闭。",
        "wait.waiting": "正在等待目标 QQ 进程退出：{pids}",
        "wait.done": "目标 QQ 进程已退出。",
        "wait.skipped": "已跳过等待。数据库可能尚未完成 WAL checkpoint，输出可能不完整。",
        "decrypt.header": "\n-- 正在解密到 {directory} --",
        "decrypt.ok": "  成功 {name}（{size:.0f} KB）",
        "decrypt.fail": "  失败 {name}",
        "decrypt.conflict": "目标文件名冲突，拒绝覆盖：{name}",
        "decrypt.summary": "\n解密结果：{ok} 成功，{failed} 失败 -> {directory}",
        "exit.ok": "处理完成。",
        "viewer.table_header": "\n  ┌─ 表：{name}（共 {count} 行，显示 {shown} 行）",
        "viewer.columns": "  │  列：{columns}",
        "viewer.table_skip": "\n  ┌─ 表：{name}  [跳过：{error}]",
        "viewer.no_tables": "  （没有表）",
        "viewer.table_count": "  表数量：{total}（普通表 {regular} 个，FTS {fts} 个，已跳过）",
        "viewer.regular": "  普通表：{names}",
        "viewer.fts": "  FTS（已跳过）：{names}",
        "viewer.not_found": "  [!] 未找到表“{name}”",
        "viewer.db_error": "  [错误] {error}",
        "viewer.directory_missing": "[错误] 目录不存在：{path}",
        "viewer.no_db_files": "[错误] 在 {path} 中没有找到 .db 文件",
        "viewer.db_missing": "[错误] 在 {path} 中未找到 {name}",
        "viewer.available": "可用文件：{names}",
        "viewer.qq": "QQ：{qq}",
        "viewer.directory": "目录：{path}",
        "viewer.databases": "数据库数量：{count}",
        "viewer.done": "\n完成。已检查 {count} 个数据库。",
        "viewer.database": "  数据库：{name}（{size:.1f} KB）",
        "viewer.description": "读取已解密的 NTQQ SQLite 数据库",
        "viewer.qq_help": "QQ 号（对应 output/<QQ号>/ 目录）",
        "viewer.db_help": "指定要读取的 .db 文件，例如 nt_msg.db",
        "viewer.table_help": "指定要显示的数据表",
        "viewer.limit_help": "每张表最多显示的行数（默认 10）",
        "viewer.lang_help": "界面语言：auto、zh-CN 或 en-US",
    },
    "en-US": {
        "app.description": "Read and validate local database keys from a running QQ process.",
        "cli.qq": "Target QQ account number (numeric account directory)",
        "cli.pid": "Diagnostic override: explicitly select a scan PID",
        "cli.output": "Key-map JSON path; relative paths are resolved under the output directory",
        "cli.db_dir": "Manually specify the account database directory",
        "cli.output_dir": "Output root; defaults to ./output/<QQ number>",
        "cli.lang": "UI language: auto, zh-CN, or en-US",
        "cli.no_wait": "Do not wait for QQ to exit; WAL may not be checkpointed",
        "cli.help": "Show this help message and exit",
        "cli.version": "Show version information and exit",
        "cli.invalid_qq": "QQ number must be a non-empty string of digits.",
        "cli.invalid_pid": "PID must be a positive integer.",
        "cli.db_dir_missing": "Database directory does not exist: {path}",
        "cli.usage_error": "Command-line error: {detail}",
        "app.version": "qq_dump_db Python {version}",
        "app.platform_error": "This operation is supported on Windows only.",
        "app.internal_error": "Unexpected error. Details: {detail}",
        "app.interrupted": "Interrupted by user.",
        "error.prefix": "Error [{code}]: {message}",
        "warning.prefix": "Warning: {message}",
        "process.qq_pids": "QQ process PIDs: {pids}",
        "process.wrapper_found": "  PID {pid} contains wrapper.node",
        "process.none": "No QQ.exe process with wrapper.node was found. Start QQ or specify --pid.",
        "mapping.failed": "Could not reliably associate the QQ account with a process: {detail}",
        "mapping.detected_header": "\nDetected QQ process/account mappings:",
        "mapping.detected": "  PID {wrapper_pid} -> QQ {account} (nt_msg.db handle owner PID {handle_pid})",
        "mapping.unmatched": "  PID ? -> QQ {account} (handle owner PID {handle_pid}; wrapper.node could not be correlated)",
        "mapping.db_selected": "  Selected QQ {qq} database: {path}",
        "mapping.pids_selected": "  Matching wrapper.node PID(s): {pids}",
        "mapping.manual_pid": "Using explicit scan PID: {pid}",
        "mapping.manual_mismatch": "PID {pid} maps to QQ {mapped}, not requested QQ {requested}.",
        "mapping.manual_unconfirmed": "No file-handle mapping confirmed PID {pid}; proceeding because it was explicit.",
        "mapping.scan_pids": "Will scan {count} wrapper.node process(es) mapped to QQ {qq}.",
        "db.global_missing": "Global DB directory not found: {path}",
        "db.summary": "\nGlobal DBs: {global_count} (fixed key, no scan)\nPer-account: {file_count} files, {salt_count} unique salts",
        "db.none": "No NTQQ databases matching the expected format were found.",
        "db.no_account_dir": "Account DB directory was not discovered from QQ process handles.",
        "db.custom_missing": "The --db-dir directory does not exist: {path}",
        "workflow.db_dir_unmapped": "The --db-dir path is not mapped to the target account; scanning available wrapper.node processes.",
        "workflow.output_db_collision": "The key-map output path must not overwrite an input database.",
        "db.global_ok": "  [global] {name}: verified",
        "db.global_bad": "  [global] {name}: HMAC verification failed",
        "memory.cannot_open": "Cannot open PID {pid} for reading (error {error}); skipping.",
        "memory.scanning": "\n-- Scanning PID {pid} for {count} known salts --",
        "memory.summary": "  PID {pid}: scanned {mb:.0f} MB in {elapsed:.1f}s -> {found}/{total} salts, {candidates} distinct candidates",
        "memory.combined": "\nCombined scan results: {found}/{total} salts, {candidates} distinct candidates across {processes} process(es).",
        "memory.hit": "  [hit] {name}: candidate passed HMAC verification (PID {pid}, address 0x{address:X}, {tested} candidate(s) tested)",
        "memory.miss_candidates": "  [miss] {names}: {count} candidate(s), none passed HMAC",
        "memory.miss_none": "  [miss] {names}: no matching key blob found in scanned process(es)",
        "result.header": "\n{line}\nRESULTS: {found}/{total} database keys recovered\n{line}",
        "result.global": "  [global] {salt} -> {names}",
        "result.account": "  [account] {salt} -> {names}",
        "result.unresolved": "\nUnresolved salts ({count}):",
        "result.saved": "\nKey map saved: {path}",
        "result.none": "No candidate key passed the page-1 HMAC validation.",
        "wait.prompt": "\nClose the target QQ process. The program will wait for it to exit; press Enter to continue early (WAL may not be flushed), or Ctrl+C to cancel.",
        "wait.noninteractive": "No interactive terminal is available to wait for QQ. Confirm QQ is closed before continuing.",
        "wait.waiting": "Waiting for target QQ process(es) to exit: {pids}",
        "wait.done": "Target QQ process(es) have exited.",
        "wait.skipped": "Wait skipped. WAL may not be checkpointed, so output may be incomplete.",
        "decrypt.header": "\n-- Decrypting to {directory} --",
        "decrypt.ok": "  OK {name} ({size:.0f} KB)",
        "decrypt.fail": "  FAIL {name}",
        "decrypt.conflict": "Output filename collision; refusing to overwrite: {name}",
        "decrypt.summary": "\nDecrypted: {ok} OK, {failed} failed -> {directory}",
        "exit.ok": "Completed.",
        "viewer.table_header": "\n  ┌─ Table: {name} ({count} rows total, showing {shown})",
        "viewer.columns": "  │  Columns: {columns}",
        "viewer.table_skip": "\n  ┌─ Table: {name}  [SKIP: {error}]",
        "viewer.no_tables": "  (no tables)",
        "viewer.table_count": "  Tables ({total}): {regular} regular, {fts} FTS (skipped)",
        "viewer.regular": "  Regular: {names}",
        "viewer.fts": "  FTS (skip): {names}",
        "viewer.not_found": "  [!] Table '{name}' not found",
        "viewer.db_error": "  [ERROR] {error}",
        "viewer.directory_missing": "[ERROR] Directory not found: {path}",
        "viewer.no_db_files": "[ERROR] No .db files found in {path}",
        "viewer.db_missing": "[ERROR] {name} not found in {path}",
        "viewer.available": "Available: {names}",
        "viewer.qq": "QQ: {qq}",
        "viewer.directory": "Directory: {path}",
        "viewer.databases": "Databases: {count}",
        "viewer.done": "\nDone. Inspected {count} database(s).",
        "viewer.database": "  Database: {name} ({size:.1f} KB)",
        "viewer.description": "Read decrypted NTQQ SQLite databases",
        "viewer.qq_help": "QQ number (matches the output/<QQ number>/ directory)",
        "viewer.db_help": "Specific .db file to read, for example nt_msg.db",
        "viewer.table_help": "Specific table to display",
        "viewer.limit_help": "Maximum rows per table (default: 10)",
        "viewer.lang_help": "UI language: auto, zh-CN, or en-US",
    },
}


def set_language(language: str) -> None:
    global _CURRENT_LANGUAGE
    _CURRENT_LANGUAGE = language if language in SUPPORTED_LANGUAGES else "zh-CN"


def get_language(requested: str = "auto") -> str:
    if requested in SUPPORTED_LANGUAGES:
        return requested
    env_language = os.environ.get("QQ_DUMP_DB_LANG", "").strip()
    if env_language in SUPPORTED_LANGUAGES:
        return env_language
    try:
        if os.name == "nt":
            import ctypes
            lang_id = ctypes.WinDLL("kernel32").GetUserDefaultUILanguage()
            primary = lang_id & 0x3FF
            if primary == 0x04:
                return "zh-CN"
            if primary == 0x09:
                return "en-US"
        system_locale = locale.getlocale()[0] or ""
        if system_locale.lower().startswith("zh"):
            return "zh-CN"
        if system_locale.lower().startswith("en"):
            return "en-US"
    except Exception:
        pass
    return "zh-CN"


def tr(message_id: str, **values) -> str:
    template = _MESSAGES.get(_CURRENT_LANGUAGE, {}).get(message_id)
    if template is None:
        template = _MESSAGES["zh-CN"].get(message_id, message_id)
    try:
        return template.format(**values)
    except (KeyError, ValueError):
        return template
