# 现有实现差异与迁移约束

本文件记录对项目当前源码的核对结果，并明确规范 v1 如何统一。它不是对当前代码行为的描述性承诺；规范 v1 是后续迁移目标。

## 1. 已确认差异

| 项目 | 当前 Python | 当前 C++ | 规范 v1 |
|---|---|---|---|
| CLI 必需项 | `--qq` | `--qq` | 保持必需 |
| 显式 PID | `--pid` | `--pid` | 保持诊断覆盖语义 |
| 手动数据库目录 | `--db-dir` | `--db-dir` | 保持；指定时不自动额外发现全局库 |
| key map 默认位置 | 当前工作目录下 `key_map.json` | `output/<QQ号>/key_map.json`（当前工作目录为根） | `<当前工作目录>/output/<QQ号>/key_map.json` |
| 解密输出目录 | 脚本文件所在目录下 `output/<QQ号>/` | 当前工作目录下 `output/<QQ号>/` | `<当前工作目录>/output/<QQ号>/` |
| `-o` 相对路径 | 相对于当前工作目录 | 相对于输出目录 | 相对于输出目录 |
| 等待 QQ 退出 | 不等待 | 默认等待，可按 Enter 提前继续 | 默认等待；允许 Enter 或 `--no-wait` 显式跳过 |
| 等待后重读数据库 | 不做 | 做 | 必须做 |
| JSON 顶层字段 | `key_map`、`_generated` | `key_map`、`_generated` | `schema_version`、`key_map`、`_generated` |
| `_generated` 格式 | 本地时间 `YYYY-MM-DD HH:MM:SS` | 本地时间 `YYYY-MM-DD HH:MM:SS` | UTC `YYYY-MM-DDTHH:mm:ssZ` |
| C++ 参数帮助 | 基础 usage，未知参数处理不完整 | 当前可见实现未提供 argparse 等价体验 | 两端都支持 `--help`、`--version` 和严格参数校验 |

## 2. 向后兼容

### CLI

- 旧参数名称保留：`--qq`、`--pid`、`--db-dir`、`-o/--output`。
- 旧的常见调用方式仍然有效；默认输出路径统一后，Python 使用者可能会看到 key map 移入 `output/<QQ号>/`。
- Python 用户若要保留原来的 JSON 落点，应显式传入绝对路径，例如 `--output C:\\exports\\key_map.json`。
- `--output` 相对路径语义统一到输出根目录；需要精确控制落点时使用绝对路径。

### JSON

- 旧文件格式（无 `schema_version`，只有 `key_map` 与本地时间 `_generated`）作为 legacy v0 接受读取。
- 新实现只写 v1，不再写无时区的时间字符串。
- 读取 legacy v0 时不能把本地时间错误解释为 UTC；它应作为无时区的旧式时间值保留或仅用于显示。
- `key_map` 的现有语义不变：16 字节 salt 的小写十六进制字符串映射到 32 字节密钥的小写十六进制字符串。

### 数据库文件

- 默认解密文件仍放在 `output/<QQ号>/` 根目录，暂不改变数据库文件名。
- 若多个源文件产生同名目标文件，v1 要显式报冲突而不是沿用当前可能覆盖文件的行为。
- 只有解密后通过 SQLite 验证的结果才允许成为最终目标文件。

## 3. 第二阶段实现进度（Python）

已在 Python 端落实：

1. 模块化拆分 Win32 API、进程枚举、句柄映射、账号识别、数据库发现、SQLCipher、内存扫描和工作流。
2. 保留根目录 `dump_qq_key_auto.py` 作为兼容启动器，并增加 `python -m qq_dump_db` / 安装后 `qq-dump-db` 入口。
3. 实现 `--output-dir`、`--lang auto|zh-CN|en-US`、`--no-wait`、`--version`。
4. 默认输出统一到 `./output/<QQ号>/`；新 key map 使用 Schema v1 和 UTC 时间。
5. 实现原子写入、解密临时文件验证、目标文件名冲突保护和稳定错误码。
6. Python CLI 与 `read_db.py` 支持简体中文和英文；两套文案目录的 Message ID 保持一致。
7. 默认等待目标 QQ 进程退出，允许等待期间按 Enter 提前继续；跳过等待时提示 WAL 风险。

仍待后续 C++ 阶段落实：

- C++ CLI 的 `--output-dir`、`--lang`、`--no-wait`、`--version` 和严格参数校验。
- C++ 的 Schema v1 UTC JSON 写入、原子文件写入和解密结果验证。
- C++ 与 Python 的统一错误码、退出码、路径处理及跨语言契约测试。

## 4. 本阶段边界

- 第二阶段只拆分和改造 Python 实现；`main.cpp` 与 CMake 源码未在本阶段重构。
- SQLCipher 算法参数和现有内存扫描算法保持不变。
- 不引入 Python/C++ 互操作层。
- 当前 Python 国际化只支持简体中文（`zh-CN`）和英文（`en-US`），`auto` 仅为自动选择模式。
