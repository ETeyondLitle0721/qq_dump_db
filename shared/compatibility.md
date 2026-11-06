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

## 3. 需要在后续实现中修改的明确事项

1. Python：统一输出根目录、实现等待关闭 QQ 的交互流程，并在等待后重新发现数据库。
2. C++：完善 CLI 参数校验和 `--help` / `--version`；输出 JSON 增加 `schema_version` 并改用 UTC。
3. 两端：实现 `--output-dir`、`--lang`、`--no-wait`；统一 `-o` 相对路径规则。
4. 两端：解密文件先写临时文件，再执行 SQLite 验证，成功后原子替换。
5. 两端：检测同名解密目标，禁止静默覆盖。
6. 两端：统一错误 ID、退出码和 stdout/stderr 归属。

## 4. 本阶段不做的事情

- 不移动或重写现有 Python/C++ 业务函数。
- 不改变 SQLCipher 算法参数或内存扫描实现。
- 不引入 Python/C++ 互操作层。
- 不在本阶段完成翻译文案；这里只确定 `--lang` 接口及语言选择规则。
