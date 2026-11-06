# qq_dump_db

> 在极为安全的情况下，自动提取并解密 NTQQ 的 SQLCipher 数据库。

## Why

NTQQ 将聊天记录等数据保存在本地 SQLCipher 加密数据库中，密钥仅存在于进程内存里，用户无法直接导出自己的数据。
本工具让你能够 **拿回属于你自己的聊天记录**。

## 原理

程序要求目标 QQ 正在运行。数据库目录不再通过 `%USERPROFILE%\Documents\Tencent Files` 推测：程序使用 `NtQuerySystemInformation(SystemExtendedHandleInformation)` 枚举系统句柄，只筛选 QQ 进程持有的文件句柄，再通过 `DuplicateHandle` 与 `GetFinalPathNameByHandleW` 定位实际打开的 `nt_msg.db`。随后从该路径推导账号数据库目录及同级的全局数据库目录。

如果找不到正在打开的 `nt_msg.db`，或者同时发现多个无法与 `--qq` 参数关联的账号路径，程序会明确报错，不会回退到固定目录。`--db-dir` 仍可用于手动指定数据库目录。

程序还会保留系统句柄表中的“句柄所有者 PID + nt_msg.db 完整路径”这一对应关系，从路径的 `Tencent Files/<QQ号>/nt_qq/nt_db/nt_msg.db` 结构解析 QQ 号，再通过 QQ.exe 的父子进程关系，将句柄所有者关联到加载 `wrapper.node` 的进程。启动时会打印 `PID -> QQ号` 映射；默认只扫描与 `--qq` 匹配的 wrapper.node 进程，不再依赖进程枚举顺序。若文件句柄所有者与 wrapper.node 进程之间无法建立唯一关系，程序会明确报错，不会猜测。

找到数据库后，程序读取数据库页头部的 salt，并扫描与目标账号匹配的 wrapper.node 进程。内存按 4 MiB 分块读取，并保留跨块重叠，避免密钥字符串正好位于读取边界时漏检。对于每个数据库 salt，程序会保留不同的 Key 候选，再逐个使用数据库第一页的 HMAC 验证；只有验证成功的候选才会写入 `key_map.json`。

## 为什么安全

| 特性 | 说明 |
|---|---|
| **无注入** | 全程不 inject 任何 DLL 到 QQ 进程 |
| **无 Hook** | 不修改 QQ 的任何函数或内存 |
| **纯外部读取** | 仅使用 `OpenProcess` + `ReadProcessMemory`，属于外部进程调用系统内核的行为 |
| **结果校验** | 只有通过数据库第一页 HMAC 校验的候选密钥才会写入结果 |

扫描时间取决于 QQ 进程数量、进程工作集和系统负载；工具不会修改 QQ 进程中的代码或数据。

## 使用方式

### C++ 版（推荐，无额外依赖）

```bash
qq_dump_db.exe --qq <QQ号>
qq_dump_db.exe --qq <QQ号> --pid <PID>       # 可选：显式覆盖自动映射（诊断用）
qq_dump_db.exe --qq <QQ号> --db-dir <目录>   # 可选：手动指定 db 搜索目录
```

### Python 版

```bash
pip install cryptography
python dump_qq_key_auto.py --qq <QQ号>
python dump_qq_key_auto.py --qq <QQ号> --db-dir <数据库目录>
python dump_qq_key_auto.py --qq <QQ号> --pid <PID>  # 可选：显式覆盖自动映射（诊断用）
```

自动句柄枚举依赖 Windows Native API，建议使用 64 位 Python 和 64 位程序构建。默认通过 `nt_msg.db` 文件句柄映射 PID 与 QQ 号，只扫描 `--qq` 对应的 wrapper.node 进程；`--pid` 用于人工覆盖自动选择（会显示映射不一致警告）。如果句柄持有者不是 wrapper.node 进程，程序会尝试通过 QQ.exe 父子进程关系关联；关系不唯一时不会猜测。进程访问权限不足时，程序会提示并跳过无法读取的进程。

解密后的数据库文件将输出到 `output/<QQ号>/` 目录。

## 构建

```bash
cmake -B build -A x64
cmake --build build --config Release
```

生成的可执行文件位于 `build/Release/qq_dump_db.exe`。

## License

MIT

转载或引用请注明来源：[https://github.com/NapNeko/qq_dump_db](https://github.com/NapNeko/qq_dump_db)
## 开发与维护规范

Python 与 C++ 两种实现的命令行参数、输出格式、错误码和处理流程统一定义在 [`shared/`](shared/README.md) 中。开始拆分或修改实现前，请先阅读该目录下的规范；跨语言验收项见 [`shared/contract-tests.md`](shared/contract-tests.md)。
