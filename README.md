# qq_dump_db

> 在极为安全的情况下，自动提取并解密 NTQQ 的 SQLCipher 数据库。

## Why

NTQQ 将聊天记录等数据保存在本地 SQLCipher 加密数据库中，密钥仅存在于进程内存里，用户无法直接导出自己的数据。
本工具让你能够 **拿回属于你自己的聊天记录**。

## 原理

程序要求目标 QQ 正在运行。数据库目录不再通过 `%USERPROFILE%\Documents\Tencent Files` 推测：程序使用 `NtQuerySystemInformation(SystemExtendedHandleInformation)` 枚举系统句柄，只筛选 QQ 进程持有的文件句柄，再通过 `DuplicateHandle` 与 `GetFinalPathNameByHandleW` 定位实际打开的 `nt_msg.db`。随后从该路径推导账号数据库目录及同级的全局数据库目录。

如果找不到正在打开的 `nt_msg.db`，或者同时发现多个无法与 `--qq` 参数关联的账号路径，程序会明确报错，不会回退到固定目录。`--db-dir` 仍可用于手动指定数据库目录。

找到数据库后，程序读取数据库页头部的 salt，并在 `wrapper.node` 主进程的可读内存区域中查找与该 salt 对应的密钥模式；随后通过 PBKDF2-SHA512、AES-256-CBC 和 HMAC-SHA1 完成数据库页解密与校验。

## 为什么安全

| 特性 | 说明 |
|---|---|
| **无注入** | 全程不 inject 任何 DLL 到 QQ 进程 |
| **无 Hook** | 不修改 QQ 的任何函数或内存 |
| **纯外部读取** | 仅使用 `OpenProcess` + `ReadProcessMemory`，属于外部进程调用系统内核的行为 |
| **极短暴露窗口** | 扫描耗时 1-2 秒，随用随走 |

NTQQ 即使 hook 自身的这些 API 也无法检测到外部进程的调用。除非对所有进程进行注入检测或采用更高权限的内核级方案，这在实践中极为困难。即便存在进程名识别，随机命名即可规避。

## 使用方式

### C++ 版（推荐，无额外依赖）

```bash
qq_dump_db.exe --qq <QQ号>
qq_dump_db.exe --qq <QQ号> --pid <PID>       # 可选：手动指定进程 PID
qq_dump_db.exe --qq <QQ号> --db-dir <目录>   # 可选：手动指定 db 搜索目录
```

### Python 版

```bash
pip install cryptography
python dump_qq_key_auto.py --qq <QQ号>
python dump_qq_key_auto.py --qq <QQ号> --db-dir <数据库目录>
```

自动句柄枚举依赖 Windows Native API，建议使用 64 位 Python 和 64 位程序构建。进程访问权限不足时，请使用有权访问目标 QQ 进程的 Windows 账户运行。

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