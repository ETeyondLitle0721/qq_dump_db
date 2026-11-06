# qq_dump_db

一个面向 Windows 的本地数据库工具，提供 C++ 和 Python 两种实现。仅用于处理你本人拥有或已获授权访问的 QQ 账号及本地数据。

## 实现版本

- **C++**：模块化原生实现，入口保留在根目录 `main.cpp`，模块位于 `cpp/src/` 和 `cpp/include/`。
- **Python**：模块化 Package 位于 `python/qq_dump_db/`；根目录 `dump_qq_key_auto.py` 保留为兼容启动入口。

Python CLI 只支持简体中文和英文（`zh-CN`、`en-US`）。切换语言不会改变 JSON 字段、CLI 参数名、错误 ID 或退出码。数据库查看工具 `read_db.py` 同样支持 `--lang zh-CN|en-US|auto`。

## Python 安装

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e .
```

运行方式：

```powershell
qq-dump-db --qq <QQ号> --lang zh-CN
python dump_qq_key_auto.py --qq <QQ号> --lang en-US
python -m qq_dump_db --qq <QQ号> --lang auto
```

若未安装 Package，可直接使用兼容入口。Windows 进程访问权限不足时，请使用具有相应权限的终端。

## Python 参数

```text
--qq <QQ号>              必需，目标账号
--pid <PID>              可选，诊断用途的扫描 PID 覆盖
--db-dir <目录>          可选，手动指定账号数据库目录
-o, --output <路径>      密钥 JSON 路径（相对路径以输出目录为基准）
--output-dir <目录>      输出根目录（默认 ./output/<QQ号>）
--lang <auto|zh-CN|en-US>
--no-wait                跳过等待 QQ 退出，直接重新读取数据库文件
-h, --help               显示帮助
--version                显示版本
```

默认会提示关闭目标 QQ，并等待所选进程退出后重新发现数据库文件。等待期间按 Enter 可提前继续，也可以使用 `--no-wait`；这两种方式都可能在 WAL 尚未 checkpoint 时产生不完整的数据库视图。

## 语言选择

1. 显式 `--lang zh-CN` 或 `--lang en-US`。
2. 环境变量 `QQ_DUMP_DB_LANG`（仅接受 `zh-CN`、`en-US`）。
3. 检测 Windows UI 语言或系统 locale，并映射为中文或英文。
4. 默认回退到 `zh-CN`。

## 数据库查看工具

```powershell
python read_db.py --qq <QQ号> --lang zh-CN
python read_db.py --qq <QQ号> --lang en-US --db nt_msg.db
```

## 输出文件

默认输出到：

```text
./output/<QQ号>/
    key_map.json
    <解密后的数据库文件>
```

新生成的 key map 使用 `schema_version: 1`，`_generated` 为 UTC 时间。该文件包含敏感的数据库解密密钥，请妥善保管，不要提交到 Git 或公开分享。

## 项目结构

```text
main.cpp                         C++ 极简程序入口
cpp/include/qq_dump_db/          C++ 模块接口
cpp/src/                         C++ 模块实现
  cli.cpp / i18n/                 CLI 与中文/英文文案
  platform/win32/                 Win32 进程、句柄和内存 API
  discovery/                      QQ 实例及数据库发现
  crypto/                         SQLCipher 密钥验证
  services/                       工作流、等待、JSON 输出及解密
python/qq_dump_db/                模块化 Python 实现
shared/                           跨语言 CLI / JSON / 工作流规范
```

## 依赖

Python 依赖 `cryptography`。源码交付包按要求不包含 `third_party/`。C++ 使用 Windows API、Windows BCrypt，以及单独安装的 SQLite（例如通过 vcpkg）。

## C++ 构建

先通过 vcpkg 安装 SQLite：

```powershell
vcpkg install sqlite3:x64-windows
cmake -B build -A x64 -DCMAKE_TOOLCHAIN_FILE="$env:VCPKG_INSTALLATION_ROOT/scripts/buildsystems/vcpkg.cmake"
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
```

C++ CLI 同样支持 `--lang zh-CN|en-US|auto`、`--output-dir` 和 `--no-wait`。`--output` 的相对路径相对于最终输出目录；默认输出为 `./output/<QQ号>/`。

## 测试

```powershell
python -m pip install -e .
python -m unittest discover -s tests/python -v
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
```

跨语言规范见 [`shared/`](shared/README.md)。

## 许可证

MIT。原项目：https://github.com/NapNeko/qq_dump_db
