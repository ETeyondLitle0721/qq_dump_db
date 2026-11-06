# Shared contracts（第一阶段规范）

本目录定义 `dump_qq_key_auto.py`（Python）与 `main.cpp`（C++）共同遵循的外部行为规范。两种实现可以有不同的内部结构，但不得自行改变命令行语义、输出文件布局、JSON 格式、错误分类或处理阶段顺序。

## 规范文件

- [CLI 契约](cli-contract.md)：参数、默认值、路径解释和语言选择。
- [Key map JSON Schema](key-map.schema.json)：版本化的密钥映射输出格式。
- [错误码](error-codes.md)：稳定的进程退出码和诊断规则。
- [统一工作流](workflow.md)：Python/C++ 应遵循的阶段顺序和失败处理。
- [兼容性与迁移记录](compatibility.md)：现有实现差异、迁移约束及向后兼容要求。
- [契约测试清单](contract-tests.md)：后续拆分和实现时必须通过的验证项。

## 规范状态

- 规范版本：`1.0.0`
- 状态：**规范已确定；Python 第二阶段已部分落实，C++ 实现待迁移**
- 适用范围：Python CLI、C++ CLI，以及由它们生成的文件
- Python 已实现模块化结构、中英文界面、CLI 扩展、Schema v1 输出和重新发现流程；C++ 仍需按本规范迁移

## 核心原则

1. Python 与 C++ 是两套独立实现，不通过运行时互相调用。
2. 对外行为以本目录规范为准；源代码中的既有差异不构成规范。
3. `key_map.json` 是敏感凭据文件；不得把密钥内容写入普通日志、测试报告或版本控制。
4. 只有通过数据库页头 HMAC 校验的密钥候选才可以进入 `key_map`。
5. 旧版 JSON 可以被兼容读取；新版本只写入 Schema v1。
