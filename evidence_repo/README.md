# 离线保存证据仓（offline preservation evidence repository）

读取交接包中的 METS 结构、PREMIS 3 对象/事件与包内二进制，回答：
**“这份表示是否有完整可信的原件路径，哪项证据缺失？”**

它是交接数据质量与谱系功能：不做格式转换、杀毒、数字签名认证或内容相似匹配。

## 目录结构

```
evidence_repo/
├── profile.md                 # 明确 profile：逐元素映射、信任模型、状态语义
├── evidrepo/                  # 实现（仅依赖 Python 3.11 标准库 + SQLite）
│   ├── util.py                # 分块哈希、路径逃逸防护、C14N、身份键
│   ├── db.py                  # SQLite schema（全量落盘，staging/sealed 隔离）
│   ├── parser.py              # METS/PREMIS 解析（只映射 profile 元素）
│   ├── ingest.py              # 接包/暂存/恢复/封包（事务化、分块复制）
│   ├── evaluate.py            # 冲突检测 + 半朴素增量不动点证明求值
│   ├── diagnostics.py         # AND/OR 依赖解释、representation 多原因诊断
│   ├── export.py              # 证明子包导出（稳定选路、共享证据只存一次）
│   ├── synthetic_xml.py       # 导出子包内的合成 PREMIS/METS + 元素映射
│   ├── verify_export.py       # 独立验证器（仅标准库，不复用求值器）
│   └── cli.py                 # 命令行入口
└── tests/
    ├── fixtures.py            # 合成交接包构造器（不受信输入数据）
    ├── demo_main.py           # 主演练（含人工 AND/OR 图与预期摘要表）
    ├── demo_edges.py          # 边界场景（34 项断言）
    ├── demo_memory.py         # 大成员内存/分块 I/O 测量
    └── demo_scale.py          # 路径规模与落盘求值内存测量
```

## 快速运行

所有脚本以隔离模式运行（`-I`，不读取环境中的站点包/当前目录模块）：

```bash
cd /workspace/evidence_repo
python3 -I tests/demo_main.py     # 主演练：A+B 共同迁移 C、循环支路、failed、OR 恢复
python3 -I tests/demo_edges.py    # 边界：跨包、身份冲突、逃逸、晚到包、不可变证明等
python3 -I tests/demo_memory.py   # 256 MiB 成员内存测量（峰值约 2 MiB）
python3 -I tests/demo_scale.py    # 2000 节点长链：存活内存不随路径数增长
```

## CLI 用法

```bash
python3 -m evidrepo.cli init <repo>
python3 -m evidrepo.cli receive <repo> <package_dir> [--resume]
python3 -m evidrepo.cli finish <repo> <package_id>
python3 -m evidrepo.cli packages <repo>
python3 -m evidrepo.cli object <repo> <id_type> <id_value>
python3 -m evidrepo.cli rep <repo> <id_type> <id_value>
python3 -m evidrepo.cli reps <repo>
python3 -m evidrepo.cli node <repo> <node_id>
python3 -m evidrepo.cli export <repo> (--node <node_id> | --id-type T --id-value V) [--out DIR]
python3 -m evidrepo.cli verify <export_dir>
python3 -m evidrepo.cli proofs <repo>
python3 -m evidrepo.cli check-store <repo>
```

## 核心设计要点

1. **信任起点来自 manifest**：受信 ingest 事件名单由调用者给定，
   程序不凭 `eventType` 自行信任。
2. **身份 = identifierType + identifierValue**：不按文件名或摘要合并；
   字节相同但 ID 不同仍是两个对象；一个 bitstream 被多节点引用不复制身份。
3. **AND/OR 语义**：一个事件的全部输入是共同前提（AND）；同一对象的多条
   产出路径任选其一（OR）。循环支路不能自证，也不否决独立好路径。
4. **staging/sealed 隔离**：未完成包的记录不进入任何可查询事实。
5. **多原因并列**：verified/incomplete/invalid/unproven 各状态的具体原因
   逐项列出，不合成单一“失败”。
6. **旧证明不可变**：证明号绑定导出当时的包集合；迟到原件只影响新查询。
7. **可移动、可独立验证**：仓内全相对路径；导出子包自包含，验证器重算
   哈希并重做无环 DFS，不复用正式状态求值器。
8. **资源边界**：二进制 1 MiB 分块流式处理；图与求值落盘，内存不随
   二进制大小或路径数增长。
