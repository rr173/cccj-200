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
│   ├── inventory.py           # 预期馆藏清单导入（流式校验、整份事务、独立存储）
│   ├── reconcile.py           # 预期馆藏对账（最大匹配 + 歧义语义 + 不可变报告）
│   └── cli.py                 # 命令行入口
└── tests/
    ├── fixtures.py            # 合成交接包构造器（不受信输入数据）
    ├── demo_main.py           # 主演练（含人工 AND/OR 图与预期摘要表）
    ├── demo_edges.py          # 边界场景（41 项断言）
    ├── demo_memory.py         # 大成员内存/分块 I/O 测量
    ├── demo_scale.py          # 路径规模与落盘求值内存测量
    ├── demo_reconcile.py      # 预期馆藏对账验收（17 场景、86 项断言）
    └── demo_reconcile_scale.py# 歧义双路线一致性 + 大图规模测试
```

## 快速运行

所有脚本以隔离模式运行（`-I`，不读取环境中的站点包/当前目录模块）：

```bash
cd /workspace/evidence_repo
python3 -I tests/demo_main.py     # 主演练：A+B 共同迁移 C、循环支路、failed、OR 恢复
python3 -I tests/demo_edges.py    # 边界：跨包、身份冲突、逃逸、晚到包、不可变证明等
python3 -I tests/demo_memory.py   # 256 MiB 成员内存测量（峰值约 2 MiB）
python3 -I tests/demo_scale.py    # 2000 节点长链：存活内存不随路径数增长
python3 -I tests/demo_reconcile.py       # 预期馆藏对账（17 场景）
python3 -I tests/demo_reconcile_scale.py # 歧义双路线一致 + 大图有界内存
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
python3 -m evidrepo.cli inventory-import <repo> <list.jsonl>
python3 -m evidrepo.cli inventories <repo>
python3 -m evidrepo.cli inventory-show <repo> <inventory_id>
python3 -m evidrepo.cli reconcile <repo> <inventory_id>
python3 -m evidrepo.cli reports <repo> [--inventory <inventory_id>]
python3 -m evidrepo.cli report <repo> <report_id>
python3 -m evidrepo.cli verify-report <report.json>
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

## 预期馆藏对账（expected-inventory reconciliation）

回答的是**另一个问题**：*本批预期交付由哪些实际表示承担？*
它不替代字节完整性、来源谱系判定或证明子包导出。

1. **清单独立于谱系**：导入的清单落在 `inventories` / `inventory_obligations`
   / `inventory_acceptable` 三张表，绝不写入 `objects` / `events` / 求值图，
   也不改变 `obj_status`。清单不是 PREMIS object。
2. **导入整份接受或整份拒绝**：UTF-8 JSONL、逐行流式校验（单行 ≤ 1 MiB）、
   拒绝 BOM/非法编码/字段类型错误/重复 item-obligation-候选/控制字符；
   任一行失败即回滚，不会留下可参与对账的半份预期数据。保留来源行号与
   原始清单 SHA-256，并保存校验通过的原始副本供争议定位。
3. **身份精确匹配**：只有 `identifierType + identifierValue` 有序二元组
   精确相等才连边；不按显示名、文件名、摘要或部分匹配。
4. **实际侧只数 sealed 表示**：staging 包、bitstream 对象、METS 结构节点、
   同一表示在多个包中的重复提及都不增加候选（按身份去重）。
5. **最大一对一分配**：义务与实际表示构成二分图，求最大匹配（Hopcroft–Karp）。
   不同义务候选可重叠，但一个实际身份最多分配给一个义务。
6. **稳定展示 vs 全部最大分配都成立的事实**：报告同时给出**一组稳定分配**，
   并用“交替路径可达 + 强连通分量”标出哪些义务与分配边在不同最大分配中
   会改变（`ambiguous_obligations` / `ambiguous_edges`），绝不把任意一次
   匹配伪装成唯一事实。该路线与“逐边强制/排除后重解最大匹配”等价
   （`demo_reconcile_scale.py` 对随机图逐边核对两条路线一致）。
7. **未满足须有原因**：逐项给出候选的 *缺失 / 已被其他义务占用 / 身份冲突*
   状态，不合成单一“失败”。
8. **质量不提升**：已分配表示附 `package_id` 与既有质量标签及原因
   （`verified|incomplete|invalid|unproven`）；`bytes_missing`、`unproven`、
   `invalid` 的表示仍可匹配为“已出现”，但原样保留诊断，绝不被对账提升为
   `verified`。
9. **身份事实冲突不择一**：同一表示身份若在 sealed 事实中类别不一致、
   成员集合不一致或字节身份冲突，报告列出全部相关包并置 `package_id=null`。
10. **额外表示**：列出清单未预期（不在任何义务候选内）、且未被分配的
    sealed 表示身份。
11. **不可变报告 + 输入绑定**：报告只增不改，`report_id` 即内容寻址；
    绑定清单 SHA-256、执行时纳入的 sealed 包集合及其哈希。清单导入后新增
    或迟到包封存时旧报告不变，重新对账产生新报告。
12. **重复运行稳定**：相同清单 + 相同 sealed 包集合 → 相同业务结果与相同
    `report_id`（复用既有报告）；分配不依赖清单行序。
13. **可搬迁、可独立校验**：`verify-report` 重算内容哈希与包集合哈希，
    报告内部无绝对路径，整份文件可搬到任意目录后校验。

### 清单格式（UTF-8 JSONL）

```jsonl
{"record_type":"inventory_header","format_version":"expected-inventory/v1","inventory_id":"batch-2026-11","batch_note":"季度提交"}
{"record_type":"obligation","inventory_id":"batch-2026-11","item_id":"ITEM-1","obligation_id":"OBL-1","note":"主本","acceptable_representations":[{"identifierType":"local","identifierValue":"REP-A"},{"identifierType":"uuid","identifierValue":"..."}]}
{"record_type":"obligation","item_id":"ITEM-1","obligation_id":"OBL-2","acceptable_representations":[{"identifierType":"local","identifierValue":"REP-B"}]}
```

- 首行为头记录；其后每行一条义务。`item_id` 可出现在多行（一项可有多条义务）。
- `obligation_id` 全局唯一；同一义务内候选身份不得重复。
- 行内 `inventory_id` 可省略；若给出须与头记录一致。

### 报告结构（要点）

`summary` 汇总 `obligation_total / satisfied / unsatisfied / ambiguous / extra`
以及 `always_satisfied`、`ambiguous_edges`、`identity_conflicts`、
`maximum_matching_size`、`actual_representation_identities`。
`assignments[]` 为稳定分配（含 `stable_across_all_maximum_assignments`）；
`unsatisfied_obligations[]` 含逐候选原因码与状态；`ambiguous_obligations[]`
与 `ambiguous_edges[]` 标注可变化的义务与边；`extra_representations[]`
列出清单未预期的 sealed 表示；`inputs` 绑定清单哈希与 sealed 包集合快照。
