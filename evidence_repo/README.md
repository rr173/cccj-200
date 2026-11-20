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
│   ├── release_rules.py       # 发布请求/受众规则严格校验（版本化 JSONL、错误分层）
│   ├── redaction.py           # UTF-8 字节坐标遮盖（分块、字符边界、长度/哈希核对）
│   ├── release_plan.py        # 馆内计划（sealed 视图、按内容统一落实、内容寻址）
│   ├── release_publish.py     # 批准后发布（陈旧拒绝、互斥、原子一次性交付）
│   ├── verify_release.py      # 外发目录离线校验器（只认公开格式，不 import 仓内模块）
│   ├── format_catalog.py      # 格式签名目录严格校验与登记（版本化 JSONL、整份事务）
│   ├── format_profile.py      # 封存对象格式画像（区域分块扫描、不可变结果、绑定校验）
│   ├── verify_profile.py      # 画像结果离线校验器（不重跑匹配，不 import 仓内模块）
│   └── cli.py                 # 命令行入口
└── tests/
    ├── fixtures.py            # 合成交接包构造器（不受信输入数据）
    ├── demo_main.py           # 主演练（含人工 AND/OR 图与预期摘要表）
    ├── demo_edges.py          # 边界场景（41 项断言）
    ├── demo_memory.py         # 大成员内存/分块 I/O 测量
    ├── demo_scale.py          # 路径规模与落盘求值内存测量
    ├── demo_reconcile.py      # 预期馆藏对账验收（17 场景、86 项断言）
    ├── demo_reconcile_scale.py# 歧义双路线一致性 + 大图规模测试
    ├── demo_release_main.py   # 离线发布主演练（A馆B、别名并集、staging、陈旧重做）
    ├── demo_release_edges.py  # 发布边界（字符边界/错误分层/并发/中断/注入等 60 项）
    ├── demo_release_scale.py  # 大文件跨块遮盖 + 大量别名/区间的规模与内存
    ├── demo_format_profile.py # 格式画像验收（独立 oracle + 人工表，87 项断言）
    └── demo_format_profile_scale.py # 大载荷跨块扫描 + 格式/别名规模与内存
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
python3 -I tests/demo_release_main.py    # 离线发布主例（A馆B -> A****、staging、陈旧重做）
python3 -I tests/demo_release_edges.py   # 发布边界（60 项：错误分层/字符边界/并发/中断/注入）
python3 -I tests/demo_release_scale.py   # 64 MiB 跨块遮盖 + 2000 别名规模与峰值内存
python3 -I tests/demo_format_profile.py  # 格式画像验收（独立 oracle + 人工表，87 项）
python3 -I tests/demo_format_profile_scale.py  # 64 MiB 跨块扫描 + 2000 别名/300 格式内存
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

# 离线发布（馆内计划 -> 批准后发布 -> 外发目录离线校验）
python3 -m evidrepo.cli release-plan <repo> <request.jsonl> <rules.jsonl>
python3 -m evidrepo.cli release-plans <repo>
python3 -m evidrepo.cli release-show <repo> <plan_id>
python3 -m evidrepo.cli release-publish <repo> <plan_id> <new_target_dir>
python3 -m evidrepo.cli release-verify <release_dir>   # 可在搬离仓库后运行
python3 -m evidrepo.cli release-deliveries <repo>

# 格式画像（目录登记 -> 启动画像 -> 查看结果 -> 绑定/离线校验）
python3 -m evidrepo.cli catalog-register <repo> <catalog.jsonl>
python3 -m evidrepo.cli catalogs <repo>
python3 -m evidrepo.cli catalog-show <repo> <catalog_id> <catalog_version>
python3 -m evidrepo.cli profile-run <repo> <catalog_id> <catalog_version> (--packages P1,P2 | --all-sealed)
python3 -m evidrepo.cli profiles <repo>
python3 -m evidrepo.cli profile-show <repo> <profile_id>
python3 -m evidrepo.cli profile-check-binding <repo> <profile_id>
python3 -m evidrepo.cli profile-verify <profile.json>  # 可在搬离仓库后运行
```

## 离线发布（offline release，profile §15）

把封存馆藏按受众规则转成可直接交给阅览室的副本目录，原件与既有证明仍留馆内。

- **两个版本化输入**：发布请求 `release-request/v1`（受众 + 按精确
  `(identifierType, identifierValue)` 选表示 + 人工批准的 ASCII 安全外部代号）
  与受众规则 `release-rules/v1`（按 bitstream 身份给 release/hold/redact；
  redact 绑定原件 SHA-256 与原始 UTF-8 字节半开区间）。
- **错误分层**：语法/版本/重复/冲突/非法区间/未知动作是**计划失败**
  （整份拒绝，退出码 2）；缺规则与 hold 是**业务暂缓**（计划照常生成、
  逐项记原因）；遮盖无法成立记为 blocked，阻止可发布结果并定位失败对象。
- **按内容统一落实**：对计划涉及的每个内容摘要，纳入 sealed 视图中所有
  关联该摘要的 bytes_ok 身份（含未选表示别名）。任一别名缺规则/hold，
  内容整体暂缓；否则取全部 redact 区间并集，生成一份共同遮盖副本；全部
  release 才放行原字节。
- **遮盖**：先逐条校验区间非空、未越界、两端在 UTF-8 字符边界（被覆盖的
  非法区间也会被发现），再以等量 `*` 替换并集；分块执行，跨块字符/区间
  正确；发布时实际重算长度与 SHA-256。
- **交付顺序**：发布只认确认的 plan_id 并复核 sealed 包集合；交付前有新包
  封存即判陈旧拒绝。临时目录构建 + 写事务内复核 + 一次性原子改名；中断后
  正式路径只能不存在或完整可校验；目标已存在则保留，同路径并发最多一个成功。
- **最小披露**：外发目录仅 `release-manifest.json` + `payloads/f-<64hex>.bin`；
  清单只用外部代号、生成文件名和**交付字节**的 length/sha256，不含馆内
  身份、路径、原件摘要（作为文件名）、规则、原因、XML、事件、证明或计划。
  生成文件名是 plan_id 键控的 HMAC，不取自馆内身份或原件摘要。
- **离线校验**：`release-verify` 不 import 仓内模块，搬离仓库后只按公开
  格式校验引用、文件集合与实际字节，拒绝多余/缺失文件、路径逃逸、符号链接
  与摘要错误；规则是否落实由馆内独立验收判断。

## 格式画像（format profiling，profile §16）

回答“**仓里有哪些文件格式、判断依据是什么、哪些对象需要人工识别**”。
画像用于保存与盘点：不做格式转换，也不改变对象身份、谱系结论或对外
发布许可。

- **版本化目录**：`format-catalog/v1` JSONL。头记录给 `catalog_id` +
  `catalog_version`；每条格式一行（稳定标识 + 可读名称）；每条签名
  一行（多个必需字节片段 + 可选禁止片段）。片段支持固定偏移或有限
  搜索窗口（≤ 1 MiB 跨度）与逐字节掩码。严格校验（头/版本/字段类型/
  十六进制/偏移边界/掩码长度/重复标识），任一行错误整份拒绝；目录
  行序与片段顺序不影响规范化内容摘要。
- **范围与身份**：只纳入指定封存包集合中的 bitstream 身份（staging
  不得进入）；按精确 `(identifierType, identifierValue)` 展开——
  跨包重复声明只记一次，同字节不同身份分别列出，表示/结构节点不计入。
  画像前重新读取封存载荷并核对长度与 SHA-256；缺失、损坏、身份冲突
  不被签名命中掩盖，逐项给出状态与逐副本出处。
- **匹配语义**：求出**所有**完整命中的签名。无命中 `unidentified`；
  全部命中同一格式 `identified`（保留全部命中签名）；命中多个格式
  `ambiguous`（绝不按目录顺序或首个命中静默挑选）。证据逐条指出
  签名、片段偏移与匹配字节。汇总按精确身份去重：各格式对象数 +
  identified/ambiguous/unidentified/无效字节/身份冲突数。
- **不可变结果**：绑定规范化目录摘要、实际封存包集合及其清单摘要；
  `profile_id` 内容寻址；相同输入复跑得到相同结果与稳定标识；新增
  封包/新目录版本不改写旧结果。`profile-check-binding` 区分“当前
  画像”与“历史画像”（旧结果仍可校验，但不能冒充当前仓画像）。
- **离线校验**：`profile-verify` 不 import 仓内模块、不重跑格式
  匹配，只核对内容摘要、绑定信息与汇总/证据结构自洽；结果文件可
  搬出仓库校验。
- **资源边界**：按片段区域分块读取（区域 ≤ 窗口跨度 + 片段长度，
  单次 read ≤ 1 MiB），掩码编译为等价字节正则；允许按内容摘要复用
  扫描，但每个身份独立写入、每次运行重新验证字节来源与绑定。
  实测：64 MiB 载荷扫描峰值约 2 MiB；2000 别名 + 300 格式峰值约
  27 MiB。

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
