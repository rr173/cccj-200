# 离线保存证据仓 Profile（offline-evidence-repo/v1）

本 profile 严格界定系统**能解释为证据**的 XML 元素。任何未列出的元素一律
原样保存为 `uninterpreted`，**不得猜测为证明**。系统不做格式转换、杀毒、
数字签名认证或内容相似匹配。

## 1. 命名空间

| 前缀 | URI |
| --- | --- |
| premis | `http://www.loc.gov/premis/v3`（PREMIS 3） |
| mets | `http://www.loc.gov/METS/` |
| xlink | `http://www.w3.org/1999/xlink` |

## 2. 信任起点（调用者给定，程序不自行推断）

每个交接包的 `manifest.json` 是唯一信任起点，必须声明：

- `package_id`
- `xml[]`：XML 文档的包内相对路径与 kind（`mets` | `premis` | `other`）
- `members[]`：二进制成员的相对路径、长度 `size`、`sha256`，以及承载该字节的
  PREMIS 对象身份 `object.id_type` / `object.id_value`
- `representations[]`：每个表示的完整 bitstream 成员身份集合（允许引用别的
  已接收包提供的成员）、对应 METS `fileGrp`、结构节点
- `trusted_ingest_events[]`：可作为原始接收证据的 ingest 事件 ID 名单

程序**只**因 ingest 事件自身的 ID 出现在该名单中而信任其输出；
**绝不**因为 `eventType=ingest` 就自动信任。

## 3. PREMIS 3 元素映射

| PREMIS 元素 | 映射到 | 证据语义 |
| --- | --- | --- |
| `object/objectIdentifier/objectIdentifierType` | 对象身份分量 `id_type` | 身份，不按文件名/摘要合并 |
| `object/objectIdentifier/objectIdentifierValue` | 对象身份分量 `id_value` | 同上；身份键 = type + value |
| `object/objectCategory` | `bitstream` 或 `representation` | `file`/`bitstream` 均归 bitstream |
| `event/eventIdentifier/eventIdentifierValue` | 事件 ID | 同名事件按**事件元素规范化内容**判异 |
| `event/eventType` | `ingest` / `copy` / `migration` | 仅这三类参与证明；其他类型保留事实、永不作证据 |
| `event/eventDateTime` | 仅来源元数据 | **不**参与依赖或有效性判定 |
| `event/eventOutcomeInformation/eventOutcome` | `success`/`failed`/`unknown` | 仅 success 可作有效证据；非受控词按 unknown |
| `event/linkingObjectIdentifier` + `linkingObjectRole=input` | 事件输入（AND 共同前提） | 角色缺失/未知 → 整条存 uninterpreted，不按顺序猜 |
| `event/linkingObjectIdentifier` + `linkingObjectRole=output` | 事件输出 | 同上 |

未在表内的元素（如 `agent`、`rightsStatement`、其他角色的
`linkingObjectIdentifier`、非受控 outcome 细节）写入
`object_uninterpreted` / `event_uninterpreted` 表，保留原始 XML 文本。

## 4. METS 元素映射

| METS 元素 | 映射到 |
| --- | --- |
| `fileSec/fileGrp@ID` + `@ADMID`（指向 amdSec/mdWrap 内 PREMIS representation 对象） | 一个 representation |
| `fileSec/fileGrp/file/FLocat@xlink:href` | 表示成员的包内（或跨包成员）路径 |
| `file@ADMID`（指向 bitstream 的 PREMIS 对象） | 成员对象身份 |
| `structMap/div@ID`、`@LABEL` | 结构节点 |
| `structMap/div/fptr@FILEID` | 节点引用的唯一 `fileGrp`（即一个表示） |

结构节点**只引用表示**。同一 bitstream 被多个节点/多处展示时，
按对象身份去重，**绝不复制成多个身份或重复计数**。

## 5. 事件有效性规则

1. `eventType` ∈ {ingest, copy, migration}，且 `outcome=success`；
2. 事件 ID 无“同名异内容”冲突（逐事件 C14N 哈希一致；跨包重复记载同一事件合法）；
3. 全部带角色引用无悬空、无对象身份冲突；
4. 角色规则：
   - ingest：**无 input**，至少一个 output；且事件 ID 在调用者信任名单内；
   - copy/migration：**至少一个显式 input 与一个 output**，角色必须显式，
     不得按记录顺序猜测；
5. 同一事件的**全部输入是共同前提（AND）**，不是任选一个；
6. 所有输出都至少有一份通过完整性检查的字节（bytes_ok）。

`failed`/`unknown` 事件保留为事实，但不能证明其输出可信。

## 6. 冲突规则

- **事件冲突**：同一 `event_id` 的事件元素规范化内容不同 → 写入
  `event_conflicts`，该事件全部记录不可用作证据。
- **对象身份冲突**：同一对象身份（type+value）被不同实际字节（不同 SHA-256）
  占用 → 写入 `object_conflicts`，状态 `identity_conflict`，不能择一。
- 字节相同但对象 ID 不同：仍是**两个对象**，不按摘要合并。

## 7. bitstream 状态与 origin_proven

先判字节/身份状态（互斥）：

| 状态 | 含义 |
| --- | --- |
| `bytes_ok` | 至少一份接收字节的 SHA-256/长度与 manifest 声明一致 |
| `bytes_missing` | 已声明但无任何通过完整性检查的副本 |
| `bytes_corrupt` | 存在副本但哈希不符，且无 ok 副本 |
| `identity_conflict` | 同身份被不同实际字节占用 |
| `not_received` | 被引用但任何包都未承载其字节 |

再判 `origin_proven`：存在一棵**有限、无环**证明树，其根全部来自有效的
受信 ingest 事件，中间每个事件有效且其全部输入都已被证明。

- 一个输出可有多条替代路径（OR），任一条完整即可证明；
- 循环支路不能自证；坏支路不否决另一条独立好路径。

## 8. representation 标签（多原因逐项列出，不合成单一“失败”）

| 标签 | 条件 |
| --- | --- |
| `verified` | 声明成员全部 bytes_ok 且全部 origin_proven |
| `incomplete` | 有成员 bytes_missing/not_received，或存在未解释的必需角色 |
| `invalid` | 有成员 bytes_corrupt 或 identity_conflict |
| `unproven` | 成员字节齐全但至少一个无完整原件路径 |

优先级：invalid > incomplete > unproven > verified；但所有触发原因都保留在
`reasons[]` 中并列输出。

## 9. 包生命周期与可见性

- `staging`：接包暂存。staging 数据对所有事实查询/求值/导出**不可见**；
  接包是事务，profile 校验失败整体回滚。
- `sealed`：`finish` 封包后进入可查询事实集，并触发全库重算。
- 包不齐可暂存与 `--resume` 补迟到字节；中断重开不产生半条事实。
- 迟到原件可让**新查询**转为 verified，但**不能改写**已导出的旧证明。

## 10. 证明子包导出

- 仅含选中表示的全部成员 + **一条**完整证明所需原件、事件与原始 XML 出处；
- 共享证据只保留一次；不枚举全部来源路径；不导出无关表示；
- 路径选择稳定（事件按 ID 字典序取第一条全输入可证且无环的支路），
  不追求最小证明，但必须可独立验证；
- 证明号 `proof_no` 与内容寻址 `proof_id` 固定绑定导出当时的 sealed 包集合；
- 子包自包含：`proof.json` + `blobs/` + 原始 `xml/` + 随包 manifest +
  `synthetic/`（合成 PREMIS/METS 与 element-mapping.json）。

## 11. 独立验证器（不 import 求值器）

`verify_export` 仅用标准库：重算每个 blob 的 SHA-256、重新解析原始 XML、
从每个成员独立做有限无环 DFS、逐个核对每个事件的**全部输入**、
校验合成 METS 成员集合与 proof_id 内容绑定。

## 12. 存储与资源约束

- 仓内只存相对路径；整仓与导出目录移动后仍可校验（`check-store`）。
- 所有二进制按 1 MiB 分块流式读写；内存不随二进制大小增长。
  实测：256 MiB 成员全流程（接包→封包→导出→独立验证）Python 峰值约
  2.1 MiB、RSS 增量约 3 MiB，所有 read() 调用均不超过 1 MiB 块。
- 谱系图与求值结果落盘（SQLite）。求值用增量 BFS 不动点（每条依赖边只
  处理一次，O(边数)），存活状态不随路径数线性增长。实测 2000 事件 /
  4002 链接的长链全流程约 9 秒，RSS 增量随图规模次线性变化
  （10 倍图规模对应约 6 倍 RSS 增量，约 9.9 KiB/节点）。
- 已知边界：XML 文档用 ElementTree 按文档解析，单文档应保持可管理大小；
  超大 XML 应在交接前拆分为多个文档。这部分瞬时内存与单文档元素数相关，
  解析结束即可回收，不进入常驻的落盘图。

## 13. 明确非目标

格式转换、病毒/恶意软件查杀、数字签名/证书认证、内容相似性/近似重复匹配。

## 14. 预期馆藏对账（独立于 §2–§12 的谱系证据）

预期馆藏对账回答“本批预期交付由哪些实际表示承担”，**不是**证据判定，
不替代 §5–§8 的字节完整性与来源谱系结论，也不导出证明子包。

- **独立输入**：清单为 UTF-8 JSONL（`expected-inventory/v1`），只落入
  `inventories` / `inventory_obligations` / `inventory_acceptable`，
  绝不伪装成 PREMIS object、不进入 §5 求值图，也不改变 `obj_status`。
- **整份事务**：导入失败（编码/字段类型/重复 item-obligation-候选/
  身份组件边界/格式版本）整体回滚，不留半份预期数据；保留来源行号与
  原始清单 SHA-256 及校验通过的副本。
- **身份**：只有 `identifierType + identifierValue` 有序二元组精确相等
  才视为同一身份；不按显示名、文件名、摘要或部分匹配（与 §2“身份”一致）。
- **实际侧**：只统计 `sealed` 包中声明的 representation 身份；`staging`
  包、bitstream 对象、METS 结构节点、跨包重复提及均不增加候选（按身份去重）。
- **匹配**：义务—实际身份二分图上的最大一对一匹配。一个实际身份最多
  分配给一个义务；不同义务候选可重叠。
- **歧义语义**：报告给出一组稳定分配，并显式标出在**不同最大分配中会改变**
  的义务与边；不得把任意一次匹配当作唯一事实。该语义与“逐边强制/排除重算
  最大匹配”等价。
- **质量**：分配的表示附 `package_id` 与既有质量标签及原因（§8）；
  已收但 `bytes_missing` / `unproven` / `invalid` 仍可匹配为“已出现”，
  但绝不因对账被提升为 `verified`。
- **身份冲突**：同一 sealed 表示身份类别不一致、成员集合不一致或字节身份
  冲突时，不静默择一，作为冲突原因展示。
- **报告不变**：报告只增不改，`report_id` 内容寻址，绑定清单 SHA-256 与
  执行时的 sealed 包集合；相同清单与相同包集合重复执行得到相同业务结果；
  报告文件可搬迁并独立校验（`verify-report`），内部无绝对路径。

## 15. 离线发布（封存馆藏 -> 阅览室副本目录）

离线发布回答“**在给定受众规则下，哪些封存表示可以开放、哪些遮盖、哪些
暂缓，以及外发目录里到底应该出现哪些字节**”。它复用 §2–§8 的封存对象、
表示成员关系与字节索引，不改变任何谱系结论；原件与既有证明仍仅供馆内。

### 15.1 两个版本化输入（无 BOM 的 UTF-8 JSONL，逐行一个对象）

**发布请求 `release-request/v1`**：首行头记录，其后每行按精确
`(identifierType, identifierValue)` 选择一份表示，并显式给出经人工批准的
外部代号。

```jsonl
{"record_type":"release_header","format_version":"release-request/v1",
 "request_id":"REQ-1","audience":"reading-room-a"}
{"record_type":"representation_selection",
 "identifierType":"local","identifierValue":"REP-1",
 "external_code":"EXT-0001"}
```

- 头记录必填 `request_id`、`audience`；选择行必填 `identifierType`、
  `identifierValue`、`external_code`。
- 外部代号严格 ASCII 安全：`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`。
- 同一请求内表示身份不得重复、外部代号不得重复；违反即计划失败。

**受众规则 `release-rules/v1`**：首行头记录的 `audience` 必须与请求**精确
相等**；其后每行按 bitstream 身份给出**一个**动作。

```jsonl
{"record_type":"rules_header","format_version":"release-rules/v1",
 "rules_id":"RULES-1","audience":"reading-room-a"}
{"record_type":"rule",
 "bitstream":{"identifierType":"local","identifierValue":"BS-1"},
 "action":"release"}
{"record_type":"rule",
 "bitstream":{"identifierType":"local","identifierValue":"BS-2"},
 "action":"redact","content_sha256":"<64 个小写十六进制>",
 "ranges":[[1,4],[4,5]]}
{"record_type":"rule",
 "bitstream":{"identifierType":"local","identifierValue":"BS-3"},
 "action":"hold"}
```

- 受控动作仅 `release`（放行原字节）、`hold`（业务暂缓）、`redact`
  （按原始 UTF-8 字节半开区间遮盖）；未知动作即计划失败。
- `redact` 必须绑定原件 `content_sha256` 并给出**非空** `ranges`；
  `release`/`hold` 不得携带绑定摘要或区间。
- 区间 `[start,end)` 必须是两个非负整数且 `start < end`；同一规则内区间
  不得重复。内容相关的越界与字符边界校验在发布执行时按真实字节复核
  （§15.4），即使一条非法区间被有效区间完整覆盖也必须发现。
- 同一 bitstream 身份至多一条规则：重复身份即冲突规则，整份拒绝。

### 15.2 错误分层（业务暂缓 ≠ 计划失败）

- **计划失败（语法/约束错误，`ReleaseInputError`）**：编码（含 BOM、裸
  CR、非法 UTF-8）、非法 JSON、格式版本不符、字段缺失/类型错误、受控词
  越界、重复或冲突规则、重复外部代号、非法区间结构、受众不一致。整份输入
  拒绝，不产生馆内计划、不留半份数据。逐行流式校验，单行上限 1 MiB。
- **业务暂缓（计划照常生成）**：某 bitstream 身份在规则中**缺规则**，或
  被显式 `hold`。逐项记录原因码与规则来源行号，计划仍可用于其他对象。
- **遮盖不可成立（blocked）**：绑定摘要与封存字节不符、原件不是合法
  UTF-8、区间越界或端点不在字符边界。计划保留可审计记录并定位失败对象，
  但阻止产生任何可发布结果。

### 15.3 馆内计划（一致 sealed 视图 + 按内容统一落实）

一次计划读取当时的 sealed 包集合（staging 包对计划完全不可见），把包集合
及其哈希、请求与规则的来源 SHA-256/字节数/行数绑定进计划。`plan_id` 为
业务内容寻址；相同输入 + 相同 sealed 包集合得到相同 `plan_id`，登记表
（`release_plans`）只增不改。

1. **表示展开与成员检查**：用既有 `rep_members` 展开完整表示，合并跨包的
   相同声明；成员集合在包间互相矛盾、任一成员缺失、字节不可用
   （`bytes_missing`/`bytes_corrupt`/`not_received`）或身份冲突
   （`identity_conflict`）时，整份表示暂缓并逐项给出原因。
2. **按内容（SHA-256）统一落实规则**：相同字节的不同对象是不同身份，
   因此对计划涉及的每个内容摘要，纳入本次 sealed 视图中**所有**关联该摘要
   的 `bytes_ok` bitstream 身份，包括未选表示中的别名。
   - 任一别名身份缺规则或显式 `hold` → 该内容对本受众**整体暂缓**；
   - 否则取全部 `redact` 区间的并集；存在 redact → 生成一份共同遮盖副本；
   - 全部别名均为 `release` → 才允许输出原字节。
3. **可对外列出的表示**：只有通过全部成员检查、且其全部内容决定可发布
   （release/redact，无 blocked）的表示才能进入公开清单。多个表示可共享
   同一个输出文件；被暂缓表示独有且未被开放表示引用的内容一律留在馆内。
4. 原件谱系结论（verified/incomplete/…）继续由 §8 的既有命令提供，发布
   流程不重算也不改写它。

### 15.4 遮盖执行（原始 UTF-8 字节坐标）

- 坐标永远是**原始字节**偏移，不是字符序号。字节 `b` 是 UTF-8 字符边界
  当且仅当 `b < 0x80` 或 `b >= 0xC0`；区间两端都必须落在字符边界上
  （文件末尾 EOF 必为边界）。
- 先逐条校验原始区间（非空、未越界、两端对齐），**再**求并集；被覆盖的
  非法区间同样报错。以等量 ASCII `*`（0x2A）替换并集内字节，其余原始字节
  （含换行）保留，因此输出长度与原件一致。
- 全流程 1 MiB 分块，增量 UTF-8 解码器跨块保留状态，遮盖区间可跨块；
  读取发布用封存文件时实际重算长度与 SHA-256，确保被转换或复制的字节
  就是通过校验的字节。内容损坏、摘要不符、无法成立的遮盖规则均阻止产生
  可发布结果，并在馆内计划中定位失败对象。

### 15.5 批准后交付与并发顺序

- 发布必须指定经确认的 `plan_id`，并重新核对请求/规则来源哈希与 live
  sealed 包集合；包集合变化即判定计划**陈旧**（`stale_plan`），拒绝交付、
  要求重做。
- 全部产物先在目标之外的临时目录构建并通过校验，最后在一个写事务内复核
  包集合后**一次性原子改名**到全新目标目录。封存（`finish`）与发布同用
  SQLite 写锁，故“复核 → 公开目录出现”之间不可能夹入新封存；只要新包在
  交付前已经封存，旧计划就不能交付。
- 中途失败或进程中断后，正式路径只能是**不存在**或一份完整可校验目录；
  临时目录与仓内互斥锁在 `finally` 中清理，可安全重跑。目标已存在时保留
  原内容并拒绝；并发发布同一路径最多一个成功。
- 馆内计划、原始输入副本与临时文件均存放在外发目录**之外**
  （仓内 `release/plans`、`release/requests`、`release/rules`）。

### 15.6 外发目录与公开清单（最小披露）

目录布局受控：根目录仅 `release-manifest.json` 与 `payloads/`；
`payloads/` 下仅 `f-<64hex>.bin`。生成文件名是以 `plan_id` 为键、交付字节
摘要为消息的完整 HMAC-SHA-256，**不得**取自馆内身份、路径或原件摘要；同一
计划内相同交付字节共享一个文件，跨计划自然更名。

公开清单（`offline-evidence-repo/release-manifest/v1`）只用获批外部代号
列出开放表示，通过生成文件名引用成员，且只记录**交付字节**的 `size` 与
`sha256`（原样放行时自然等于原件的长度与摘要）。清单不得另附原件摘要
（作为文件名/身份的情形）、馆内对象身份、路径、规则、原因、原始 XML、
事件、证明或馆内计划；字段集合受离线校验器白名单约束。

### 15.7 离线自校验（搬离仓库后）

`release-verify` 不 import 仓内任何模块，只依据公开格式与清单：重算每个
有效载荷的 SHA-256/长度，核对成员引用、文件集合（清单 files == 引用集合
== 磁盘集合），拒绝多余文件、缺文件、路径逃逸、任何层级的符号链接与摘要
错误。它只检验目录**自身一致性**；规则是否确实落实由馆内独立验收判断。

### 15.8 资源边界

规则与请求逐行流式解析；别名反查经 TEMP 表与有界连接完成，避免逐表示
全仓扫描或重复复制内容；成员关系、清单处理允许 SQLite 暂存或外部排序。
二进制遮盖/复制恒定 1 MiB 分块（单条记录约束 + 有界缓存），峰值内存不随
载荷体积或别名/区间数量线性增长（见 `tests/demo_release_scale.py`）。

## 16. 封存对象格式画像（format profiling）

格式画像回答“**仓里有哪些文件格式、判断依据是什么、哪些对象需要人工
识别**”。它用于保存与盘点：**不执行格式转换**，也不改变对象身份、
谱系结论（§5–§8）或对外发布许可（§15）；只读既有事实表，结果写入
独立的 `format_catalogs` / `catalog_formats` / `catalog_signatures` /
`format_profiles` 表与 `profiles/` 下的不可变文件。

### 16.1 格式签名目录（`format-catalog/v1`，版本化 UTF-8 JSONL）

管理员提供有版本号的目录：首行头记录（`catalog_id` + `catalog_version`
+ 可选 `note`），其后每条格式一行（稳定 `format_id` + 可读 `name`）、
每条签名一行（`signature_id`、所属 `format_id`、`required`/`forbidden`
片段表）。片段规则：

- `bytes`：偶数长度十六进制（1..256 字节）；`mask` 可选、与 `bytes`
  等长，逐字节掩码——仅当 `(实际字节 & mask) == (模式字节 & mask)`
  逐字节成立时片段匹配；
- 定位二选一：`offset` 固定偏移，或 `window: [start, end]` 有限搜索
  窗口（起始偏移闭区间，跨度 ≤ 1 MiB）；
- 签名命中 ⟺ 全部 required 片段都匹配 **且** 全部 forbidden 片段
  都不匹配。

**严格校验**：目录头、格式版本、字段类型、未知字段、十六进制、偏移
边界、掩码长度、窗口跨度、重复 format_id / signature_id、签名引用
未声明格式等，任一行错误即整份拒绝并回滚，仓内不留半份可用版本。
目录行序与签名内片段顺序**不影响结果**：登记时把解析内容规范化
（排序）后取内容摘要 `catalog_sha256` 作为该目录版本的内容地址；
相同 `(catalog_id, catalog_version)` 重复登记且摘要一致时幂等复用，
内容不同则拒绝。明确上限：单行 ≤ 1 MiB、总行数 ≤ 4096、每签名
片段 ≤ 32、片段 ≤ 256 字节、窗口跨度 ≤ 1 MiB、偏移 ≤ 2^48。

### 16.2 画像范围与逐身份事实

一次画像只纳入**指定一组已封存包**中声明的 bitstream 身份；staging
包不得进入（范围校验直接拒绝）。按精确 `(identifierType,
identifierValue)` 展开事实：

- 同一身份在多个范围内包重复声明只记录一次（`package_ids` 列出全部
  来源）；相同字节但身份不同的对象是不同记录，分别列出；
- 表示、METS 结构节点不是 bitstream 身份，绝不计入；
- 每个身份单独记录：包来源、字节状态、内容摘要、采用的目录版本
  （`catalog_id`/`catalog_version`/`catalog_sha256`）与逐条匹配证据；
- **画像前重新读取**被引用的封存载荷，分块核对实际长度与 SHA-256；
  缺失、损坏、身份冲突的对象**不被签名命中掩盖**，给出相应状态
  （`bytes_missing` / `bytes_corrupt` / `not_received` /
  `identity_conflict`）与逐副本出处（`copies[]`，含仓内状态与本次
  复核结论）。

### 16.3 匹配语义与证据

对字节有效（`bytes_ok`）的每个对象，求出目录中**所有**完整命中的
签名（与目录行序无关）：

- 无命中 → `unidentified`；
- 全部命中指向同一格式 → `identified`（保留全部命中签名）；
- 命中指向多个格式 → `ambiguous`（绝不按目录顺序或首个命中静默
  挑选）。

证据逐条指出签名、片段偏移与匹配字节：每条必需片段记录
`match_count`、前 ≤8 个命中偏移与第一命中处的实际字节（十六进制）；
每条禁止片段记录 `match_count: 0`。汇总按精确对象身份去重：各格式
对象数（仅计 `identified`）、`identified` / `ambiguous` /
`unidentified` / 无效字节（`bytes_invalid`）/ 身份冲突数，以及
`by_byte_state` 分解。

### 16.4 不可变结果与输入绑定

每次画像生成一个不可变结果，绑定规范化目录内容摘要、实际封存包
集合及其清单摘要；`profile_id` 为业务内容寻址。相同输入重跑得到
相同业务结果与稳定标识（复用既有结果，不重写）；新增封包或新目录
版本只会产生新结果，不改写旧结果。`profile-check-binding` 对照当前
仓库校验画像输入绑定：目录版本仍登记且摘要一致、绑定的包全部仍
sealed、绑定包集合是否等于当前 sealed 集合——旧画像所绑定包集合
变化后仍可校验（`historical`），但不能冒充当前仓库的画像
（`current=false`）。结果文件可复制到仓库外，由独立校验器
（`verify_profile.py`，不 import 仓内模块、**不重跑格式匹配**）核对
内容摘要、绑定信息与汇总/证据结构自洽。

### 16.5 资源边界

- 载荷按**区域**读取：每个片段的扫描区域 ≤ 窗口跨度上限 + 片段长度
  上限；相邻区域在不超限（`MAX_REGION_BYTES`）前提下合并一次读入；
  单次 `read()` ≤ 1 MiB；**绝不把整个载荷读入内存**。搜索窗口、掩码
  比较与跨读取块的片段因此都有界。
- 掩码比较编译为等价的字节正则（零宽 lookahead 枚举全部重叠命中），
  常数内存；全通配片段按区间算术计数。
- 允许按内容摘要在**同一运行内**复用签名扫描；每个精确对象身份仍
  独立写入结果，且每次运行都重新验证其仓内字节来源与输入绑定。
- 目录规模受 §16.1 上限约束；格式数、别名数、载荷体积增大时峰值
  内存有界（见 `tests/demo_format_profile_scale.py`：64 MiB 载荷
  扫描峰值约 2 MiB；2000 别名 + 300 格式峰值约 27 MiB，随结果文件
  本身大小变化）。
