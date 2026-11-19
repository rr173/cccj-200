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
