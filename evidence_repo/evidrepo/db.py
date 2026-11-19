# -*- coding: utf-8 -*-
"""
证据仓持久层（SQLite，全量落盘）。

表结构要点：
- 身份一律为 (id_type, id_value) 复合键，blob 内容（哈希）不参与身份。
- staging 与 sealed 数据同库存放，所有事实查询/求值只看 sealed 包，
  未完成包因此无法进入可查询事实。
- 求值结果物化在 obj_status / ev_status 两张表里，每次封包后重算。
"""
from __future__ import annotations

import os
import sqlite3

from .util import PKG_SEALED

SCHEMA_VERSION = 3


def connect(repo_root):
    db_path = os.path.join(repo_root, "db", "evidence.sqlite3")
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA synchronous = NORMAL")
    # 谱系不动点频繁使用 TEMP 表与多轮连接：临时对象留在内存，避免逐轮换盘
    conn.execute("PRAGMA temp_store = MEMORY")
    conn.execute("PRAGMA cache_size = -65536")  # 64 MiB 页缓存
    _create(conn)
    return conn


def _create(conn):
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS meta (
            key   TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );

        -- 交接包 ------------------------------------------------------------
        CREATE TABLE IF NOT EXISTS packages (
            package_id   TEXT PRIMARY KEY,
            state        TEXT NOT NULL CHECK (state IN ('staging','sealed')),
            manifest     TEXT NOT NULL,          -- 原始 manifest 副本（仓内相对路径）
            received_at  TEXT NOT NULL,
            sealed_at    TEXT
        );

        -- manifest 声明的信任起点：ingest 事件 ID 名单（调用者给定）
        CREATE TABLE IF NOT EXISTS trusted_ingest (
            package_id TEXT NOT NULL REFERENCES packages(package_id),
            event_id   TEXT NOT NULL,
            PRIMARY KEY (package_id, event_id)
        );

        -- 包内 XML 文档 ------------------------------------------------------
        CREATE TABLE IF NOT EXISTS xml_docs (
            package_id  TEXT NOT NULL REFERENCES packages(package_id),
            rel_path    TEXT NOT NULL,           -- 包内相对路径
            kind        TEXT NOT NULL,           -- mets | premis | other
            c14n_sha256 TEXT NOT NULL,
            stored_path TEXT NOT NULL,           -- 仓内相对路径（规范化 XML）
            PRIMARY KEY (package_id, rel_path)
        );

        -- 二进制成员 ---------------------------------------------------------
        CREATE TABLE IF NOT EXISTS blobs (
            package_id   TEXT NOT NULL REFERENCES packages(package_id),
            rel_path     TEXT NOT NULL,
            declared_sha TEXT NOT NULL,
            actual_sha   TEXT,                   -- 接包时实算；缺失为 NULL
            size_decl    INTEGER NOT NULL,
            size_actual  INTEGER,
            state        TEXT NOT NULL,          -- bytes_ok|bytes_missing|bytes_corrupt
            stored_path  TEXT,                   -- 仓内相对路径（成功接收时）
            PRIMARY KEY (package_id, rel_path)
        );

        -- PREMIS 对象（身份 = type+value；同字节不同 ID 是不同对象） -----------
        CREATE TABLE IF NOT EXISTS objects (
            id_type       TEXT NOT NULL,
            id_value      TEXT NOT NULL,
            package_id    TEXT NOT NULL REFERENCES packages(package_id),
            category      TEXT NOT NULL,         -- bitstream | representation
            xml_rel       TEXT NOT NULL,         -- 出处 XML（包内相对路径）
            PRIMARY KEY (id_type, id_value, package_id)
        );

        -- bitstream 身份 -> 承载它的包内 blob（一个身份可由多个包提供）
        CREATE TABLE IF NOT EXISTS object_blobs (
            id_type       TEXT NOT NULL,
            id_value      TEXT NOT NULL,
            package_id    TEXT NOT NULL REFERENCES packages(package_id),
            blob_rel      TEXT NOT NULL,
            PRIMARY KEY (id_type, id_value, package_id, blob_rel)
        );

        -- PREMIS 事件（同名异内容 -> 冲突，见 event_conflicts 物化表） ---------
        CREATE TABLE IF NOT EXISTS events (
            event_id      TEXT NOT NULL,
            package_id    TEXT NOT NULL REFERENCES packages(package_id),
            event_type    TEXT NOT NULL,
            event_dt      TEXT,                  -- 仅来源信息，不参与依赖
            outcome       TEXT NOT NULL,         -- success|failed|unknown
            c14n_sha256   TEXT NOT NULL,
            xml_rel       TEXT NOT NULL,
            PRIMARY KEY (event_id, package_id)
        );

        -- 带 input/output 角色的 linkingObjectIdentifier
        CREATE TABLE IF NOT EXISTS event_links (
            event_id      TEXT NOT NULL,
            package_id    TEXT NOT NULL REFERENCES packages(package_id),
            role          TEXT NOT NULL CHECK (role IN ('input','output')),
            obj_id_type   TEXT NOT NULL,
            obj_id_value  TEXT NOT NULL,
            ord           INTEGER NOT NULL
        );

        -- 事件上的其他角色/其他 PREMIS 扩展：原样保存为 uninterpreted
        CREATE TABLE IF NOT EXISTS event_uninterpreted (
            event_id    TEXT NOT NULL,
            package_id  TEXT NOT NULL,
            xml_rel     TEXT NOT NULL,
            local_name  TEXT NOT NULL,
            raw_xml     TEXT NOT NULL
        );

        -- 对象上的 uninterpreted 扩展
        CREATE TABLE IF NOT EXISTS object_uninterpreted (
            id_type     TEXT NOT NULL,
            id_value    TEXT NOT NULL,
            package_id  TEXT NOT NULL,
            xml_rel     TEXT NOT NULL,
            local_name  TEXT NOT NULL,
            raw_xml     TEXT NOT NULL
        );

        -- representation 声明的完整 bitstream 成员集合。
        -- package_id 纳入主键：同一表示身份在不同包中的成员声明各自保留，
        -- 以便识别“同身份、不同成员集合”的事实冲突（不在导入时静默择一）。
        CREATE TABLE IF NOT EXISTS rep_members (
            rep_id_type   TEXT NOT NULL,
            rep_id_value  TEXT NOT NULL,
            member_type   TEXT NOT NULL,
            member_value  TEXT NOT NULL,
            package_id    TEXT NOT NULL,
            ord           INTEGER NOT NULL,
            PRIMARY KEY (rep_id_type, rep_id_value, package_id,
                         member_type, member_value)
        );

        -- METS structMap 结构节点（只引用表示；同 bitstream 多处展示不重复计数）
        CREATE TABLE IF NOT EXISTS struct_nodes (
            package_id    TEXT NOT NULL,
            node_id       TEXT NOT NULL,
            label         TEXT,
            rep_id_type   TEXT NOT NULL,
            rep_id_value  TEXT NOT NULL,
            PRIMARY KEY (package_id, node_id)
        );

        -- 物化：事件身份冲突（同一 event_id 的 c14n 不一致）
        CREATE TABLE IF NOT EXISTS event_conflicts (
            event_id TEXT PRIMARY KEY
        );

        -- 物化：对象身份冲突（同一对象身份被不同实际字节占用）
        CREATE TABLE IF NOT EXISTS object_conflicts (
            id_type  TEXT NOT NULL,
            id_value TEXT NOT NULL,
            PRIMARY KEY (id_type, id_value)
        );

        -- 物化：sealed 视图下每个 bitstream 对象的状态
        CREATE TABLE IF NOT EXISTS obj_status (
            id_type   TEXT NOT NULL,
            id_value  TEXT NOT NULL,
            state     TEXT NOT NULL,
            proven    INTEGER NOT NULL,           -- 1 = origin_proven
            PRIMARY KEY (id_type, id_value)
        );

        -- 物化：sealed 视图下每个事件是否为有效（转换/根）证据
        CREATE TABLE IF NOT EXISTS ev_status (
            event_id  TEXT PRIMARY KEY,
            valid     INTEGER NOT NULL
        );

        -- 导出的证明（证明号固定绑定当时的 sealed 包集合）
        CREATE TABLE IF NOT EXISTS proofs (
            proof_no     INTEGER PRIMARY KEY AUTOINCREMENT,
            proof_id     TEXT NOT NULL UNIQUE,    -- 内容寻址
            created_at   TEXT NOT NULL,
            rep_id_type  TEXT NOT NULL,
            rep_id_value TEXT NOT NULL,
            export_dir   TEXT NOT NULL,
            package_set  TEXT NOT NULL            -- JSON 排序数组，封面包集合快照
        );

        -- 预期馆藏清单（独立存储：绝不进入 objects / events / 谱系求值图）-----
        CREATE TABLE IF NOT EXISTS inventories (
            inventory_id    TEXT PRIMARY KEY,
            batch_note      TEXT NOT NULL,        -- 批次说明
            format_version  TEXT NOT NULL,        -- 清单格式版本
            source_sha256   TEXT NOT NULL,        -- 原始清单文件 SHA-256
            source_bytes    INTEGER NOT NULL,
            source_lines    INTEGER NOT NULL,     -- 物理行数（含表头）
            obligation_count INTEGER NOT NULL,
            item_count      INTEGER NOT NULL,
            imported_at     TEXT NOT NULL,
            stored_path     TEXT NOT NULL         -- 仓内相对路径的原始清单副本
        );

        -- 每条交付义务（一个 item_id 可声明多条义务）
        CREATE TABLE IF NOT EXISTS inventory_obligations (
            inventory_id  TEXT NOT NULL REFERENCES inventories(inventory_id),
            obligation_id TEXT NOT NULL,
            item_id       TEXT NOT NULL,
            note          TEXT,
            source_line   INTEGER NOT NULL,       -- 原始 JSONL 行号（1 基）
            PRIMARY KEY (inventory_id, obligation_id)
        );
        CREATE INDEX IF NOT EXISTS idx_inv_ob_item
            ON inventory_obligations(inventory_id, item_id);

        -- 每条义务的可接受表示身份（有序二元组；type+value 精确匹配）
        CREATE TABLE IF NOT EXISTS inventory_acceptable (
            inventory_id  TEXT NOT NULL,
            obligation_id TEXT NOT NULL,
            id_type       TEXT NOT NULL,
            id_value      TEXT NOT NULL,
            ord           INTEGER NOT NULL,
            source_line   INTEGER NOT NULL,
            PRIMARY KEY (inventory_id, obligation_id, id_type, id_value),
            FOREIGN KEY (inventory_id, obligation_id)
                REFERENCES inventory_obligations(inventory_id, obligation_id)
        );

        -- 对账报告（只增不改；文件内容寻址；绑定清单哈希与封包集合）--------
        CREATE TABLE IF NOT EXISTS reconciliation_reports (
            report_no          INTEGER PRIMARY KEY AUTOINCREMENT,
            report_id          TEXT NOT NULL UNIQUE,
            inventory_id       TEXT NOT NULL REFERENCES inventories(inventory_id),
            inventory_sha256   TEXT NOT NULL,
            package_set_sha256 TEXT NOT NULL,
            content_sha256     TEXT NOT NULL,
            created_at         TEXT NOT NULL,
            report_path        TEXT NOT NULL      -- 仓内相对路径（可搬迁）
        );
        CREATE INDEX IF NOT EXISTS idx_recon_inventory
            ON reconciliation_reports(inventory_id);

        -- 离线发布：馆内计划（只增不改；内容寻址；绑定请求/规则/封包集合）--
        CREATE TABLE IF NOT EXISTS release_plans (
            plan_id            TEXT PRIMARY KEY,   -- 业务内容 SHA-256
            request_id         TEXT NOT NULL,
            audience           TEXT NOT NULL,
            created_at         TEXT NOT NULL,
            sealed_package_set TEXT NOT NULL,      -- JSON 排序数组（计划事实视图）
            package_set_sha256 TEXT NOT NULL,
            request_sha256     TEXT NOT NULL,
            rules_sha256       TEXT NOT NULL,
            request_bytes      INTEGER NOT NULL,
            rules_bytes        INTEGER NOT NULL,
            plan_path          TEXT NOT NULL,      -- 仓内相对路径（外发目录之外）
            deliverable_count  INTEGER NOT NULL,
            held_count         INTEGER NOT NULL,
            blocked_count      INTEGER NOT NULL
        );

        -- 离线发布：按计划产生的外发目录登记（发布审计；不写任何外发内容）
        CREATE TABLE IF NOT EXISTS release_deliveries (
            delivery_no   INTEGER PRIMARY KEY AUTOINCREMENT,
            plan_id       TEXT NOT NULL REFERENCES release_plans(plan_id),
            delivered_at  TEXT NOT NULL,
            target_dir    TEXT NOT NULL,
            manifest_name TEXT NOT NULL,
            file_count    INTEGER NOT NULL,
            manifest_sha256 TEXT NOT NULL,
            package_set_sha256 TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_delivery_plan
            ON release_deliveries(plan_id);
        """
    )
    cur = conn.execute("SELECT value FROM meta WHERE key='schema_version'")
    row = cur.fetchone()
    if row is None:
        conn.execute(
            "INSERT INTO meta(key,value) VALUES('schema_version',?)",
            (str(SCHEMA_VERSION),),
        )
        conn.commit()
    elif int(row[0]) == SCHEMA_VERSION:
        pass
    elif int(row[0]) == 1:
        # v1 -> v2：rep_members 主键加入 package_id（保留每个包的成员声明，
        # 以便识别“同身份不同成员集合”的事实冲突）。既有行原样保留。
        _migrate_v1_to_v2(conn)
        conn.execute(
            "UPDATE meta SET value=? WHERE key='schema_version'",
            (str(SCHEMA_VERSION),),
        )
        conn.commit()
    elif int(row[0]) == 2:
        # v2 -> v3：离线发布表（release_plans / release_deliveries）。
        # 既有谱系/对账数据原样保留，发布子系统独立建表。
        conn.execute(
            "UPDATE meta SET value=? WHERE key='schema_version'",
            (str(SCHEMA_VERSION),),
        )
        conn.commit()
    else:
        raise RuntimeError("schema version mismatch: %s" % row[0])


def _migrate_v1_to_v2(conn):
    cols = [
        r[1]
        for r in conn.execute("PRAGMA table_info(rep_members)").fetchall()
    ]
    # v1 主键为 (rep_id_type,rep_id_value,member_type,member_value)，
    # 重建为含 package_id 的表并原样搬运数据。
    conn.execute("ALTER TABLE rep_members RENAME TO rep_members_v1")
    conn.execute(
        """
        CREATE TABLE rep_members (
            rep_id_type   TEXT NOT NULL,
            rep_id_value  TEXT NOT NULL,
            member_type   TEXT NOT NULL,
            member_value  TEXT NOT NULL,
            package_id    TEXT NOT NULL,
            ord           INTEGER NOT NULL,
            PRIMARY KEY (rep_id_type, rep_id_value, package_id,
                         member_type, member_value)
        )
        """
    )
    conn.execute(
        "INSERT OR IGNORE INTO rep_members"
        "(rep_id_type,rep_id_value,member_type,member_value,package_id,ord) "
        "SELECT rep_id_type,rep_id_value,member_type,member_value,"
        "package_id,ord FROM rep_members_v1"
    )
    conn.execute("DROP TABLE rep_members_v1")


def sealed_filter(prefix=""):
    """SQL 片段：只选 sealed 包。"""
    p = (prefix + ".") if prefix else ""
    return "%spackage_id IN (SELECT package_id FROM packages WHERE state='%s')" % (
        p,
        PKG_SEALED,
    )


def get_meta(conn, key, default=None):
    row = conn.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
    return row[0] if row else default


def set_meta(conn, key, value):
    conn.execute(
        "INSERT INTO meta(key,value) VALUES(?,?) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        (key, value),
    )
