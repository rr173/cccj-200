# -*- coding: utf-8 -*-
"""
证明求值引擎（每次封包后对 sealed 事实集整体重算，结果物化落盘）。

状态定义（对应题目四态 + 谱系）：
  bytes_ok / bytes_missing / bytes_corrupt / identity_conflict / not_received
  origin_proven：存在有限无环证明，根全部来自受信有效 ingest，
                 中间事件全部有效、且每个事件的全部输入都已被证明（AND）；
                 同一对象可由多个事件证明，任一路径成立即可（OR）。

实现方式：SQL 不动点迭代。循环支路永远进不了不动点（其前提无法先被证明），
但不会否决其他独立好路径——坏支路不产生否决，只产生缺失诊断。
内存只放得下“已证明对象集合”的 ID，不读任何二进制内容。
"""
from __future__ import annotations

from .db import sealed_filter
from .util import ST_NOT_RECEIVED


def recompute(conn):
    # 持久化索引（IF NOT EXISTS，幂等）：加速谱系图上的连接与反查
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_links_obj ON "
        "event_links(role, obj_id_type, obj_id_value)"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_links_evt ON "
        "event_links(event_id, package_id, role)"
    )
    conn.execute("BEGIN IMMEDIATE")
    try:
        _conflicts(conn)
        _event_base_validity(conn)
        _fixpoint(conn)
        _object_states(conn)
        conn.commit()
    except Exception:
        conn.rollback()
        raise


def _conflicts(conn):
    conn.execute("DELETE FROM event_conflicts")
    # 同名异内容：同一 event_id 在 sealed 包中出现 >1 个不同 c14n 哈希
    conn.execute(
        """
        INSERT INTO event_conflicts(event_id)
        SELECT event_id
        FROM events
        WHERE """
        + sealed_filter("events")
        + """
        GROUP BY event_id
        HAVING COUNT(DISTINCT c14n_sha256) > 1
        """
    )
    conn.execute("DELETE FROM object_conflicts")
    # 同一对象身份被不同实际字节占用（只比较已完整接收的字节）
    conn.execute(
        """
        INSERT INTO object_conflicts(id_type,id_value)
        SELECT ob.id_type, ob.id_value
        FROM object_blobs ob
        JOIN blobs b
          ON b.package_id = ob.package_id AND b.rel_path = ob.blob_rel
         AND b.state = 'bytes_ok'
        WHERE """
        + sealed_filter("ob")
        + """
        GROUP BY ob.id_type, ob.id_value
        HAVING COUNT(DISTINCT b.actual_sha) > 1
        """
    )


def _event_base_validity(conn):
    """
    事件“结构有效性”（不含输入 proven 条件，那部分进不动点）。
    逐条排除规则，任一不满足即无效；诊断时再给出具体原因。
    """
    conn.execute("DELETE FROM ev_status")
    conn.execute(
        """
        INSERT INTO ev_status(event_id, valid)
        SELECT DISTINCT e.event_id, 0
        FROM events e
        WHERE """
        + sealed_filter("e")
    )
    # 置 1：通过全部结构检查的事件
    conn.execute(
        """
        UPDATE ev_status
        SET valid = 1
        WHERE event_id IN (
          SELECT e.event_id
          FROM events e
          WHERE """
        + sealed_filter("e")
        + """
            AND e.event_type IN ('ingest','copy','migration')
            AND e.outcome = 'success'
            -- 同名异内容冲突
            AND NOT EXISTS (SELECT 1 FROM event_conflicts c WHERE c.event_id = e.event_id)
            -- 引用无歧义 = 同名事件的全部 sealed 记录规范化内容一致
            -- （跨包重复记载同一事件合法；冲突已在上面排除）
            AND 1 = 1
            -- ingest 必须在调用者给定的受信名单中（不按 eventType 自行信任）
            AND (
              (e.event_type = 'ingest'
               AND EXISTS (SELECT 1 FROM trusted_ingest t
                           WHERE t.event_id = e.event_id
                             AND """ + sealed_filter("t") + """))
              OR e.event_type IN ('copy','migration')
            )
            -- 角色规则：ingest 无 input；copy/migration 至少一个 input
            AND (
              (e.event_type = 'ingest'
               AND NOT EXISTS (SELECT 1 FROM event_links l
                               WHERE l.event_id=e.event_id AND l.role='input'
                                 AND """ + sealed_filter("l") + """))
              OR (e.event_type IN ('copy','migration')
                  AND EXISTS (SELECT 1 FROM event_links l
                              WHERE l.event_id=e.event_id AND l.role='input'
                                AND """ + sealed_filter("l") + """))
            )
            -- 至少一个 output
            AND EXISTS (SELECT 1 FROM event_links l
                        WHERE l.event_id=e.event_id AND l.role='output'
                          AND """ + sealed_filter("l") + """)
            -- 所有引用对象在 sealed 事实中都存在（无悬空/歧义引用）
            AND NOT EXISTS (
                SELECT 1 FROM event_links l
                WHERE l.event_id=e.event_id AND """ + sealed_filter("l") + """
                  AND NOT EXISTS (
                      SELECT 1 FROM objects o
                      WHERE o.id_type=l.obj_id_type AND o.id_value=l.obj_id_value
                        AND """ + sealed_filter("o") + """
                  )
            )
            AND NOT EXISTS (
                SELECT 1 FROM event_links l
                JOIN object_conflicts oc
                  ON oc.id_type=l.obj_id_type AND oc.id_value=l.obj_id_value
                WHERE l.event_id=e.event_id
            )
            -- 所有 output 都至少有一份 bytes_ok 的字节（输入字节在 proven 中要求）
            AND NOT EXISTS (
                SELECT 1 FROM event_links l
                WHERE l.event_id=e.event_id AND l.role='output'
                  AND """ + sealed_filter("l") + """
                  AND NOT EXISTS (
                      SELECT 1 FROM object_blobs ob
                      JOIN blobs b ON b.package_id=ob.package_id
                                  AND b.rel_path=ob.blob_rel
                      WHERE ob.id_type=l.obj_id_type AND ob.id_value=l.obj_id_value
                        AND b.state='bytes_ok'
                  )
            )
        )
        """
    )


def _fixpoint(conn):
    """
    不动点（增量 BFS，每条依赖边只处理一次 => 总复杂度 O(边数)）。

    维护：
      tmp_proven  全量已证明对象集
      tmp_pending 本轮新证明、尚未沿入边传播的对象（BFS 前沿）
      tmp_ev_got  每个事件“已被证明的输入对象数”
      tmp_ev_need 每个事件的输入总数（AND 门分母）
    当某事件 got == need（全部输入 proven，AND 共同前提）且事件有效时，
    其全部输出进入下一轮前沿。环上事件永远满足不了 need（某输入只由环
    自身产出），故循环支路进不了不动点，也不否决独立好路径。
    """
    conn.executescript(
        """
        DROP TABLE IF EXISTS tmp_proven;
        DROP TABLE IF EXISTS tmp_pending;
        DROP TABLE IF EXISTS tmp_ev_got;
        DROP TABLE IF EXISTS tmp_ev_need;
        DROP TABLE IF EXISTS tmp_fire;
        DROP TABLE IF EXISTS tmp_fixpoint;
        CREATE TEMP TABLE tmp_proven(id_type TEXT, id_value TEXT,
            PRIMARY KEY(id_type,id_value)) WITHOUT ROWID;
        CREATE TEMP TABLE tmp_pending(id_type TEXT, id_value TEXT,
            PRIMARY KEY(id_type,id_value)) WITHOUT ROWID;
        CREATE TEMP TABLE tmp_ev_need(event_id TEXT PRIMARY KEY,
            n INTEGER) WITHOUT ROWID;
        CREATE TEMP TABLE tmp_ev_got(event_id TEXT PRIMARY KEY,
            n INTEGER DEFAULT 0) WITHOUT ROWID;
        CREATE TEMP TABLE tmp_fire(event_id TEXT PRIMARY KEY) WITHOUT ROWID;
        -- 本算子专用临时索引，加速按对象身份反查输入边/按事件取输出
        CREATE INDEX IF NOT EXISTS idx_tmp_li_obj ON
            event_links(role, obj_id_type, obj_id_value);
        CREATE INDEX IF NOT EXISTS idx_tmp_li_evt ON
            event_links(event_id, role);
        """
    )

    # 每个 copy/migration 事件的“去重后”输入总数（AND 门分母，按事件身份）
    conn.execute(
        """
        INSERT INTO tmp_ev_need(event_id, n)
        SELECT li.event_id,
               COUNT(DISTINCT li.obj_id_type || char(31) || li.obj_id_value)
        FROM event_links li
        JOIN events e ON e.event_id = li.event_id AND e.package_id = li.package_id
         AND e.event_type IN ('copy','migration')
        WHERE li.role = 'input' AND """ + sealed_filter("li") + """
        GROUP BY li.event_id
        """
    )
    conn.execute(
        "INSERT OR IGNORE INTO tmp_ev_got(event_id, n) "
        "SELECT event_id, 0 FROM tmp_ev_need"
    )

    # 证明根：有效受信 ingest 的输出
    conn.execute(
        """
        INSERT OR IGNORE INTO tmp_proven(id_type,id_value)
        SELECT DISTINCT l.obj_id_type, l.obj_id_value
        FROM ev_status s
        JOIN events e ON e.event_id = s.event_id
        JOIN event_links l ON l.event_id = e.event_id
                         AND l.package_id = e.package_id
        WHERE s.valid=1 AND e.event_type='ingest' AND l.role='output'
          AND """ + sealed_filter("e") + """
          AND """ + sealed_filter("l")
    )
    conn.execute("INSERT INTO tmp_pending SELECT * FROM tmp_proven")

    while True:
        # 1) 只计算本轮前沿对象给各事件带来的“新增已满足输入数”
        conn.execute("DROP TABLE IF EXISTS tmp_incr")
        conn.execute(
            """
            CREATE TEMP TABLE tmp_incr AS
            SELECT li.event_id AS event_id,
                   COUNT(DISTINCT li.obj_id_type || char(31) || li.obj_id_value) AS dn
            FROM tmp_pending d
            JOIN event_links li
              ON li.obj_id_type = d.id_type AND li.obj_id_value = d.id_value
             AND li.role = 'input'
             AND """ + sealed_filter("li") + """
            GROUP BY li.event_id
            """
        )
        # 2) 登记新出现的计数器行，并把增量并入总计数
        conn.execute(
            "INSERT OR IGNORE INTO tmp_ev_got(event_id, n) "
            "SELECT event_id, 0 FROM tmp_incr"
        )
        conn.execute(
            """
            UPDATE tmp_ev_got
            SET n = n + (SELECT dn FROM tmp_incr
                         WHERE tmp_incr.event_id = tmp_ev_got.event_id)
            WHERE event_id IN (SELECT event_id FROM tmp_incr)
            """
        )
        # 3) AND 门：只在“本轮计数有增长”的事件中找新满足者，
        #    且排除已经触发过的事件（增量，不重复全表扫描）
        conn.execute("DELETE FROM tmp_fire")
        conn.execute(
            """
            INSERT INTO tmp_fire(event_id)
            SELECT i.event_id
            FROM tmp_incr i
            JOIN tmp_ev_got g ON g.event_id = i.event_id
            JOIN tmp_ev_need q ON q.event_id = i.event_id
            JOIN ev_status s ON s.event_id = i.event_id AND s.valid = 1
            WHERE g.n >= q.n
            """
        )
        # 4) 触发事件的输出成为新前沿（已证明者排除，环在此终止）
        conn.execute("DELETE FROM tmp_pending")
        conn.execute(
            """
            INSERT OR IGNORE INTO tmp_pending(id_type, id_value)
            SELECT DISTINCT lo.obj_id_type, lo.obj_id_value
            FROM tmp_fire f
            JOIN event_links lo ON lo.event_id = f.event_id
             AND lo.role = 'output'
             AND """ + sealed_filter("lo") + """
            WHERE NOT EXISTS (
                SELECT 1 FROM tmp_proven p
                WHERE p.id_type = lo.obj_id_type
                  AND p.id_value = lo.obj_id_value
            )
            """
        )
        if conn.execute("SELECT COUNT(*) FROM tmp_pending").fetchone()[0] == 0:
            break
        conn.execute("INSERT OR IGNORE INTO tmp_proven SELECT * FROM tmp_pending")

    conn.execute("CREATE TEMP TABLE tmp_fixpoint AS SELECT * FROM tmp_proven")
    conn.execute("DROP TABLE IF EXISTS tmp_pending")
    conn.execute("DROP TABLE IF EXISTS tmp_ev_got")
    conn.execute("DROP TABLE IF EXISTS tmp_ev_need")
    conn.execute("DROP TABLE IF EXISTS tmp_fire")
    conn.execute("DROP TABLE IF EXISTS tmp_incr")


def _object_states(conn):
    conn.execute("DELETE FROM obj_status")
    # 所有在 sealed 事实中出现过的 bitstream 身份
    conn.execute(
        """
        INSERT INTO obj_status(id_type,id_value,state,proven)
        WITH sealed_objs AS (
            SELECT DISTINCT id_type, id_value FROM objects
            WHERE category='bitstream' AND """
        + sealed_filter("objects")
        + """
            UNION
            SELECT DISTINCT id_type, id_value FROM object_blobs
            WHERE """
        + sealed_filter("object_blobs")
        + """
        )
        SELECT so.id_type, so.id_value,
          CASE
            WHEN EXISTS (SELECT 1 FROM object_conflicts oc
                         WHERE oc.id_type=so.id_type AND oc.id_value=so.id_value)
              THEN 'identity_conflict'
            WHEN NOT EXISTS (
                SELECT 1 FROM object_blobs ob
                JOIN blobs b ON b.package_id=ob.package_id AND b.rel_path=ob.blob_rel
                WHERE ob.id_type=so.id_type AND ob.id_value=so.id_value
                  AND b.state IN ('bytes_ok','bytes_corrupt','bytes_missing')
            ) THEN 'not_received'
            WHEN EXISTS (
                SELECT 1 FROM object_blobs ob
                JOIN blobs b ON b.package_id=ob.package_id AND b.rel_path=ob.blob_rel
                WHERE ob.id_type=so.id_type AND ob.id_value=so.id_value
                  AND b.state='bytes_corrupt'
            ) AND NOT EXISTS (
                SELECT 1 FROM object_blobs ob
                JOIN blobs b ON b.package_id=ob.package_id AND b.rel_path=ob.blob_rel
                WHERE ob.id_type=so.id_type AND ob.id_value=so.id_value
                  AND b.state='bytes_ok'
            ) THEN 'bytes_corrupt'
            WHEN EXISTS (
                SELECT 1 FROM object_blobs ob
                JOIN blobs b ON b.package_id=ob.package_id AND b.rel_path=ob.blob_rel
                WHERE ob.id_type=so.id_type AND ob.id_value=so.id_value
                  AND b.state='bytes_ok'
            ) THEN 'bytes_ok'
            ELSE 'bytes_missing'
          END AS state,
          CASE WHEN EXISTS (
              SELECT 1 FROM tmp_fixpoint p
              WHERE p.id_type=so.id_type AND p.id_value=so.id_value
          ) THEN 1 ELSE 0 END AS proven
        FROM sealed_objs so
        """
    )
    conn.execute("DROP TABLE IF EXISTS tmp_proven")
    conn.execute("DROP TABLE IF EXISTS tmp_fixpoint")


# --------------------------------------------------------------------------
# 查询辅助（只读 sealed 物化结果；未接收对象的行可能不存在）
# --------------------------------------------------------------------------

def is_proven(conn, id_type, id_value):
    row = conn.execute(
        "SELECT proven FROM obj_status WHERE id_type=? AND id_value=?",
        (id_type, id_value),
    ).fetchone()
    return bool(row and row["proven"])


def object_state(conn, id_type, id_value):
    row = conn.execute(
        "SELECT state, proven FROM obj_status WHERE id_type=? AND id_value=?",
        (id_type, id_value),
    ).fetchone()
    if row is None:
        return ST_NOT_RECEIVED, False
    return row["state"], bool(row["proven"])


def valid_events_producing(conn, id_type, id_value):
    """所有能产出该对象且当前有效的事件（OR 候选路径，按 ID 排序保证稳定）。"""
    rows = conn.execute(
        """
        SELECT DISTINCT e.event_id, e.event_type, e.event_dt, e.outcome, e.package_id,
               e.xml_rel
        FROM events e
        JOIN ev_status s ON s.event_id=e.event_id AND s.valid=1
        JOIN event_links lo ON lo.event_id=e.event_id AND lo.role='output'
        WHERE lo.obj_id_type=? AND lo.obj_id_value=?
          AND """
        + sealed_filter("e")
        + " ORDER BY e.event_id",
        (id_type, id_value),
    ).fetchall()
    return [dict(r) for r in rows]


def event_inputs(conn, event_id):
    rows = conn.execute(
        """
        SELECT l.obj_id_type, l.obj_id_value
        FROM event_links l
        WHERE l.event_id=? AND l.role='input' AND """
        + sealed_filter("l")
        + " ORDER BY l.ord",
        (event_id,),
    ).fetchall()
    return [(r["obj_id_type"], r["obj_id_value"]) for r in rows]


def event_outputs(conn, event_id):
    rows = conn.execute(
        """
        SELECT l.obj_id_type, l.obj_id_value
        FROM event_links l
        WHERE l.event_id=? AND l.role='output' AND """
        + sealed_filter("l")
        + " ORDER BY l.ord",
        (event_id,),
    ).fetchall()
    return [(r["obj_id_type"], r["obj_id_value"]) for r in rows]
