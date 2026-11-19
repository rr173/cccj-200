# -*- coding: utf-8 -*-
"""
预期馆藏清单（inventory）导入 —— 与谱系事实仓**完全隔离**的另一类输入。

清单描述“本批应当交付哪些表示身份”，不伪装成 PREMIS object、不进入
provenance 求值图，也绝不改变 bytes / origin_proven 状态。

文件格式：UTF-8 JSONL（无 BOM）
  第 1 行（头记录，必须有）：
    {"record_type":"inventory_header",
     "format_version":"expected-inventory/v1",
     "inventory_id":"batch-2026-11",
     "batch_note":"2026 年 11 月季度提交"}
  其后每行一条义务：
    {"record_type":"obligation",
     "inventory_id":"batch-2026-11",          // 可省略；若给出须与头一致
     "item_id":"ITEM-001",                     // 一个 item 可出现在多行
     "obligation_id":"OBL-001",                // 全局唯一
     "note":"可选说明",
     "acceptable_representations":[
        {"identifierType":"local","identifierValue":"REP-A"},
        {"identifierType":"uuid","identifierValue":"..."}]}

语义要点：
- 可接受身份 = (identifierType, identifierValue) 有序二元组，精确匹配；
  绝不按显示名、文件名、摘要或部分匹配。
- 每个 item_id 可声明多条义务；每项义务恰须由一个实际 representation 满足。
- 不同义务的候选集合可以重叠；实际匹配时一个实际身份最多分配给一个义务。
- 同一表示在多个包中重复出现仍只是一个候选（按身份去重）。

导入是**整份接受或整份拒绝**的事务：任何一行校验失败都回滚，仓内不会
留下可参与对账的半份预期数据。来源行号与原始文件 SHA-256 一并保留。

内存边界：逐行流式解析（单行上限 MAX_LINE_BYTES），不把整份清单读入
Python 内存；两遍读取（先算来源哈希，再校验并写库），第二遍复核哈希。
"""
from __future__ import annotations

import datetime
import hashlib
import io
import json
import os

INVENTORY_FORMAT = "expected-inventory/v1"

# 单行长度上限：清单行是控制元数据，不是大对象；防止无界内存。
MAX_LINE_BYTES = 1 << 20  # 1 MiB


class InventoryError(Exception):
    """清单无效（整份拒绝，绝不留下半份预期数据）。"""

    def __init__(self, message, line=None, code=None):
        super().__init__(message)
        self.line = line
        self.code = code or "invalid_inventory"
        self.message = message

    def as_dict(self):
        return {"error": self.code, "line": self.line, "message": self.message}


def _now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def _sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------------------
# 物理行读取（流式；字节级哈希；严格 UTF-8；行号 1 基）
# ---------------------------------------------------------------------------

def _iter_physical_lines(fp, hasher=None):
    """
    从二进制流逐行读取，产出 (line_no, text)。
    - 只按 b'\\n' 切行（不用 str.splitlines），使行号与物理行严格对应；
    - 允许 CRLF；拒绝行内裸 CR；
    - 严格 UTF-8（不允许 BOM、孤立代理等）；
    - 单行超过 MAX_LINE_BYTES 立即拒绝。
    """
    lineno = 0
    while True:
        raw = fp.readline(MAX_LINE_BYTES + 2)
        if not raw:
            break
        lineno += 1
        if hasher is not None:
            hasher.update(raw)
        if not raw.endswith(b"\n") and len(raw) > MAX_LINE_BYTES:
            raise InventoryError(
                "line exceeds %d bytes" % MAX_LINE_BYTES,
                lineno,
                "line_too_long",
            )
        chunk = raw[:-1] if raw.endswith(b"\n") else raw
        if chunk.endswith(b"\r"):
            chunk = chunk[:-1]
        if b"\r" in chunk:
            raise InventoryError(
                "bare CR in line (use LF or CRLF line endings)",
                lineno,
                "bad_encoding",
            )
        if len(chunk) > MAX_LINE_BYTES:
            raise InventoryError(
                "line exceeds %d bytes" % MAX_LINE_BYTES,
                lineno,
                "line_too_long",
            )
        try:
            text = chunk.decode("utf-8", "strict")
        except UnicodeDecodeError as exc:
            raise InventoryError(
                "line is not valid UTF-8: %s" % exc, lineno, "bad_encoding"
            )
        yield lineno, text


def _first_nonempty_line_info(fp):
    """第一遍：计算来源 SHA-256 与物理行数；顺带拒绝 BOM / 空文件。"""
    h = hashlib.sha256()
    size = 0
    last_byte = b""
    first = b""
    while True:
        chunk = fp.read(1 << 20)
        if not chunk:
            break
        if not first:
            first = chunk[:3]
        h.update(chunk)
        size += len(chunk)
        last_byte = chunk[-1:]
    if size == 0:
        raise InventoryError("inventory is empty", 1, "empty")
    if first == b"\xef\xbb\xbf":
        raise InventoryError(
            "inventory must be UTF-8 without BOM", 1, "bad_encoding"
        )
    # 行数：每个 \n 一行；末尾无换行时补一行
    fp.seek(0)
    n_lines = 0
    while True:
        chunk = fp.read(1 << 20)
        if not chunk:
            break
        n_lines += chunk.count(b"\n")
    if last_byte != b"\n":
        n_lines += 1
    return h.hexdigest(), size, n_lines


# ---------------------------------------------------------------------------
# 单条记录校验
# ---------------------------------------------------------------------------

def _validate_text(value, what, line, allow_empty=False):
    if not isinstance(value, str):
        raise InventoryError(
            "%s must be a JSON string" % what, line, "bad_type"
        )
    # 身份/标识组件边界：不允许控制字符（含换行、制表、DEL），
    # 以免显示、定位与匹配产生歧义。
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in value):
        raise InventoryError(
            "%s contains control characters" % what, line, "bad_text"
        )
    if not allow_empty and value.strip() == "":
        raise InventoryError(
            "%s must not be empty" % what, line, "bad_text"
        )
    return value


def _parse_json_object(text, line_no):
    # 严格 JSON：拒绝 NaN/Infinity（默认 json 会接受），它们不是可移植事实。
    def _bad_constant(x):
        raise InventoryError(
            "non-finite JSON number %r is not allowed" % x, line_no, "bad_json"
        )

    try:
        obj = json.loads(text, parse_constant=_bad_constant)
    except InventoryError:
        raise
    except (json.JSONDecodeError, ValueError) as exc:
        raise InventoryError("invalid JSON: %s" % exc, line_no, "bad_json")
    if not isinstance(obj, dict):
        raise InventoryError(
            "each line must be a JSON object", line_no, "bad_json"
        )
    return obj


def validate_header(hdr):
    if not isinstance(hdr, dict):
        raise InventoryError("header must be a JSON object", 1, "bad_header")
    if hdr.get("record_type") not in (None, "inventory_header"):
        raise InventoryError(
            "first line must be the inventory header", 1, "bad_header"
        )
    if "format_version" not in hdr or "inventory_id" not in hdr:
        raise InventoryError(
            "header requires format_version and inventory_id", 1, "bad_header"
        )
    inv = _validate_text(hdr["inventory_id"], "inventory_id", 1)
    fv = _validate_text(hdr["format_version"], "format_version", 1)
    if fv != INVENTORY_FORMAT:
        raise InventoryError(
            "unsupported format_version %r (expected %r)"
            % (fv, INVENTORY_FORMAT),
            1,
            "bad_format_version",
        )
    note = hdr.get("batch_note", "")
    if note is None:
        note = ""
    _validate_text(note, "batch_note", 1, allow_empty=True)
    if hdr.get("obligations") not in (None, []):
        raise InventoryError(
            "header must not embed obligations; use one JSONL line per obligation",
            1,
            "bad_header",
        )
    return inv, fv, note


def validate_obligation(rec, line_no, inventory_id):
    if rec.get("record_type") not in (None, "obligation"):
        raise InventoryError(
            "expected an obligation record, got record_type %r"
            % (rec.get("record_type"),),
            line_no,
            "bad_record",
        )
    if "inventory_id" in rec:
        rid = _validate_text(rec["inventory_id"], "inventory_id", line_no)
        if rid != inventory_id:
            raise InventoryError(
                "line inventory_id %r does not match header %r"
                % (rid, inventory_id),
                line_no,
                "inventory_id_mismatch",
            )
    for field in ("item_id", "obligation_id", "acceptable_representations"):
        if field not in rec:
            raise InventoryError(
                "missing required field %r" % field, line_no, "missing_field"
            )
    item_id = _validate_text(rec["item_id"], "item_id", line_no)
    obligation_id = _validate_text(
        rec["obligation_id"], "obligation_id", line_no
    )
    note = rec.get("note", "")
    if note is None:
        note = ""
    _validate_text(note, "note", line_no, allow_empty=True)

    acc = rec["acceptable_representations"]
    if not isinstance(acc, list):
        raise InventoryError(
            "acceptable_representations must be a JSON array",
            line_no,
            "bad_type",
        )
    if not acc:
        raise InventoryError(
            "acceptable_representations must not be empty",
            line_no,
            "empty_candidates",
        )
    cand = []
    seen = set()
    for i, c in enumerate(acc):
        if not isinstance(c, dict):
            raise InventoryError(
                "acceptable_representations[%d] must be an object" % i,
                line_no,
                "bad_type",
            )
        if "identifierType" not in c or "identifierValue" not in c:
            raise InventoryError(
                "acceptable_representations[%d] requires identifierType and "
                "identifierValue" % i,
                line_no,
                "missing_field",
            )
        t = _validate_text(c["identifierType"], "identifierType", line_no)
        v = _validate_text(c["identifierValue"], "identifierValue", line_no)
        if (t, v) in seen:
            raise InventoryError(
                "duplicate acceptable identity %r within obligation %r"
                % ((t, v), obligation_id),
                line_no,
                "duplicate_candidate",
            )
        seen.add((t, v))
        cand.append((t, v))
    return {
        "obligation_id": obligation_id,
        "item_id": item_id,
        "note": note,
        "source_line": line_no,
        "candidates": cand,
    }


# ---------------------------------------------------------------------------
# 内存内解析（小型夹具/单元测试；导入走流式路径）
# ---------------------------------------------------------------------------

def parse_inventory_bytes(raw):
    """完整解析并校验清单字节，返回 dict（不写库）。"""
    if not isinstance(raw, (bytes, bytearray)):
        raise InventoryError("inventory must be raw bytes", None, "bad_input")
    raw = bytes(raw)
    if raw.startswith(b"\xef\xbb\xbf"):
        raise InventoryError(
            "inventory must be UTF-8 without BOM", 1, "bad_encoding"
        )
    digest = _sha256_bytes(raw)
    out = {
        "inventory_id": None,
        "batch_note": "",
        "format_version": None,
        "source_sha256": digest,
        "source_bytes": len(raw),
        "source_lines": 0,
        "item_count": 0,
        "obligations": [],
    }
    seen = set()
    items = set()
    first = True
    n = 0
    for line_no, text in _iter_physical_lines(io.BytesIO(raw)):
        n += 1
        if text.strip() == "":
            raise InventoryError(
                "blank line in inventory", line_no, "blank_line"
            )
        rec = _parse_json_object(text, line_no)
        if first:
            inv_id, fv, note = validate_header(rec)
            out["inventory_id"] = inv_id
            out["format_version"] = fv
            out["batch_note"] = note
            first = False
            continue
        ob = validate_obligation(rec, line_no, out["inventory_id"])
        if ob["obligation_id"] in seen:
            raise InventoryError(
                "duplicate obligation_id %r" % ob["obligation_id"],
                line_no,
                "duplicate_obligation",
            )
        seen.add(ob["obligation_id"])
        items.add(ob["item_id"])
        out["obligations"].append(ob)
    if first:
        raise InventoryError("inventory has no header", 1, "empty")
    out["source_lines"] = n
    out["item_count"] = len(items)
    return out


# ---------------------------------------------------------------------------
# 流式导入（整份事务；失败回滚，不留半份）
# ---------------------------------------------------------------------------

def _inventory_rel_path(inventory_id):
    # inventory_id 允许任意可打印文本；落盘名用哈希，避免路径注入。
    digest = hashlib.sha256(inventory_id.encode("utf-8")).hexdigest()[:24]
    return "inventories/%s.jsonl" % digest


def import_inventory(conn, repo_root, inventory_path):
    """
    导入一份清单。整份校验后单事务写入；任一行失败 -> 回滚并删除副本。
    inventory_id 已存在且来源哈希相同 -> 幂等复用；内容不同 -> 拒绝。
    """
    inventory_path = os.path.abspath(inventory_path)
    try:
        with open(inventory_path, "rb") as fp:
            source_sha, source_bytes, source_lines = _first_nonempty_line_info(fp)
    except InventoryError:
        raise
    except OSError as exc:
        raise InventoryError(
            "cannot read inventory: %s" % exc, None, "io_error"
        )

    conn.execute("BEGIN IMMEDIATE")
    stored_abs = None
    tmp_abs = None
    try:
        seen_hasher = hashlib.sha256()
        n_lines = 0
        inventory_id = None
        with open(inventory_path, "rb") as fp:
            first = True
            for line_no, text in _iter_physical_lines(fp, seen_hasher):
                n_lines += 1
                if text.strip() == "":
                    raise InventoryError(
                        "blank line in inventory", line_no, "blank_line"
                    )
                rec = _parse_json_object(text, line_no)
                if first:
                    inventory_id, fv, note = validate_header(rec)
                    existing = conn.execute(
                        "SELECT source_sha256 FROM inventories WHERE "
                        "inventory_id=?",
                        (inventory_id,),
                    ).fetchone()
                    if existing is not None:
                        conn.rollback()
                        if existing["source_sha256"] == source_sha:
                            return _inventory_summary(
                                conn, inventory_id, reused=True
                            )
                        raise InventoryError(
                            "inventory_id %r already imported with different "
                            "content (existing sha256=%s, new sha256=%s)"
                            % (inventory_id, existing["source_sha256"],
                               source_sha),
                            None,
                            "inventory_id_conflict",
                        )
                    conn.execute(
                        "INSERT INTO inventories(inventory_id,batch_note,"
                        "format_version,source_sha256,source_bytes,source_lines,"
                        "obligation_count,item_count,imported_at,stored_path) "
                        "VALUES(?,?,?,?,?,?,?,?,?,?)",
                        (
                            inventory_id,
                            note,
                            fv,
                            source_sha,
                            source_bytes,
                            source_lines,
                            0,
                            0,
                            _now(),
                            _inventory_rel_path(inventory_id),
                        ),
                    )
                    first = False
                    continue
                if inventory_id is None:
                    raise InventoryError(
                        "inventory has no readable header", 1, "bad_header"
                    )
                ob = validate_obligation(rec, line_no, inventory_id)
                dup = conn.execute(
                    "SELECT source_line FROM inventory_obligations WHERE "
                    "inventory_id=? AND obligation_id=?",
                    (inventory_id, ob["obligation_id"]),
                ).fetchone()
                if dup is not None:
                    raise InventoryError(
                        "duplicate obligation_id %r (first seen at line %d)"
                        % (ob["obligation_id"], dup["source_line"]),
                        line_no,
                        "duplicate_obligation",
                    )
                conn.execute(
                    "INSERT INTO inventory_obligations(inventory_id,"
                    "obligation_id,item_id,note,source_line) VALUES(?,?,?,?,?)",
                    (
                        inventory_id,
                        ob["obligation_id"],
                        ob["item_id"],
                        ob["note"],
                        line_no,
                    ),
                )
                conn.executemany(
                    "INSERT INTO inventory_acceptable(inventory_id,"
                    "obligation_id,id_type,id_value,ord,source_line) "
                    "VALUES(?,?,?,?,?,?)",
                    [
                        (inventory_id, ob["obligation_id"], t, v, ord_, line_no)
                        for ord_, (t, v) in enumerate(ob["candidates"])
                    ],
                )
        if first:
            raise InventoryError("inventory has no header", 1, "empty")
        if n_lines != source_lines:
            raise InventoryError(
                "inventory changed while being imported (line count %d != %d)"
                % (n_lines, source_lines),
                None,
                "source_changed",
            )
        if seen_hasher.hexdigest() != source_sha:
            raise InventoryError(
                "inventory changed while being imported (sha256 mismatch)",
                None,
                "source_changed",
            )

        # 统计并回填
        conn.execute(
            "UPDATE inventories SET obligation_count=("
            "SELECT COUNT(*) FROM inventory_obligations WHERE inventory_id=?),"
            "item_count=(SELECT COUNT(DISTINCT item_id) FROM "
            "inventory_obligations WHERE inventory_id=?) WHERE inventory_id=?",
            (inventory_id, inventory_id, inventory_id),
        )

        # 原始清单副本（校验通过的字节，用于争议定位）：临时文件 + 原子改名
        rel = _inventory_rel_path(inventory_id)
        stored_abs = os.path.join(repo_root, rel)
        os.makedirs(os.path.dirname(stored_abs), exist_ok=True)
        tmp_abs = stored_abs + ".tmp-%d" % os.getpid()
        with open(inventory_path, "rb") as src, open(tmp_abs, "wb") as dst:
            while True:
                chunk = src.read(1 << 20)
                if not chunk:
                    break
                dst.write(chunk)
            dst.flush()
            os.fsync(dst.fileno())
        os.replace(tmp_abs, stored_abs)
        tmp_abs = None
        conn.commit()
    except Exception:
        try:
            conn.rollback()
        except Exception:
            pass
        for leftover in (tmp_abs,):
            if leftover:
                try:
                    os.remove(leftover)
                except OSError:
                    pass
        # stored_abs 只在 commit 前才 replace；异常时若已 replace 则删除
        if stored_abs and os.path.exists(stored_abs):
            row = conn.execute(
                "SELECT 1 FROM inventories WHERE stored_path=?",
                (os.path.relpath(stored_abs, repo_root),),
            ).fetchone()
            if row is None:
                try:
                    os.remove(stored_abs)
                except OSError:
                    pass
        raise

    return _inventory_summary(conn, inventory_id, reused=False)


def _inventory_summary(conn, inventory_id, reused):
    inv = conn.execute(
        "SELECT * FROM inventories WHERE inventory_id=?", (inventory_id,)
    ).fetchone()
    return {
        "inventory_id": inv["inventory_id"],
        "batch_note": inv["batch_note"],
        "format_version": inv["format_version"],
        "source_sha256": inv["source_sha256"],
        "source_bytes": inv["source_bytes"],
        "source_lines": inv["source_lines"],
        "obligation_count": inv["obligation_count"],
        "item_count": inv["item_count"],
        "imported_at": inv["imported_at"],
        "reused": reused,
    }


def list_inventories(conn):
    rows = conn.execute(
        "SELECT i.inventory_id,i.batch_note,i.format_version,i.source_sha256,"
        "i.source_bytes,i.source_lines,i.imported_at,i.obligation_count,"
        "i.item_count,"
        "(SELECT COUNT(*) FROM reconciliation_reports r "
        " WHERE r.inventory_id=i.inventory_id) AS report_count "
        "FROM inventories i ORDER BY i.inventory_id"
    ).fetchall()
    return [dict(r) for r in rows]


def get_inventory(conn, inventory_id):
    inv = conn.execute(
        "SELECT * FROM inventories WHERE inventory_id=?", (inventory_id,)
    ).fetchone()
    if inv is None:
        raise InventoryError(
            "unknown inventory_id %r" % inventory_id, None, "unknown_inventory"
        )
    obligations = []
    for ob in conn.execute(
        "SELECT obligation_id,item_id,note,source_line FROM "
        "inventory_obligations WHERE inventory_id=? "
        "ORDER BY obligation_id",
        (inventory_id,),
    ).fetchall():
        cand = conn.execute(
            "SELECT id_type,id_value,ord FROM inventory_acceptable "
            "WHERE inventory_id=? AND obligation_id=? ORDER BY ord",
            (inventory_id, ob["obligation_id"]),
        ).fetchall()
        obligations.append(
            {
                "obligation_id": ob["obligation_id"],
                "item_id": ob["item_id"],
                "note": ob["note"],
                "source_line": ob["source_line"],
                "acceptable_representations": [
                    {"identifierType": c["id_type"],
                     "identifierValue": c["id_value"]}
                    for c in cand
                ],
            }
        )
    return {
        "inventory_id": inv["inventory_id"],
        "batch_note": inv["batch_note"],
        "format_version": inv["format_version"],
        "source_sha256": inv["source_sha256"],
        "source_bytes": inv["source_bytes"],
        "source_lines": inv["source_lines"],
        "obligation_count": inv["obligation_count"],
        "item_count": inv["item_count"],
        "imported_at": inv["imported_at"],
        "obligations": obligations,
    }
