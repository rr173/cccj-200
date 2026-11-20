# -*- coding: utf-8 -*-
"""
格式签名目录（format signature catalog）的严格校验与登记。

目录是**有版本号的无 BOM UTF-8 JSONL**（逐行一个 JSON 对象）：

  第 1 行（头记录，必须有）：
    {"record_type":"catalog_header","format_version":"format-catalog/v1",
     "catalog_id":"preservation-formats","catalog_version":"2026-11",
     "note":"可选说明"}
  格式行（每种格式一条，给出稳定标识与可读名称）：
    {"record_type":"format","format_id":"fmt.png",
     "name":"Portable Network Graphics"}
  签名行（每条签名一条，归属一个已声明格式）：
    {"record_type":"signature","signature_id":"sig.png.magic",
     "format_id":"fmt.png",
     "required":[{"bytes":"89504e470d0a1a0a","offset":0}],
     "forbidden":[{"bytes":"4d4d","window":[0,4],"mask":"ffff"}]}

片段（fragment）规则：
  - "bytes"：偶数长度十六进制，1..MAX_FRAGMENT_BYTES 字节；
  - "mask"：可选，与 bytes 等长的十六进制；逐字节掩码，仅当
    (实际字节 & mask) == (模式字节 & mask) 逐字节成立时片段匹配；
  - 定位二选一："offset" 固定偏移（非负整数，<= MAX_OFFSET）；
    或 "window": [start, end]（非负整数、start <= end、
    end - start <= MAX_WINDOW_SPAN），片段可在该闭区间内任一起始偏移匹配；
  - 不允许其他字段。

签名语义：全部 required 片段都匹配、且全部 forbidden 片段都不匹配时，
签名命中。目录行序与签名内片段顺序都不影响结果：登记时把解析内容
规范化（排序）后取内容摘要 catalog_sha256 作为目录版本的内容地址。

登记是**整份接受或整份拒绝**的事务：任一行错误都回滚，仓内不会留下
半份可用目录。相同 (catalog_id, catalog_version) 重复登记且规范化内容
摘要一致时幂等复用；内容不同则拒绝。

内存边界：逐行流式解析（单行上限 MAX_LINE_BYTES，行数上限
MAX_CATALOG_LINES），不把整份目录读入 Python 内存；两遍读取
（先算来源哈希，再校验并写库），第二遍复核哈希。
"""
from __future__ import annotations

import datetime
import hashlib
import json
import os
import re

CATALOG_FORMAT = "format-catalog/v1"

# 资源上限（明确、可引用）：单行、行数、片段、窗口、偏移。
MAX_LINE_BYTES = 1 << 20            # 单行 JSONL 上限（控制元数据）
MAX_CATALOG_LINES = 4096            # 目录总行数上限（含表头）
MAX_FRAGMENT_BYTES = 256            # 单个片段模式字节数上限
MAX_FRAGMENTS_PER_SIGNATURE = 32    # 单条签名的 required+forbidden 片段总数上限
MAX_WINDOW_SPAN = 1 << 20           # 搜索窗口跨度（end - start）上限
MAX_OFFSET = 1 << 48                # 偏移/窗口端点上限

# 稳定标识：保守 ASCII 字符集（字母数字开头，可含 . _ / : -），长度 1..128。
IDENT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/:-]{0,127}$")
HEX_RE = re.compile(r"^[0-9a-fA-F]*$")

HEADER_KEYS = {"record_type", "format_version", "catalog_id",
               "catalog_version", "note"}
FORMAT_KEYS = {"record_type", "format_id", "name"}
SIGNATURE_KEYS = {"record_type", "signature_id", "format_id",
                  "required", "forbidden"}
FRAGMENT_KEYS = {"bytes", "mask", "offset", "window"}


class CatalogError(Exception):
    """目录无效（整份拒绝，绝不留下半份可用版本）。"""

    def __init__(self, message, line=None, code=None):
        super().__init__(message)
        self.line = line
        self.code = code or "invalid_catalog"
        self.message = message

    def as_dict(self):
        return {"error": self.code, "line": self.line, "message": self.message}


def _now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def _canon(obj):
    return json.dumps(
        obj, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def _sha(data):
    return hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------------------
# 物理行读取（与 inventory/release_rules 同一套严格语义）
# ---------------------------------------------------------------------------

def _iter_physical_lines(fp, hasher=None):
    lineno = 0
    while True:
        raw = fp.readline(MAX_LINE_BYTES + 2)
        if not raw:
            break
        lineno += 1
        if lineno > MAX_CATALOG_LINES:
            raise CatalogError(
                "catalog exceeds %d lines" % MAX_CATALOG_LINES,
                lineno,
                "catalog_too_large",
            )
        if hasher is not None:
            hasher.update(raw)
        if not raw.endswith(b"\n") and len(raw) > MAX_LINE_BYTES:
            raise CatalogError(
                "line exceeds %d bytes" % MAX_LINE_BYTES,
                lineno,
                "line_too_long",
            )
        chunk = raw[:-1] if raw.endswith(b"\n") else raw
        if chunk.endswith(b"\r"):
            chunk = chunk[:-1]
        if b"\r" in chunk:
            raise CatalogError(
                "bare CR in line (use LF or CRLF line endings)",
                lineno,
                "bad_encoding",
            )
        if len(chunk) > MAX_LINE_BYTES:
            raise CatalogError(
                "line exceeds %d bytes" % MAX_LINE_BYTES,
                lineno,
                "line_too_long",
            )
        try:
            text = chunk.decode("utf-8", "strict")
        except UnicodeDecodeError as exc:
            raise CatalogError(
                "line is not valid UTF-8: %s" % exc, lineno, "bad_encoding"
            )
        yield lineno, text


def _first_pass_info(path):
    """第一遍：来源 SHA-256 / 字节数 / 物理行数；拒绝空文件与 BOM。"""
    h = hashlib.sha256()
    size = 0
    first = b""
    n_lines = 0
    last = b""
    with open(path, "rb") as fp:
        while True:
            chunk = fp.read(1 << 20)
            if not chunk:
                break
            if not first:
                first = chunk[:3]
            h.update(chunk)
            size += len(chunk)
            n_lines += chunk.count(b"\n")
            last = chunk[-1:]
    if size == 0:
        raise CatalogError("catalog is empty", 1, "empty")
    if first == b"\xef\xbb\xbf":
        raise CatalogError(
            "catalog must be UTF-8 without BOM", 1, "bad_encoding"
        )
    if last != b"\n":
        n_lines += 1
    if n_lines > MAX_CATALOG_LINES:
        raise CatalogError(
            "catalog exceeds %d lines" % MAX_CATALOG_LINES,
            None,
            "catalog_too_large",
        )
    return h.hexdigest(), size, n_lines


# ---------------------------------------------------------------------------
# 记录校验
# ---------------------------------------------------------------------------

def _validate_text(value, what, line, allow_empty=False, max_len=256):
    if not isinstance(value, str):
        raise CatalogError("%s must be a JSON string" % what, line, "bad_type")
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in value):
        raise CatalogError(
            "%s contains control characters" % what, line, "bad_text"
        )
    if not allow_empty and value.strip() == "":
        raise CatalogError("%s must not be empty" % what, line, "bad_text")
    if len(value) > max_len:
        raise CatalogError(
            "%s exceeds %d characters" % (what, max_len), line, "bad_text"
        )
    return value


def _validate_ident(value, what, line):
    _validate_text(value, what, line, max_len=128)
    if not IDENT_RE.match(value):
        raise CatalogError(
            "%s %r is not a stable ASCII identifier "
            "(allowed: A-Z a-z 0-9 . _ / : -, must start alphanumeric)"
            % (what, value),
            line,
            "bad_identifier",
        )
    return value


def _parse_json_object(text, line_no):
    def _bad_constant(x):
        raise CatalogError(
            "non-finite JSON number %r is not allowed" % x, line_no, "bad_json"
        )

    try:
        obj = json.loads(text, parse_constant=_bad_constant)
    except CatalogError:
        raise
    except (json.JSONDecodeError, ValueError) as exc:
        raise CatalogError("invalid JSON: %s" % exc, line_no, "bad_json")
    if not isinstance(obj, dict):
        raise CatalogError(
            "each line must be a JSON object", line_no, "bad_json"
        )
    return obj


def _check_keys(rec, allowed, what, line_no):
    extra = sorted(set(rec.keys()) - allowed)
    if extra:
        raise CatalogError(
            "%s has unknown field(s) %r" % (what, extra), line_no, "bad_field"
        )


def _validate_hex(value, what, line_no):
    if not isinstance(value, str):
        raise CatalogError("%s must be a hex string" % what, line_no, "bad_type")
    if len(value) == 0 or len(value) % 2 != 0 or not HEX_RE.match(value):
        raise CatalogError(
            "%s must be non-empty even-length hexadecimal" % what,
            line_no,
            "bad_hex",
        )
    return value.lower()


def _validate_offset(value, what, line_no):
    if isinstance(value, bool) or not isinstance(value, int):
        raise CatalogError(
            "%s must be an integer" % what, line_no, "bad_offset"
        )
    if value < 0 or value > MAX_OFFSET:
        raise CatalogError(
            "%s must be between 0 and %d" % (what, MAX_OFFSET),
            line_no,
            "bad_offset",
        )
    return value


def validate_fragment(raw, line_no):
    """校验单个片段，返回规范化 dict（hex 小写、键受控）。"""
    if not isinstance(raw, dict):
        raise CatalogError(
            "fragment must be a JSON object", line_no, "bad_type"
        )
    _check_keys(raw, FRAGMENT_KEYS, "fragment", line_no)
    if "bytes" not in raw:
        raise CatalogError(
            "fragment requires 'bytes'", line_no, "missing_field"
        )
    pat = _validate_hex(raw["bytes"], "fragment bytes", line_no)
    n = len(pat) // 2
    if n > MAX_FRAGMENT_BYTES:
        raise CatalogError(
            "fragment bytes exceed %d bytes" % MAX_FRAGMENT_BYTES,
            line_no,
            "fragment_too_long",
        )
    out = {"bytes": pat}
    if "mask" in raw:
        mask = _validate_hex(raw["mask"], "fragment mask", line_no)
        if len(mask) != len(pat):
            raise CatalogError(
                "fragment mask length must equal bytes length",
                line_no,
                "bad_mask",
            )
        out["mask"] = mask
    has_offset = "offset" in raw
    has_window = "window" in raw
    if has_offset == has_window:
        raise CatalogError(
            "fragment requires exactly one of 'offset' or 'window'",
            line_no,
            "bad_position",
        )
    if has_offset:
        out["offset"] = _validate_offset(raw["offset"], "fragment offset",
                                         line_no)
    else:
        w = raw["window"]
        if not isinstance(w, list) or len(w) != 2:
            raise CatalogError(
                "fragment window must be a [start, end] pair",
                line_no,
                "bad_window",
            )
        s = _validate_offset(w[0], "window start", line_no)
        e = _validate_offset(w[1], "window end", line_no)
        if s > e:
            raise CatalogError(
                "fragment window start must not exceed end",
                line_no,
                "bad_window",
            )
        if e - s > MAX_WINDOW_SPAN:
            raise CatalogError(
                "fragment window span exceeds %d bytes" % MAX_WINDOW_SPAN,
                line_no,
                "window_too_wide",
            )
        out["window"] = [s, e]
    return out


def _frag_sort_key(frag):
    return _canon(frag)


def validate_header(rec, line_no):
    _check_keys(rec, HEADER_KEYS, "catalog header", line_no)
    if rec.get("record_type") not in (None, "catalog_header"):
        raise CatalogError(
            "first line must be the catalog header", line_no, "bad_header"
        )
    for field in ("format_version", "catalog_id", "catalog_version"):
        if field not in rec:
            raise CatalogError(
                "header requires %r" % field, line_no, "missing_field"
            )
    fv = _validate_text(rec["format_version"], "format_version", line_no)
    if fv != CATALOG_FORMAT:
        raise CatalogError(
            "unsupported format_version %r (expected %r)"
            % (fv, CATALOG_FORMAT),
            line_no,
            "bad_format_version",
        )
    catalog_id = _validate_ident(rec["catalog_id"], "catalog_id", line_no)
    version = _validate_ident(
        rec["catalog_version"], "catalog_version", line_no
    )
    note = rec.get("note", "")
    if note is None:
        note = ""
    _validate_text(note, "note", line_no, allow_empty=True, max_len=1024)
    return catalog_id, version, note


def validate_format_line(rec, line_no):
    _check_keys(rec, FORMAT_KEYS, "format record", line_no)
    if rec.get("record_type") != "format":
        raise CatalogError(
            "expected a format record, got record_type %r"
            % (rec.get("record_type"),),
            line_no,
            "bad_record",
        )
    for field in ("format_id", "name"):
        if field not in rec:
            raise CatalogError(
                "format record requires %r" % field, line_no, "missing_field"
            )
    format_id = _validate_ident(rec["format_id"], "format_id", line_no)
    name = _validate_text(rec["name"], "name", line_no)
    return {"format_id": format_id, "name": name, "source_line": line_no}


def validate_signature_line(rec, line_no):
    _check_keys(rec, SIGNATURE_KEYS, "signature record", line_no)
    if rec.get("record_type") != "signature":
        raise CatalogError(
            "unknown record_type %r" % rec.get("record_type"),
            line_no,
            "bad_record",
        )
    for field in ("signature_id", "format_id", "required"):
        if field not in rec:
            raise CatalogError(
                "signature record requires %r" % field, line_no,
                "missing_field",
            )
    signature_id = _validate_ident(rec["signature_id"], "signature_id",
                                   line_no)
    format_id = _validate_ident(rec["format_id"], "format_id", line_no)
    required = rec["required"]
    if not isinstance(required, list) or not required:
        raise CatalogError(
            "signature requires a non-empty required fragment list",
            line_no,
            "empty_required",
        )
    forbidden = rec.get("forbidden", [])
    if not isinstance(forbidden, list):
        raise CatalogError(
            "forbidden must be a JSON array", line_no, "bad_type"
        )
    if len(required) + len(forbidden) > MAX_FRAGMENTS_PER_SIGNATURE:
        raise CatalogError(
            "signature has more than %d fragments"
            % MAX_FRAGMENTS_PER_SIGNATURE,
            line_no,
            "too_many_fragments",
        )
    req = [validate_fragment(f, line_no) for f in required]
    forb = [validate_fragment(f, line_no) for f in forbidden]
    # 规范化：片段排序，使目录行序/片段顺序不影响内容摘要与结果
    req.sort(key=_frag_sort_key)
    forb.sort(key=_frag_sort_key)
    return {
        "signature_id": signature_id,
        "format_id": format_id,
        "required": req,
        "forbidden": forb,
        "source_line": line_no,
    }


# ---------------------------------------------------------------------------
# 规范化内容摘要（目录版本的内容地址；行序/片段序无关）
# ---------------------------------------------------------------------------

def canonical_catalog(catalog_id, catalog_version, note, formats, signatures):
    return {
        "format_version": CATALOG_FORMAT,
        "catalog_id": catalog_id,
        "catalog_version": catalog_version,
        "note": note,
        "formats": [
            {"format_id": f["format_id"], "name": f["name"]}
            for f in sorted(formats, key=lambda f: f["format_id"])
        ],
        "signatures": [
            {
                "signature_id": s["signature_id"],
                "format_id": s["format_id"],
                "required": s["required"],
                "forbidden": s["forbidden"],
            }
            for s in sorted(signatures, key=lambda s: s["signature_id"])
        ],
    }


def catalog_content_sha256(catalog_id, catalog_version, note, formats,
                           signatures):
    return _sha(_canon(canonical_catalog(
        catalog_id, catalog_version, note, formats, signatures
    )))


# ---------------------------------------------------------------------------
# 流式登记（整份事务；失败回滚，不留半份）
# ---------------------------------------------------------------------------

def _catalog_rel_path(catalog_id, catalog_version):
    digest = hashlib.sha256(
        (catalog_id + "\x1f" + catalog_version).encode("utf-8")
    ).hexdigest()[:24]
    return "catalogs/%s.jsonl" % digest


def register_catalog(conn, repo_root, catalog_path):
    """
    登记一份目录版本。整份校验后单事务写入；任一行失败 -> 回滚，不留半份。
    (catalog_id, catalog_version) 已存在且规范化内容摘要相同 -> 幂等复用；
    内容不同 -> 拒绝。
    """
    catalog_path = os.path.abspath(catalog_path)
    try:
        source_sha, source_bytes, source_lines = _first_pass_info(catalog_path)
    except CatalogError:
        raise
    except OSError as exc:
        raise CatalogError(
            "cannot read catalog: %s" % exc, None, "io_error"
        )

    conn.execute("BEGIN IMMEDIATE")
    stored_abs = None
    tmp_abs = None
    try:
        seen_hasher = hashlib.sha256()
        n_lines = 0
        catalog_id = catalog_version = note = None
        formats = []
        signatures = []
        seen_formats = set()
        seen_signatures = set()
        with open(catalog_path, "rb") as fp:
            first = True
            for line_no, text in _iter_physical_lines(fp, seen_hasher):
                n_lines += 1
                if text.strip() == "":
                    raise CatalogError(
                        "blank line in catalog", line_no, "blank_line"
                    )
                rec = _parse_json_object(text, line_no)
                if first:
                    catalog_id, catalog_version, note = validate_header(
                        rec, line_no
                    )
                    existing = conn.execute(
                        "SELECT catalog_sha256 FROM format_catalogs WHERE "
                        "catalog_id=? AND catalog_version=?",
                        (catalog_id, catalog_version),
                    ).fetchone()
                    if existing is not None:
                        # 需要完整解析才能比较规范化摘要：先记下，继续解析
                        existing_sha = existing["catalog_sha256"]
                    else:
                        existing_sha = None
                    first = False
                    continue
                rtype = rec.get("record_type")
                if rtype == "format":
                    fmt = validate_format_line(rec, line_no)
                    if fmt["format_id"] in seen_formats:
                        raise CatalogError(
                            "duplicate format_id %r" % fmt["format_id"],
                            line_no,
                            "duplicate_format",
                        )
                    seen_formats.add(fmt["format_id"])
                    formats.append(fmt)
                elif rtype == "signature":
                    sig = validate_signature_line(rec, line_no)
                    if sig["signature_id"] in seen_signatures:
                        raise CatalogError(
                            "duplicate signature_id %r" % sig["signature_id"],
                            line_no,
                            "duplicate_signature",
                        )
                    seen_signatures.add(sig["signature_id"])
                    signatures.append(sig)
                else:
                    raise CatalogError(
                        "unknown record_type %r" % rtype, line_no, "bad_record"
                    )
        if first:
            raise CatalogError("catalog has no header", 1, "empty")
        if not formats:
            raise CatalogError(
                "catalog declares no formats", None, "empty_formats"
            )
        if not signatures:
            raise CatalogError(
                "catalog declares no signatures", None, "empty_signatures"
            )
        # 签名引用的格式必须已在本目录内声明（与行序无关，整份解析后核对）
        for sig in signatures:
            if sig["format_id"] not in seen_formats:
                raise CatalogError(
                    "signature %r references undeclared format_id %r"
                    % (sig["signature_id"], sig["format_id"]),
                    sig["source_line"],
                    "unknown_format",
                )
        if n_lines != source_lines:
            raise CatalogError(
                "catalog changed while being registered (line count %d != %d)"
                % (n_lines, source_lines),
                None,
                "source_changed",
            )
        if seen_hasher.hexdigest() != source_sha:
            raise CatalogError(
                "catalog changed while being registered (sha256 mismatch)",
                None,
                "source_changed",
            )

        content_sha = catalog_content_sha256(
            catalog_id, catalog_version, note, formats, signatures
        )
        if existing_sha is not None:
            conn.rollback()
            if existing_sha == content_sha:
                return _catalog_summary(
                    conn, catalog_id, catalog_version, reused=True
                )
            raise CatalogError(
                "catalog %r version %r already registered with different "
                "content (existing sha256=%s, new sha256=%s)"
                % (catalog_id, catalog_version, existing_sha, content_sha),
                None,
                "catalog_version_conflict",
            )

        conn.execute(
            "INSERT INTO format_catalogs(catalog_id,catalog_version,"
            "catalog_sha256,note,source_sha256,source_bytes,source_lines,"
            "format_count,signature_count,registered_at,stored_path) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (
                catalog_id,
                catalog_version,
                content_sha,
                note,
                source_sha,
                source_bytes,
                source_lines,
                len(formats),
                len(signatures),
                _now(),
                _catalog_rel_path(catalog_id, catalog_version),
            ),
        )
        conn.executemany(
            "INSERT INTO catalog_formats(catalog_sha256,format_id,name,"
            "source_line) VALUES(?,?,?,?)",
            [
                (content_sha, f["format_id"], f["name"], f["source_line"])
                for f in formats
            ],
        )
        conn.executemany(
            "INSERT INTO catalog_signatures(catalog_sha256,signature_id,"
            "format_id,spec,source_line) VALUES(?,?,?,?,?)",
            [
                (
                    content_sha,
                    s["signature_id"],
                    s["format_id"],
                    _canon({
                        "signature_id": s["signature_id"],
                        "format_id": s["format_id"],
                        "required": s["required"],
                        "forbidden": s["forbidden"],
                    }).decode("utf-8"),
                    s["source_line"],
                )
                for s in signatures
            ],
        )

        # 原始目录副本（校验通过的字节，用于争议定位）：临时文件 + 原子改名
        rel = _catalog_rel_path(catalog_id, catalog_version)
        stored_abs = os.path.join(repo_root, rel)
        os.makedirs(os.path.dirname(stored_abs), exist_ok=True)
        tmp_abs = stored_abs + ".tmp-%d" % os.getpid()
        with open(catalog_path, "rb") as src, open(tmp_abs, "wb") as dst:
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
        if tmp_abs:
            try:
                os.remove(tmp_abs)
            except OSError:
                pass
        if stored_abs and os.path.exists(stored_abs):
            row = conn.execute(
                "SELECT 1 FROM format_catalogs WHERE stored_path=?",
                (os.path.relpath(stored_abs, repo_root),),
            ).fetchone()
            if row is None:
                try:
                    os.remove(stored_abs)
                except OSError:
                    pass
        raise

    return _catalog_summary(conn, catalog_id, catalog_version, reused=False)


def _catalog_summary(conn, catalog_id, catalog_version, reused):
    row = conn.execute(
        "SELECT * FROM format_catalogs WHERE catalog_id=? AND "
        "catalog_version=?",
        (catalog_id, catalog_version),
    ).fetchone()
    return {
        "catalog_id": row["catalog_id"],
        "catalog_version": row["catalog_version"],
        "catalog_sha256": row["catalog_sha256"],
        "note": row["note"],
        "source_sha256": row["source_sha256"],
        "source_bytes": row["source_bytes"],
        "source_lines": row["source_lines"],
        "format_count": row["format_count"],
        "signature_count": row["signature_count"],
        "registered_at": row["registered_at"],
        "reused": reused,
    }


def list_catalogs(conn):
    rows = conn.execute(
        "SELECT catalog_id,catalog_version,catalog_sha256,note,source_sha256,"
        "source_bytes,source_lines,format_count,signature_count,registered_at "
        "FROM format_catalogs ORDER BY catalog_id, catalog_version"
    ).fetchall()
    return [dict(r) for r in rows]


def get_catalog(conn, catalog_id, catalog_version):
    row = conn.execute(
        "SELECT * FROM format_catalogs WHERE catalog_id=? AND "
        "catalog_version=?",
        (catalog_id, catalog_version),
    ).fetchone()
    if row is None:
        raise CatalogError(
            "unknown catalog %r version %r" % (catalog_id, catalog_version),
            None,
            "unknown_catalog",
        )
    formats = [
        {"format_id": r["format_id"], "name": r["name"],
         "source_line": r["source_line"]}
        for r in conn.execute(
            "SELECT format_id,name,source_line FROM catalog_formats WHERE "
            "catalog_sha256=? ORDER BY format_id",
            (row["catalog_sha256"],),
        ).fetchall()
    ]
    signatures = []
    for r in conn.execute(
        "SELECT signature_id,spec,source_line FROM catalog_signatures WHERE "
        "catalog_sha256=? ORDER BY signature_id",
        (row["catalog_sha256"],),
    ).fetchall():
        spec = json.loads(r["spec"])
        spec["source_line"] = r["source_line"]
        signatures.append(spec)
    return {
        "catalog_id": row["catalog_id"],
        "catalog_version": row["catalog_version"],
        "catalog_sha256": row["catalog_sha256"],
        "note": row["note"],
        "source_sha256": row["source_sha256"],
        "source_bytes": row["source_bytes"],
        "source_lines": row["source_lines"],
        "format_count": row["format_count"],
        "signature_count": row["signature_count"],
        "registered_at": row["registered_at"],
        "formats": formats,
        "signatures": signatures,
    }


def load_catalog_for_matching(conn, catalog_id, catalog_version):
    """
    供画像引擎使用：取出目录绑定信息与规范化签名定义（不编译，编译在
    扫描进程内按需进行）。未知目录抛 CatalogError。
    """
    cat = get_catalog(conn, catalog_id, catalog_version)
    return {
        "catalog_id": cat["catalog_id"],
        "catalog_version": cat["catalog_version"],
        "catalog_sha256": cat["catalog_sha256"],
        "format_count": cat["format_count"],
        "signature_count": cat["signature_count"],
        "formats": cat["formats"],
        "signatures": [
            {
                "signature_id": s["signature_id"],
                "format_id": s["format_id"],
                "required": s["required"],
                "forbidden": s["forbidden"],
            }
            for s in cat["signatures"]
        ],
    }
