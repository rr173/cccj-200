# -*- coding: utf-8 -*-
"""
封存对象格式画像引擎（format profiling）。

回答“仓里有哪些文件格式、判断依据是什么、哪些对象需要人工识别”。
画像用于保存与盘点：**不执行格式转换**，也不改变对象身份、谱系结论
（obj_status / 表示标签）或对外发布许可；本模块只读既有事实表，
画像结果写入独立的 format_profiles 登记与 profiles/ 下的不可变文件。

范围与身份
----------
- 只纳入**指定一组已封存（sealed）包**中声明的 bitstream 身份；
  staging 包不得进入（范围校验直接拒绝）。
- 按精确 (identifierType, identifierValue) 展开事实：同一身份在多个
  范围内包重复声明只记录一次（package_ids 列出全部来源）；相同字节但
  身份不同的对象是不同记录，分别列出。
- 表示（representation）、METS 结构节点不是 bitstream 身份，绝不计入。

字节核对
--------
画像前重新读取被引用的封存载荷（仓内 stored_path），分块核对实际长度
与 SHA-256；缺失、损坏、身份冲突的对象**不被签名命中掩盖**，给出相应
状态与出处（copies[] 逐副本记录仓内状态与本次复核结果）。

匹配语义（与目录行序无关）
--------------------------
对字节有效的对象，求出目录中**所有**完整命中的签名：
  - 无命中 -> unidentified；
  - 全部命中指向同一格式 -> identified（保留全部命中签名）；
  - 命中指向多个格式 -> ambiguous（绝不按目录顺序或首个命中静默挑选）。
证据逐条指出签名、片段偏移与匹配字节（不只是格式名称）。

资源边界
--------
- 载荷按区域读取：每个片段的扫描区域 <= 窗口跨度上限 + 片段长度上限，
  相邻区域在不超限前提下合并；每次读入内存的区域有界（MAX_REGION_BYTES），
  且单次 read 不超过 CHUNK_SIZE；绝不把整个载荷读入内存。
- 掩码比较编译为等价的字节正则（lookahead 找全部重叠命中），常数内存。
- 允许按内容摘要复用签名扫描（同一运行内），但每个精确对象身份仍独立
  写入结果；每次运行都重新验证其仓内字节来源与输入绑定。

不可变结果
----------
每次画像生成一个不可变结果，绑定规范化目录内容摘要、实际封存包集合
及其清单摘要；profile_id 为业务内容寻址。相同输入重跑得到相同业务
结果与稳定标识（复用既有结果，不重写）；新增封包或新目录版本只会
产生新结果，不改写旧结果。
"""
from __future__ import annotations

import datetime
import hashlib
import json
import os
import re
import sqlite3

from . import format_catalog as fc
from .util import (
    CHUNK_SIZE,
    ST_BYTES_CORRUPT,
    ST_BYTES_MISSING,
    ST_BYTES_OK,
    ST_IDENTITY_CONFLICT,
    ST_NOT_RECEIVED,
    safe_relpath,
)

PROFILE_PROFILE = "offline-evidence-repo/format-profile/v1"
ENGINE_VERSION = "format-profile/v1"

# 结果状态
R_IDENTIFIED = "identified"
R_AMBIGUOUS = "ambiguous"
R_UNIDENTIFIED = "unidentified"

# 单条片段证据中记录的命中偏移上限（另有 match_count 记录总数）
MAX_EVIDENCE_OFFSETS = 8
# 单次读入内存的扫描区域上限：必须 >= 窗口跨度上限 + 片段长度上限，
# 这样任一片段区域都能完整落入一个合并区域。
MAX_REGION_BYTES = fc.MAX_WINDOW_SPAN + fc.MAX_FRAGMENT_BYTES

# 复核结论（画像时对仓内字节的实际重读结果）
VERIFY_OK = "ok"
VERIFY_MISSING = "stored_file_missing"
VERIFY_LENGTH = "length_mismatch"
VERIFY_SHA = "sha256_mismatch"


class ProfileError(Exception):
    def __init__(self, message, code=None):
        super().__init__(message)
        self.message = message
        self.code = code or "profile_error"

    def as_dict(self):
        return {"error": self.code, "message": self.message}


def _now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def _canon(obj):
    return json.dumps(
        obj, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def sealed_package_set(conn):
    return sorted(
        r[0]
        for r in conn.execute(
            "SELECT package_id FROM packages WHERE state='sealed' "
            "ORDER BY package_id"
        ).fetchall()
    )


def package_set_sha256(pkg_set):
    return _sha(_canon(sorted(pkg_set)))


# ===========================================================================
# 片段编译与区域扫描（有界内存；掩码 -> 等价字节正则）
# ===========================================================================

class _CompiledFragment:
    """一个片段的扫描计划：候选起始偏移区间 + 匹配器。"""

    __slots__ = ("spec", "pat", "mask", "cand_lo", "cand_hi", "plen",
                 "kind", "regex")

    def __init__(self, spec):
        self.spec = spec
        self.pat = bytes.fromhex(spec["bytes"])
        self.mask = bytes.fromhex(spec["mask"]) if "mask" in spec else None
        self.plen = len(self.pat)
        if "offset" in spec:
            self.cand_lo = self.cand_hi = spec["offset"]
        else:
            self.cand_lo, self.cand_hi = spec["window"]
        if self.mask is None or all(m == 0xFF for m in self.mask):
            self.kind = "plain"
            self.regex = None
        elif all(m == 0x00 for m in self.mask):
            self.kind = "any"
            self.regex = None
        else:
            self.kind = "regex"
            self.regex = self._compile_masked()

    def _compile_masked(self):
        """
        把逐字节掩码比较编译为等价字节正则：
          mask=0xFF -> 字面字节；mask=0x00 -> 任意字节；
          其余 -> 满足 (v & mask) == (pat & mask) 的字节类。
        用零宽 lookahead 包住，使 finditer 能找到全部重叠命中。
        """
        parts = []
        for i, m in enumerate(self.mask):
            if m == 0xFF:
                parts.append(re.escape(bytes([self.pat[i]])))
            elif m == 0x00:
                parts.append(b".")
            else:
                target = self.pat[i] & m
                charset = bytes(
                    v for v in range(256) if (v & m) == target
                )
                parts.append(b"[" + re.escape(charset) + b"]")
        return re.compile(b"(?=(" + b"".join(parts) + b"))", re.DOTALL)

    def region(self):
        """该片段需要读取的文件区域 [lo, hi)（hi 不含）。"""
        return self.cand_lo, self.cand_hi + self.plen


def _search_fragment(frag, buf, region_lo, filesize):
    """
    在合并区域缓冲 buf（文件 [region_lo, region_lo+len(buf)) 的实际字节）
    中搜索片段，返回 (match_count, first_offsets, matched_bytes)。
    搜索严格限制在片段自己的候选区间 [cand_lo, cand_hi]：合并区域可能
    覆盖更大范围，候选区间外的命中不算数。
    first_offsets 至多 MAX_EVIDENCE_OFFSETS 个（升序）；matched_bytes 为
    第一个命中处的实际载荷字节（无命中为 None）。
    """
    if frag.kind == "any":
        # 全通配：候选区间内每个能完整容纳片段的偏移都命中
        last = min(frag.cand_hi, filesize - frag.plen)
        count = last - frag.cand_lo + 1
        if count <= 0:
            return 0, [], None
        offsets = list(
            range(frag.cand_lo,
                  frag.cand_lo + min(count, MAX_EVIDENCE_OFFSETS))
        )
        first = offsets[0]
        matched = bytes(buf[first - region_lo: first - region_lo + frag.plen])
        return count, offsets, matched

    # 从合并缓冲中切出本片段的扫描区域 [cand_lo, cand_hi+plen)
    # （靠近 EOF 时 buf 已截短，切片随之变短，匹配自然受限）
    base = frag.cand_lo - region_lo
    end = frag.cand_hi + frag.plen - region_lo
    sub = buf[base:end]
    offsets = []
    count = 0
    if frag.kind == "plain":
        start = 0
        pat = frag.pat
        while True:
            i = sub.find(pat, start)
            if i < 0:
                break
            count += 1
            if len(offsets) < MAX_EVIDENCE_OFFSETS:
                offsets.append(frag.cand_lo + i)
            start = i + 1
    else:
        for m in frag.regex.finditer(sub):
            count += 1
            if len(offsets) < MAX_EVIDENCE_OFFSETS:
                offsets.append(frag.cand_lo + m.start())
    if not count:
        return 0, [], None
    first = offsets[0]
    matched = bytes(buf[first - region_lo: first - region_lo + frag.plen])
    return count, offsets, matched


def _read_region(fp, lo, hi, filesize):
    """分块读取文件区域 [lo, hi)（按 EOF 截断），单次 read <= CHUNK_SIZE。"""
    if lo >= filesize or hi <= lo:
        return b""
    hi = min(hi, filesize)
    fp.seek(lo)
    parts = []
    remaining = hi - lo
    while remaining > 0:
        chunk = fp.read(min(CHUNK_SIZE, remaining))
        if not chunk:
            break  # 文件在读取期间被截短：按实际可得字节处理
        parts.append(chunk)
        remaining -= len(chunk)
    return b"".join(parts)


def scan_content(path, filesize, compiled_signatures):
    """
    对一个已核对长度/摘要的载荷执行全部签名扫描，返回命中签名证据列表
    （按 signature_id 排序）。只按片段区域分块读取，内存有界。
    compiled_signatures: [{"signature_id","format_id",
                           "required":[_CompiledFragment...],
                           "forbidden":[_CompiledFragment...]}]
    """
    # 去重：相同规范化片段（不同签名可能共用）只扫描一次
    uniq = {}
    for sig in compiled_signatures:
        for frag in sig["required"] + sig["forbidden"]:
            key = _canon(frag.spec)
            if key not in uniq:
                uniq[key] = frag
    # 规划合并区域：按起点排序后，相邻且合并不超限的区域一次读入
    items = sorted(uniq.values(), key=lambda f: (f.cand_lo, f.cand_hi))
    merged = []  # [lo, hi, [frag...]]
    for frag in items:
        lo, hi = frag.region()
        if merged and max(merged[-1][1], hi) - merged[-1][0] \
                <= MAX_REGION_BYTES:
            merged[-1][1] = max(merged[-1][1], hi)
            merged[-1][2].append(frag)
        else:
            merged.append([lo, hi, [frag]])
    # 逐区域读取并搜索（区域间相互独立，顺序不影响结果）
    found = {}  # canon(spec) -> (count, offsets, matched)
    with open(path, "rb") as fp:
        for lo, hi, frags in merged:
            buf = _read_region(fp, lo, hi, filesize)
            for frag in frags:
                found[_canon(frag.spec)] = _search_fragment(
                    frag, buf, lo, filesize
                )
    # 组装命中签名（全部命中，不按目录顺序挑选）
    hits = []
    for sig in compiled_signatures:
        ev_required = []
        ok = True
        for frag in sig["required"]:
            count, offsets, matched = found[_canon(frag.spec)]
            if count == 0:
                ok = False
                break
            ev_required.append({
                "fragment": frag.spec,
                "match_count": count,
                "offsets": offsets,
                "matched_bytes": matched.hex(),
            })
        if not ok:
            continue
        ev_forbidden = []
        for frag in sig["forbidden"]:
            count, offsets, _matched = found[_canon(frag.spec)]
            if count != 0:
                ok = False
                break
            ev_forbidden.append({
                "fragment": frag.spec,
                "match_count": 0,
                "offsets": [],
            })
        if not ok:
            continue
        hits.append({
            "signature_id": sig["signature_id"],
            "format_id": sig["format_id"],
            "required": ev_required,
            "forbidden": ev_forbidden,
        })
    hits.sort(key=lambda h: h["signature_id"])
    return hits


def compile_signatures(signatures):
    """把目录签名定义编译为扫描计划（每运行一次；规模受目录上限约束）。"""
    out = []
    for sig in signatures:
        out.append({
            "signature_id": sig["signature_id"],
            "format_id": sig["format_id"],
            "required": [_CompiledFragment(f) for f in sig["required"]],
            "forbidden": [_CompiledFragment(f) for f in sig["forbidden"]],
        })
    # 结果与目录行序无关：统一按 signature_id 处理
    out.sort(key=lambda s: s["signature_id"])
    return out


# ===========================================================================
# 范围内事实展开（只看指定 sealed 包集合）
# ===========================================================================

def _scope_identities(conn, pkg_set):
    """范围内声明为 bitstream 的精确身份集合（按身份排序）。"""
    marks = ",".join("?" for _ in pkg_set)
    rows = conn.execute(
        "SELECT DISTINCT id_type, id_value FROM objects "
        "WHERE category='bitstream' AND package_id IN (%s) "
        "ORDER BY id_type, id_value" % marks,
        pkg_set,
    ).fetchall()
    return [(r["id_type"], r["id_value"]) for r in rows]


def _scope_identity_packages(conn, pkg_set, id_type, id_value):
    marks = ",".join("?" for _ in pkg_set)
    rows = conn.execute(
        "SELECT DISTINCT package_id FROM objects WHERE id_type=? AND "
        "id_value=? AND package_id IN (%s) ORDER BY package_id" % marks,
        [id_type, id_value] + list(pkg_set),
    ).fetchall()
    return [r["package_id"] for r in rows]


def _scope_copies(conn, pkg_set, id_type, id_value):
    """范围内该身份的全部成员副本（含仓内状态），按 (包, 路径) 排序。"""
    marks = ",".join("?" for _ in pkg_set)
    rows = conn.execute(
        "SELECT ob.package_id AS package_id, ob.blob_rel AS rel_path, "
        "b.state AS state, b.declared_sha AS declared_sha, "
        "b.actual_sha AS actual_sha, b.size_decl AS size_decl, "
        "b.size_actual AS size_actual, b.stored_path AS stored_path "
        "FROM object_blobs ob JOIN blobs b ON b.package_id=ob.package_id "
        "AND b.rel_path=ob.blob_rel "
        "WHERE ob.id_type=? AND ob.id_value=? AND ob.package_id IN (%s) "
        "ORDER BY ob.package_id, ob.blob_rel" % marks,
        [id_type, id_value] + list(pkg_set),
    ).fetchall()
    return [dict(r) for r in rows]


def _verify_stored_copy(repo_root, copy):
    """画像前实际重读封存载荷，分块核对长度与 SHA-256。"""
    rel = copy["stored_path"]
    if not rel:
        return VERIFY_MISSING, None, None
    try:
        path = safe_relpath(rel, repo_root)
    except Exception:
        return VERIFY_MISSING, None, None
    if not os.path.isfile(path):
        return VERIFY_MISSING, None, None
    h = hashlib.sha256()
    size = 0
    with open(path, "rb") as f:
        while True:
            chunk = f.read(CHUNK_SIZE)
            if not chunk:
                break
            h.update(chunk)
            size += len(chunk)
    if size != copy["size_actual"]:
        return VERIFY_LENGTH, size, h.hexdigest()
    if h.hexdigest() != copy["actual_sha"]:
        return VERIFY_SHA, size, h.hexdigest()
    return VERIFY_OK, size, h.hexdigest()


# ===========================================================================
# 画像执行
# ===========================================================================

def _validate_scope(conn, package_ids):
    """范围校验：每个包都必须存在且已封存；staging/未知包直接拒绝。"""
    if not package_ids:
        raise ProfileError(
            "profiling scope is empty", code="empty_scope"
        )
    pkg_set = sorted(set(package_ids))
    bad = []
    for pkg in pkg_set:
        row = conn.execute(
            "SELECT state FROM packages WHERE package_id=?", (pkg,)
        ).fetchone()
        if row is None:
            bad.append((pkg, "unknown_package"))
        elif row["state"] != "sealed":
            bad.append((pkg, "package_not_sealed"))
    if bad:
        raise ProfileError(
            "profiling scope rejected: %s"
            % ", ".join("%s(%s)" % b for b in bad),
            code="scope_not_sealed",
        )
    return pkg_set


def _object_record_base(id_type, id_value, packages, copies, catalog_ref):
    return {
        "identifierType": id_type,
        "identifierValue": id_value,
        "package_ids": packages,
        "catalog": catalog_ref,
        "byte_state": None,
        "copies": copies,
        "content_sha256": None,
        "content_length": None,
        "byte_source": None,
        "result": None,
        "formats": None,
        "hits": None,
    }


def run_profile(conn, repo_root, catalog_id, catalog_version, package_ids):
    """
    对指定封存包集合执行一次画像。只读既有事实，写不可变画像结果。
    相同输入重跑 -> 相同 profile_id，复用既有结果（不重写文件）。
    """
    catalog = fc.load_catalog_for_matching(conn, catalog_id, catalog_version)
    pkg_set = _validate_scope(conn, package_ids)
    pkg_sha = package_set_sha256(pkg_set)
    catalog_ref = {
        "catalog_id": catalog["catalog_id"],
        "catalog_version": catalog["catalog_version"],
        "catalog_sha256": catalog["catalog_sha256"],
    }

    identities = _scope_identities(conn, pkg_set)
    compiled = compile_signatures(catalog["signatures"])

    objects = []
    scan_cache = {}          # content_sha256 -> hits（仅本运行内复用）
    stats = {"contents_scanned": 0, "copies_verified": 0,
             "bytes_verified": 0}
    summary = {
        "objects_total": 0,
        "identified": 0,
        "ambiguous": 0,
        "unidentified": 0,
        "bytes_invalid": 0,
        "identity_conflict": 0,
        "by_byte_state": {
            ST_BYTES_OK: 0,
            ST_BYTES_MISSING: 0,
            ST_BYTES_CORRUPT: 0,
            ST_NOT_RECEIVED: 0,
            ST_IDENTITY_CONFLICT: 0,
        },
        "formats": {},
    }

    for id_type, id_value in identities:
        packages = _scope_identity_packages(conn, pkg_set, id_type, id_value)
        raw_copies = _scope_copies(conn, pkg_set, id_type, id_value)
        ok_digests = {
            c["actual_sha"] for c in raw_copies if c["state"] == "bytes_ok"
        }
        copies_out = []
        rec = _object_record_base(
            id_type, id_value, packages, copies_out, catalog_ref
        )

        if len(ok_digests) > 1:
            # 同一身份被不同实际字节占用：不择一、不扫描
            state = ST_IDENTITY_CONFLICT
            for c in raw_copies:
                copies_out.append({
                    "package_id": c["package_id"],
                    "rel_path": c["rel_path"],
                    "stored_state": c["state"],
                    "declared_sha256": c["declared_sha"],
                    "actual_sha256": c["actual_sha"],
                })
        else:
            # 逐副本复核仓内字节（只对 bytes_ok 副本重读）
            verified = []
            for c in raw_copies:
                entry = {
                    "package_id": c["package_id"],
                    "rel_path": c["rel_path"],
                    "stored_state": c["state"],
                    "declared_sha256": c["declared_sha"],
                    "actual_sha256": c["actual_sha"],
                }
                if c["state"] == "bytes_ok":
                    verdict, size, digest = _verify_stored_copy(
                        repo_root, c
                    )
                    entry["verify"] = verdict
                    entry["verify_length"] = size
                    entry["verify_sha256"] = digest
                    stats["copies_verified"] += 1
                    if size is not None:
                        stats["bytes_verified"] += size
                    if verdict == VERIFY_OK:
                        verified.append(c)
                copies_out.append(entry)

            if verified:
                state = ST_BYTES_OK
                src = verified[0]  # 排序后的首个通过复核副本
                digest = src["actual_sha"]
                rec["content_sha256"] = digest
                rec["content_length"] = src["size_actual"]
                rec["byte_source"] = {
                    "package_id": src["package_id"],
                    "rel_path": src["rel_path"],
                }
                if digest not in scan_cache:
                    path = safe_relpath(src["stored_path"], repo_root)
                    scan_cache[digest] = scan_content(
                        path, src["size_actual"], compiled
                    )
                    stats["contents_scanned"] += 1
                hits = scan_cache[digest]
                formats = sorted({h["format_id"] for h in hits})
                rec["hits"] = hits
                rec["formats"] = formats
                if not hits:
                    rec["result"] = R_UNIDENTIFIED
                elif len(formats) == 1:
                    rec["result"] = R_IDENTIFIED
                else:
                    rec["result"] = R_AMBIGUOUS
            elif any(c["state"] == "bytes_ok" for c in raw_copies):
                # 仓内记录 bytes_ok 但画像复核全部失败：不得扫描
                states = {
                    e.get("verify") for e in copies_out if e.get("verify")
                }
                state = (ST_BYTES_MISSING
                         if states == {VERIFY_MISSING}
                         else ST_BYTES_CORRUPT)
            elif any(c["state"] == "bytes_corrupt" for c in raw_copies):
                state = ST_BYTES_CORRUPT
            elif raw_copies:
                state = ST_BYTES_MISSING
            else:
                state = ST_NOT_RECEIVED

        rec["byte_state"] = state
        summary["objects_total"] += 1
        summary["by_byte_state"][state] += 1
        if state == ST_BYTES_OK:
            summary[rec["result"]] += 1
            if rec["result"] == R_IDENTIFIED:
                fmt = rec["formats"][0]
                summary["formats"][fmt] = summary["formats"].get(fmt, 0) + 1
        elif state == ST_IDENTITY_CONFLICT:
            summary["identity_conflict"] += 1
        else:
            summary["bytes_invalid"] += 1
        objects.append(rec)

    doc = {
        "profile": PROFILE_PROFILE,
        "engine": ENGINE_VERSION,
        "inputs": {
            "catalog": {
                "catalog_id": catalog["catalog_id"],
                "catalog_version": catalog["catalog_version"],
                "catalog_sha256": catalog["catalog_sha256"],
                "format_count": catalog["format_count"],
                "signature_count": catalog["signature_count"],
            },
            "packages": {
                "package_set": pkg_set,
                "package_set_sha256": pkg_sha,
            },
        },
        "semantics": {
            "scope": "bitstream identities declared in the given sealed "
                     "package set only; staging packages never enter",
            "identity": "identifierType+identifierValue exact tuple; "
                        "same bytes under different identities are "
                        "separate records",
            "matching": "all fully-matching signatures; identified iff all "
                        "hits name one format, ambiguous iff hits name "
                        "several, unidentified iff no hits",
            "bytes": "sealed payloads re-read and checked (length + "
                     "SHA-256) before scanning; invalid bytes are never "
                     "masked by signature hits",
        },
        "summary": summary,
        "objects": objects,
    }
    return _store_profile(conn, repo_root, doc, stats)


# ===========================================================================
# 结果落盘 / 内容寻址 / 绑定校验
# ===========================================================================

def _content_for_hash(doc):
    """参与内容寻址的业务事实（排除时间戳与自身标识）。"""
    return {
        k: v
        for k, v in doc.items()
        if k not in ("generated_at", "profile_id", "content_sha256")
    }


def profile_content_sha256(doc):
    return _sha(_canon(_content_for_hash(doc)))


def _profile_rel_path(profile_id):
    return "profiles/fmt-%s.json" % profile_id


def _store_profile(conn, repo_root, doc, stats):
    doc["generated_at"] = _now()
    content_sha = profile_content_sha256(doc)
    doc["content_sha256"] = content_sha
    doc["profile_id"] = content_sha

    existing = conn.execute(
        "SELECT profile_no,profile_path FROM format_profiles WHERE "
        "profile_id=?",
        (content_sha,),
    ).fetchone()
    if existing is not None:
        abs_path = os.path.join(repo_root, existing["profile_path"])
        if not os.path.isfile(abs_path):
            raise ProfileError(
                "profile %s registered but file missing: %s"
                % (content_sha, existing["profile_path"]),
                code="profile_file_missing",
            )
        return {
            "profile_id": content_sha,
            "profile_no": existing["profile_no"],
            "profile_path": existing["profile_path"],
            "summary": doc["summary"],
            "stats": stats,
            "reused": True,
        }

    body = json.dumps(
        doc, ensure_ascii=False, sort_keys=True, indent=2
    ).encode("utf-8") + b"\n"
    rel = _profile_rel_path(content_sha)
    abs_path = os.path.join(repo_root, rel)
    os.makedirs(os.path.dirname(abs_path), exist_ok=True)
    tmp = abs_path + ".tmp-%d" % os.getpid()
    with open(tmp, "wb") as f:
        f.write(body)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, abs_path)

    s = doc["summary"]
    try:
        conn.execute(
            "INSERT INTO format_profiles(profile_id,catalog_id,"
            "catalog_version,catalog_sha256,package_set_sha256,package_set,"
            "created_at,profile_path,objects_total,identified,ambiguous,"
            "unidentified,bytes_invalid,identity_conflict) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                content_sha,
                doc["inputs"]["catalog"]["catalog_id"],
                doc["inputs"]["catalog"]["catalog_version"],
                doc["inputs"]["catalog"]["catalog_sha256"],
                doc["inputs"]["packages"]["package_set_sha256"],
                json.dumps(doc["inputs"]["packages"]["package_set"]),
                doc["generated_at"],
                rel,
                s["objects_total"],
                s["identified"],
                s["ambiguous"],
                s["unidentified"],
                s["bytes_invalid"],
                s["identity_conflict"],
            ),
        )
        conn.commit()
    except sqlite3.IntegrityError:
        # 并发画像得到同一内容地址：文件字节相同（内容寻址），降级为复用
        conn.rollback()
        row = conn.execute(
            "SELECT profile_no FROM format_profiles WHERE profile_id=?",
            (content_sha,),
        ).fetchone()
        if row is None:
            raise
        return {
            "profile_id": content_sha,
            "profile_no": row["profile_no"],
            "profile_path": rel,
            "summary": s,
            "stats": stats,
            "reused": True,
        }
    row = conn.execute(
        "SELECT profile_no FROM format_profiles WHERE profile_id=?",
        (content_sha,),
    ).fetchone()
    return {
        "profile_id": content_sha,
        "profile_no": row["profile_no"],
        "profile_path": rel,
        "summary": s,
        "stats": stats,
        "reused": False,
    }


def load_profile(conn, repo_root, profile_id):
    row = conn.execute(
        "SELECT * FROM format_profiles WHERE profile_id=?", (profile_id,)
    ).fetchone()
    if row is None:
        raise ProfileError(
            "unknown profile_id %r" % profile_id, code="unknown_profile"
        )
    path = os.path.join(repo_root, row["profile_path"])
    if not os.path.isfile(path):
        raise ProfileError(
            "profile file missing: %s" % row["profile_path"],
            code="profile_file_missing",
        )
    with open(path, "rb") as f:
        doc = json.load(f)
    return doc


def list_profiles(conn):
    rows = conn.execute(
        "SELECT profile_no,profile_id,catalog_id,catalog_version,"
        "catalog_sha256,package_set_sha256,created_at,profile_path,"
        "objects_total,identified,ambiguous,unidentified,bytes_invalid,"
        "identity_conflict FROM format_profiles ORDER BY profile_no"
    ).fetchall()
    return [dict(r) for r in rows]


def check_binding(conn, repo_root, profile_id):
    """
    校验画像的输入绑定（对照当前仓库）：
      - 画像文件自身内容摘要一致（可独立成立，即使包集合已变化）；
      - 绑定的目录版本仍登记且摘要一致；
      - 绑定的包全部仍为 sealed；
      - 绑定包集合是否等于**当前** sealed 包集合（不等于则是历史画像，
        仍然有效，但不能冒充当前仓库的画像）。
    """
    row = conn.execute(
        "SELECT * FROM format_profiles WHERE profile_id=?", (profile_id,)
    ).fetchone()
    if row is None:
        raise ProfileError(
            "unknown profile_id %r" % profile_id, code="unknown_profile"
        )
    errors = []
    checks = []

    # 1) 文件自身内容摘要（独立校验器逻辑，不重跑匹配）
    from . import verify_profile

    path = os.path.join(repo_root, row["profile_path"])
    self_check = verify_profile.verify_profile(path)
    self_consistent = bool(self_check["ok"])
    checks.append("profile file self-consistency (content digest, summary, "
                  "evidence structure): %s"
                  % ("ok" if self_consistent else "FAILED"))
    if not self_consistent:
        errors.extend(self_check["errors"])

    # 2) 目录版本仍登记且摘要一致
    cat = conn.execute(
        "SELECT catalog_sha256 FROM format_catalogs WHERE catalog_id=? AND "
        "catalog_version=?",
        (row["catalog_id"], row["catalog_version"]),
    ).fetchone()
    catalog_ok = cat is not None and \
        cat["catalog_sha256"] == row["catalog_sha256"]
    checks.append("bound catalog version still registered with identical "
                  "canonical digest: %s" % ("ok" if catalog_ok else "FAILED"))
    if not catalog_ok:
        errors.append("bound catalog %r version %r missing or changed"
                      % (row["catalog_id"], row["catalog_version"]))

    # 3) 绑定的包全部仍 sealed
    bound_set = sorted(json.loads(row["package_set"]))
    not_sealed = []
    for pkg in bound_set:
        r = conn.execute(
            "SELECT state FROM packages WHERE package_id=?", (pkg,)
        ).fetchone()
        if r is None or r["state"] != "sealed":
            not_sealed.append(pkg)
    packages_ok = not not_sealed
    checks.append("all bound packages still sealed: %s"
                  % ("ok" if packages_ok else "FAILED"))
    if not_sealed:
        errors.append("bound packages no longer sealed: %r" % not_sealed)

    # 4) 与当前 sealed 包集合的关系（历史画像仍有效，但不是当前画像）
    current_set = sealed_package_set(conn)
    matches_current = bound_set == current_set
    checks.append(
        "bound package set %s the repository's current sealed set"
        % ("equals" if matches_current else "differs from")
    )

    ok = self_consistent and catalog_ok and packages_ok
    return {
        "ok": ok,
        "profile_id": profile_id,
        "self_consistent": self_consistent,
        "catalog_binding_intact": catalog_ok,
        "packages_all_sealed": packages_ok,
        "bound_package_set": bound_set,
        "current_sealed_set": current_set,
        "matches_current_sealed": matches_current,
        "current": ok and matches_current,
        "historical": ok and not matches_current,
        "checks": checks,
        "errors": errors,
    }
