# -*- coding: utf-8 -*-
"""
封存对象格式画像验收测试。运行：
  python -I /workspace/evidence_repo/tests/demo_format_profile.py

预期来源（题目要求）：
- 每个片段的匹配与汇总由**独立短程序**（本文件内的 oracle_* 函数，纯 Python
  循环，直接读原始字节与签名定义）与**人工表格**（HAND_SUMMARY / 逐对象人工
  期望）推导，绝不调用产品匹配逻辑（evidrepo.format_profile /
  evidrepo.format_catalog 的匹配与解析代码只作为被测对象出现）。

覆盖（对应题目清单）：
  固定偏移、窗口搜索、掩码、多个必需片段、禁止片段、跨读取块命中
  （强制 64 KiB 块）、一个对象命中同一格式的多条签名、跨格式歧义、
  未识别对象、目录行序打乱、同一身份跨包重复、相同字节不同身份、
  实际载荷损坏、身份冲突、staging 隔离、无效目录不得部分登记、
  旧画像与新增封包并存、结果搬出仓库后校验、复跑稳定性、范围子集、
  目录版本演进、schema v3->v4 迁移、CLI 入口、既有功能回归冒烟。
"""
from __future__ import annotations

import io
import json
import os
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))

from evidrepo import db as dbmod  # noqa: E402
from evidrepo import diagnostics, ingest, reconcile as reconc  # noqa: E402
from evidrepo import format_catalog as fc  # noqa: E402
from evidrepo import format_profile as fp  # noqa: E402
from evidrepo import inventory as invmod  # noqa: E402
from evidrepo import release_plan  # noqa: E402
from evidrepo import verify_profile  # noqa: E402

from fixtures import PackageBuilder  # noqa: E402

WORK = "/workspace/runs/format"
REPO = os.path.join(WORK, "repo")
PKGS = os.path.join(WORK, "pkgs")
OUT = os.path.join(WORK, "out")
REPO_SRC = os.path.dirname(HERE)

PASS, FAIL = [], []


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append((name, detail))
    print(("  [PASS] " if cond else "  [FAIL] ") + name
          + ((" — " + str(detail)) if detail else ""))


# ---------------------------------------------------------------------------
# 独立 oracle：从原始字节与签名定义推导期望（不调用产品匹配逻辑）
# ---------------------------------------------------------------------------

def oracle_parse_catalog(path):
    """独立解析目录 JSONL（解析格式公开；匹配逻辑在下面独立实现）。"""
    formats, sigs = {}, []
    with open(path, "rb") as f:
        lines = f.read().decode("utf-8").splitlines()
    for line in lines[1:]:
        rec = json.loads(line)
        if rec["record_type"] == "format":
            formats[rec["format_id"]] = rec["name"]
        elif rec["record_type"] == "signature":
            sigs.append(rec)
    return formats, sigs


def oracle_frag_positions(data, frag):
    """朴素逐偏移循环匹配（含掩码），返回全部命中起始偏移（升序）。"""
    pat = bytes.fromhex(frag["bytes"])
    mask = bytes.fromhex(frag["mask"]) if "mask" in frag else None
    if "offset" in frag:
        cands = [frag["offset"]]
    else:
        cands = range(frag["window"][0], frag["window"][1] + 1)
    out = []
    for o in cands:
        if o + len(pat) > len(data):
            continue
        ok = True
        for i, p in enumerate(pat):
            b = data[o + i]
            if mask is None:
                if b != p:
                    ok = False
                    break
            elif (b & mask[i]) != (p & mask[i]):
                ok = False
                break
        if ok:
            out.append(o)
    return out


def oracle_object(data, sigs):
    """返回 {"result","formats","hits":{sig_id:{"format_id","required":{key:pos}}}}"""
    hits = {}
    for sig in sigs:
        req = {}
        ok = True
        for frag in sig["required"]:
            pos = oracle_frag_positions(data, frag)
            if not pos:
                ok = False
                break
            req[canon_frag_key(frag)] = pos
        if not ok:
            continue
        for frag in sig.get("forbidden", []):
            if oracle_frag_positions(data, frag):
                ok = False
                break
        if ok:
            hits[sig["signature_id"]] = {
                "format_id": sig["format_id"], "required": req,
            }
    fmts = sorted({h["format_id"] for h in hits.values()})
    if not hits:
        result = "unidentified"
    elif len(fmts) == 1:
        result = "identified"
    else:
        result = "ambiguous"
    return {"result": result, "formats": fmts if hits else [], "hits": hits}


def canon_frag_key(frag):
    f = {"bytes": frag["bytes"].lower()}
    if "mask" in frag:
        f["mask"] = frag["mask"].lower()
    if "offset" in frag:
        f["offset"] = frag["offset"]
    else:
        f["window"] = [int(x) for x in frag["window"]]
    return json.dumps(f, sort_keys=True)


# ---------------------------------------------------------------------------
# 夹具：目录与包
# ---------------------------------------------------------------------------

CAT_PATH = os.path.join(WORK, "catalog-v1.jsonl")
CAT_SHUFFLED_PATH = os.path.join(WORK, "catalog-v1-shuffled.jsonl")
CAT_V2_PATH = os.path.join(WORK, "catalog-v2.jsonl")

ALPHA = b"ALPHA" + b"\x00" * 400
ALPHA_OMEGA = b"ALPHA" + b"\x00" * 95 + b"OMEGA" + b"\x00" * 300   # OMEGA@100
AMB = b"ALPHA" + b"\x00" * 195 + b"BETA" + b"\x00" * 200           # BETA@200
BETA = b"BETA" + b"\x00" * 400
GAMMA = b"GXMMA" + b"\x00" * 400
DELTA_OK = b"DELTA" + b"\x00" * 400
DELTA_BAD = b"DELTA" + b"\x00" * 11 + b"BAD" + b"\x00" * 400       # BAD@16
UNKNOWN = bytes(range(256)) * 2
EMPTY = b""
BIG = bytearray(256 * 1024)
BIG[131070:131075] = b"OMEGA"        # 跨 64 KiB 读取块边界 131072
BIG = bytes(BIG)
CONFLICT_A = b"ALPHA" + b"\x00" * 400
CONFLICT_B = b"BETA" + b"\x00" * 401
NEW_GAMMA = b"GZMMA" + b"\x00" * 400

CATALOG_LINES = [
    {"record_type": "catalog_header", "format_version": "format-catalog/v1",
     "catalog_id": "fmt-cat", "catalog_version": "2026-11",
     "note": "验收目录"},
    {"record_type": "format", "format_id": "fmt.alpha", "name": "Alpha Document"},
    {"record_type": "format", "format_id": "fmt.beta", "name": "Beta Image"},
    {"record_type": "format", "format_id": "fmt.gamma", "name": "Gamma Mask"},
    {"record_type": "format", "format_id": "fmt.delta", "name": "Delta Safe"},
    {"record_type": "format", "format_id": "fmt.omega", "name": "Omega Late"},
    # 固定偏移
    {"record_type": "signature", "signature_id": "sig.alpha.fixed",
     "format_id": "fmt.alpha",
     "required": [{"bytes": "414c504841", "offset": 0}]},
    # 固定偏移 + 掩码（第 3 字节通配）
    {"record_type": "signature", "signature_id": "sig.alpha.masked",
     "format_id": "fmt.alpha",
     "required": [{"bytes": "414c504841", "offset": 0,
                   "mask": "ffff00ffff"}]},
    # 多个必需片段：固定偏移 AND 窗口搜索
    {"record_type": "signature", "signature_id": "sig.alpha.multi",
     "format_id": "fmt.alpha",
     "required": [{"bytes": "414c504841", "offset": 0},
                  {"bytes": "4f4d454741", "window": [64, 192]}]},
    {"record_type": "signature", "signature_id": "sig.beta.fixed",
     "format_id": "fmt.beta",
     "required": [{"bytes": "42455441", "offset": 0}]},
    # 窗口搜索
    {"record_type": "signature", "signature_id": "sig.beta.window",
     "format_id": "fmt.beta",
     "required": [{"bytes": "42455441", "window": [0, 256]}]},
    # 掩码（第 2 字节通配）
    {"record_type": "signature", "signature_id": "sig.gamma.masked",
     "format_id": "fmt.gamma",
     "required": [{"bytes": "47414d4d41", "offset": 0,
                   "mask": "ff00ffffff"}]},
    # 禁止片段
    {"record_type": "signature", "signature_id": "sig.delta.forbid",
     "format_id": "fmt.delta",
     "required": [{"bytes": "44454c5441", "offset": 0}],
     "forbidden": [{"bytes": "424144", "window": [8, 64]}]},
    # 大窗口（跨读取块）
    {"record_type": "signature", "signature_id": "sig.omega.late",
     "format_id": "fmt.omega",
     "required": [{"bytes": "4f4d454741", "window": [60000, 200000]}]},
    # 大窗口 + 掩码
    {"record_type": "signature", "signature_id": "sig.omega.masked",
     "format_id": "fmt.omega",
     "required": [{"bytes": "4f4d454741", "window": [60000, 200000],
                   "mask": "ff00ffffff"}]},
    # 固定偏移在跨块位置
    {"record_type": "signature", "signature_id": "sig.omega.fixedlate",
     "format_id": "fmt.omega",
     "required": [{"bytes": "4f4d454741", "offset": 131070}]},
]

# 人工表格：逐对象期望（状态/结果/格式）；命中细节由 oracle 推导
HAND_OBJECTS = {
    "BS-ALPHA":       ("bytes_ok", "identified", ["fmt.alpha"]),
    "BS-ALPHA-OMEGA": ("bytes_ok", "identified", ["fmt.alpha"]),
    "BS-AMB":         ("bytes_ok", "ambiguous", ["fmt.alpha", "fmt.beta"]),
    "BS-BETA":        ("bytes_ok", "identified", ["fmt.beta"]),
    "BS-GAMMA":       ("bytes_ok", "identified", ["fmt.gamma"]),
    "BS-DELTA-OK":    ("bytes_ok", "identified", ["fmt.delta"]),
    "BS-DELTA-BAD":   ("bytes_ok", "unidentified", []),
    "BS-UNKNOWN":     ("bytes_ok", "unidentified", []),
    "BS-EMPTY":       ("bytes_ok", "unidentified", []),
    "BS-BIG":         ("bytes_ok", "identified", ["fmt.omega"]),
    "BS-DUP":         ("bytes_ok", "identified", ["fmt.alpha"]),
    "BS-CORRUPT":     ("bytes_corrupt", None, None),
    "BS-MISSING":     ("bytes_missing", None, None),
    "BS-NOTRECV":     ("not_received", None, None),
    "BS-CONFLICT":    ("identity_conflict", None, None),
}

# 人工表格：汇总（与 oracle 独立的第二重推导）
HAND_SUMMARY = {
    "objects_total": 15,
    "identified": 7,
    "ambiguous": 1,
    "unidentified": 3,
    "bytes_invalid": 3,
    "identity_conflict": 1,
    "formats": {"fmt.alpha": 3, "fmt.beta": 1, "fmt.gamma": 1,
                "fmt.delta": 1, "fmt.omega": 1},
}

# 各对象原始字节（oracle 的输入；损坏/缺失/未接收对象无字节可查）
PAYLOAD_BYTES = {
    "BS-ALPHA": ALPHA, "BS-ALPHA-OMEGA": ALPHA_OMEGA, "BS-AMB": AMB,
    "BS-BETA": BETA, "BS-GAMMA": GAMMA, "BS-DELTA-OK": DELTA_OK,
    "BS-DELTA-BAD": DELTA_BAD, "BS-UNKNOWN": UNKNOWN, "BS-EMPTY": EMPTY,
    "BS-BIG": BIG, "BS-DUP": ALPHA,
}


def write_jsonl(path, records):
    with open(path, "wb") as f:
        for r in records:
            f.write(json.dumps(r, ensure_ascii=False).encode("utf-8") + b"\n")


def build_catalogs():
    write_jsonl(CAT_PATH, CATALOG_LINES)
    # 行序打乱版：格式行逆序、签名行逆序、多片段签名内片段换序
    shuffled = [CATALOG_LINES[0]]
    body = list(CATALOG_LINES[1:])
    body.reverse()
    for rec in body:
        rec = dict(rec)
        if rec.get("signature_id") == "sig.alpha.multi":
            rec["required"] = list(reversed(rec["required"]))
        shuffled.append(rec)
    write_jsonl(CAT_SHUFFLED_PATH, shuffled)
    # v2：追加新格式 fmt.new（sig.new 精确匹配 "GXMMA"）
    v2 = list(CATALOG_LINES)
    v2[0] = dict(v2[0], catalog_version="2027-01")
    v2.append({"record_type": "format", "format_id": "fmt.new",
               "name": "New Exact"})
    v2.append({"record_type": "signature", "signature_id": "sig.new",
               "format_id": "fmt.new",
               "required": [{"bytes": "47584d4d41", "offset": 0}]})
    write_jsonl(CAT_V2_PATH, v2)


def build_packages():
    b1 = PackageBuilder(PKGS, "P1", trusted_ingest=("ing-p1",))
    b1.add_bitstream("BS-ALPHA", ALPHA)
    b1.add_bitstream("BS-ALPHA-OMEGA", ALPHA_OMEGA)
    b1.add_bitstream("BS-AMB", AMB)
    b1.add_bitstream("BS-BETA", BETA)
    b1.add_bitstream("BS-GAMMA", GAMMA)
    b1.add_bitstream("BS-DELTA-OK", DELTA_OK)
    b1.add_bitstream("BS-DELTA-BAD", DELTA_BAD)
    b1.add_bitstream("BS-UNKNOWN", UNKNOWN)
    b1.add_bitstream("BS-EMPTY", EMPTY)
    b1.add_representation("REP-1", ["BS-ALPHA"], nodes=["node-1"])
    b1.add_event("ing-p1", "ingest",
                 outputs=["BS-ALPHA", "BS-ALPHA-OMEGA", "BS-AMB", "BS-BETA",
                          "BS-GAMMA", "BS-DELTA-OK", "BS-DELTA-BAD",
                          "BS-UNKNOWN", "BS-EMPTY"])
    b1.build()

    b2 = PackageBuilder(PKGS, "P2", trusted_ingest=("ing-p2",))
    b2.add_bitstream("BS-BIG", BIG)
    b2.add_bitstream("BS-DUP", ALPHA)          # 与 BS-ALPHA 同字节、不同身份
    b2.add_bitstream("BS-ALPHA", ALPHA)        # 同一身份跨包重复声明
    b2.add_bitstream("BS-CORRUPT", b"ALPHA-corrupted-payload")
    b2.add_bitstream("BS-MISSING", b"never arrived")
    b2.add_ref_only("BS-NOTRECV")
    b2.mark_corrupt("BS-CORRUPT")
    b2.mark_missing("BS-MISSING")
    b2.add_representation("REP-2", ["BS-BIG", "BS-DUP"], nodes=["node-2"])
    b2.add_event("ing-p2", "ingest", outputs=["BS-BIG", "BS-DUP", "BS-ALPHA"])
    b2.build()

    b3 = PackageBuilder(PKGS, "P3", trusted_ingest=("ing-p3",))
    b3.add_bitstream("BS-CONFLICT", CONFLICT_A)
    b3.add_event("ing-p3", "ingest", outputs=["BS-CONFLICT"])
    b3.build()

    b4 = PackageBuilder(PKGS, "P4", trusted_ingest=("ing-p4",))
    b4.add_bitstream("BS-CONFLICT", CONFLICT_B)   # 同身份、不同实际字节
    b4.add_event("ing-p4", "ingest", outputs=["BS-CONFLICT"])
    b4.build()

    b5 = PackageBuilder(PKGS, "P5-STG", trusted_ingest=("ing-p5",))
    b5.add_bitstream("BS-STAGING", ALPHA)
    b5.add_event("ing-p5", "ingest", outputs=["BS-STAGING"])
    b5.build()

    b6 = PackageBuilder(PKGS, "P6", trusted_ingest=("ing-p6",))
    b6.add_bitstream("BS-NEW", NEW_GAMMA)
    b6.add_event("ing-p6", "ingest", outputs=["BS-NEW"])
    b6.build()


def fresh_repo():
    shutil.rmtree(REPO, ignore_errors=True)
    os.makedirs(REPO)
    return dbmod.connect(REPO)


# ---------------------------------------------------------------------------
# 用例
# ---------------------------------------------------------------------------

def case_01_register_and_order(conn):
    print("\n[01] 目录登记 + 行序/片段序无关")
    r1 = fc.register_catalog(conn, REPO, CAT_PATH)
    check("目录登记成功", not r1["reused"] and r1["format_count"] == 5
          and r1["signature_count"] == 10)
    r2 = fc.register_catalog(conn, REPO, CAT_PATH)
    check("同内容重复登记幂等", r2["reused"]
          and r2["catalog_sha256"] == r1["catalog_sha256"])
    r3 = fc.register_catalog(conn, REPO, CAT_SHUFFLED_PATH)
    check("行序/片段序打乱后内容摘要相同（幂等复用）",
          r3["reused"] and r3["catalog_sha256"] == r1["catalog_sha256"])
    cat = fc.get_catalog(conn, "fmt-cat", "2026-11")
    check("catalog-show 内容完整",
          len(cat["formats"]) == 5 and len(cat["signatures"]) == 10
          and cat["note"] == "验收目录")
    return r1["catalog_sha256"]


def case_02_invalid_catalogs(conn):
    print("\n[02] 无效目录整份拒绝，不留半份")
    hdr = CATALOG_LINES[0]
    fmt = CATALOG_LINES[1]
    sig = CATALOG_LINES[6]

    def variant(name, mutate, expect_code):
        lines = [json.loads(json.dumps(x)) for x in
                 [hdr, fmt, sig]]
        mutate(lines)
        path = os.path.join(WORK, "bad-%s.jsonl" % name)
        if name == "bom":
            with open(path, "wb") as f:
                f.write(b"\xef\xbb\xbf")
                for l in lines:
                    f.write(json.dumps(l).encode() + b"\n")
        else:
            write_jsonl(path, lines)
        try:
            fc.register_catalog(conn, REPO, path)
        except fc.CatalogError as exc:
            check("无效目录拒绝[%s]" % name, exc.code == expect_code,
                  "got %s: %s" % (exc.code, exc.message))
            return
        check("无效目录拒绝[%s]" % name, False, "竟然登记成功")

    def set_hdr(lines, **kw):
        lines[0].update(kw)

    variant("bad-version", lambda l: set_hdr(l, format_version="format-catalog/v9"),
            "bad_format_version")
    variant("bad-hex", lambda l: l[2]["required"].__setitem__(
        0, {"bytes": "4142zz", "offset": 0}), "bad_hex")
    variant("odd-hex", lambda l: l[2]["required"].__setitem__(
        0, {"bytes": "414", "offset": 0}), "bad_hex")
    variant("mask-len", lambda l: l[2]["required"].__setitem__(
        0, {"bytes": "414c", "offset": 0, "mask": "ff"}), "bad_mask")
    variant("mask-bad-hex", lambda l: l[2]["required"].__setitem__(
        0, {"bytes": "414c", "offset": 0, "mask": "zz"}), "bad_hex")
    variant("window-inverted", lambda l: l[2]["required"].__setitem__(
        0, {"bytes": "414c", "window": [10, 5]}), "bad_window")
    variant("window-too-wide", lambda l: l[2]["required"].__setitem__(
        0, {"bytes": "414c", "window": [0, (1 << 20) + 1]}), "window_too_wide")
    variant("negative-offset", lambda l: l[2]["required"].__setitem__(
        0, {"bytes": "414c", "offset": -1}), "bad_offset")
    variant("bool-offset", lambda l: l[2]["required"].__setitem__(
        0, {"bytes": "414c", "offset": True}), "bad_offset")
    variant("dup-format", lambda l: l.append(dict(l[1])), "duplicate_format")
    variant("dup-signature", lambda l: l.append(dict(l[2])),
            "duplicate_signature")
    variant("unknown-format-ref", lambda l: l[2].__setitem__(
        "format_id", "fmt.ghost"), "unknown_format")
    variant("unknown-field", lambda l: l[2]["required"].__setitem__(
        0, {"bytes": "414c", "offset": 0, "note": "x"}), "bad_field")
    variant("both-positions", lambda l: l[2]["required"].__setitem__(
        0, {"bytes": "414c", "offset": 0, "window": [0, 4]}), "bad_position")
    variant("no-position", lambda l: l[2]["required"].__setitem__(
        0, {"bytes": "414c"}), "bad_position")
    variant("empty-required", lambda l: l[2].__setitem__("required", []),
            "empty_required")
    variant("too-many-fragments", lambda l: l[2].__setitem__(
        "required", [{"bytes": "41", "offset": 0}] * 33), "too_many_fragments")
    variant("fragment-too-long", lambda l: l[2]["required"].__setitem__(
        0, {"bytes": "41" * 257, "offset": 0}), "fragment_too_long")
    variant("bom", lambda l: None, "bad_encoding")
    variant("bad-ident", lambda l: l[1].__setitem__("format_id", "has space"),
            "bad_identifier")
    variant("no-signatures", lambda l: l.pop(2), "empty_signatures")
    variant("hdr-unknown-field", lambda l: set_hdr(l, extra=1), "bad_field")
    variant("bad-record-type", lambda l: l[2].__setitem__(
        "record_type", "rule"), "bad_record")

    # 空行变体：单独构造（write_jsonl 无法产出真正的空行）
    path = os.path.join(WORK, "bad-blank.jsonl")
    with open(path, "wb") as f:
        f.write(json.dumps(hdr).encode() + b"\n\n")
        f.write(json.dumps(fmt).encode() + b"\n")
        f.write(json.dumps(sig).encode() + b"\n")
    try:
        fc.register_catalog(conn, REPO, path)
        check("无效目录拒绝[blank-line-2]", False, "竟然登记成功")
    except fc.CatalogError as exc:
        check("无效目录拒绝[blank-line-2]", exc.code == "blank_line",
              exc.code)

    cats = fc.list_catalogs(conn)
    check("无效目录均未部分登记（仍只有 1 份目录）",
          len(cats) == 1 and cats[0]["catalog_id"] == "fmt-cat",
          cats)
    n_fmt = conn.execute("SELECT COUNT(*) c FROM catalog_formats").fetchone()["c"]
    n_sig = conn.execute(
        "SELECT COUNT(*) c FROM catalog_signatures").fetchone()["c"]
    check("目录内容表无残留（5 格式 / 10 签名）",
          n_fmt == 5 and n_sig == 10, (n_fmt, n_sig))


class _TrackingFile:
    def __init__(self, raw, sizes):
        self._raw = raw
        self._sizes = sizes

    def read(self, size=-1):
        if size is not None and size > 0:
            self._sizes.append(size)
        return self._raw.read(size)

    def __enter__(self):
        self._raw.__enter__()
        return self

    def __exit__(self, *a):
        return self._raw.__exit__(*a)

    def __getattr__(self, name):
        return getattr(self._raw, name)


def case_03_main_profile(conn, catalog_sha):
    print("\n[03] 主画像：强制 64 KiB 读取块 + 独立 oracle 全量核对")
    import builtins
    real_open = builtins.open
    read_sizes = []

    def tracking_open(file, mode="r", *a, **kw):
        raw = real_open(file, mode, *a, **kw)
        if "b" in mode and "r" in mode:
            return _TrackingFile(raw, read_sizes)
        return raw

    saved_chunk = fp.CHUNK_SIZE
    fp.CHUNK_SIZE = 64 * 1024     # 强制小读取块：跨块命中必须仍正确
    builtins.open = tracking_open
    try:
        res = fp.run_profile(conn, REPO, "fmt-cat", "2026-11",
                             ["P1", "P2", "P3", "P4"])
    finally:
        fp.CHUNK_SIZE = saved_chunk
        builtins.open = real_open
    check("画像运行完成", not res["reused"])
    check("全部 read() 不超过 64 KiB（不把载荷整体读入）",
          read_sizes and max(read_sizes) <= 64 * 1024,
          "max=%d" % (max(read_sizes) if read_sizes else -1))

    doc = fp.load_profile(conn, REPO, res["profile_id"])
    objs = {o["identifierValue"]: o for o in doc["objects"]}

    # 人工表格：汇总
    s = doc["summary"]
    check("人工汇总一致", all(
        s[k] == HAND_SUMMARY[k] for k in
        ("objects_total", "identified", "ambiguous", "unidentified",
         "bytes_invalid", "identity_conflict")) and
        s["formats"] == HAND_SUMMARY["formats"],
        json.dumps(s, ensure_ascii=False))

    # 独立 oracle：逐对象、逐片段证据核对
    _formats, sigs = oracle_parse_catalog(CAT_PATH)
    ok_all = True
    detail = ""
    for value, (state, result, formats) in HAND_OBJECTS.items():
        o = objs.get(value)
        if o is None:
            ok_all, detail = False, "缺对象 " + value
            break
        if o["byte_state"] != state:
            ok_all, detail = False, "%s 状态 %s != %s" % (
                value, o["byte_state"], state)
            break
        if state != "bytes_ok":
            if o["result"] is not None or o["hits"] is not None \
                    or o["formats"] is not None:
                ok_all, detail = False, value + " 非 ok 对象携带命中"
                break
            continue
        expect = oracle_object(PAYLOAD_BYTES[value], sigs)
        if o["result"] != expect["result"] or o["formats"] != expect["formats"]:
            ok_all, detail = False, "%s 结果不符: %s/%s vs %s/%s" % (
                value, o["result"], o["formats"],
                expect["result"], expect["formats"])
            break
        got_hits = {h["signature_id"]: h for h in o["hits"]}
        if set(got_hits) != set(expect["hits"]):
            ok_all, detail = False, "%s 命中签名集不符: %s vs %s" % (
                value, sorted(got_hits), sorted(expect["hits"]))
            break
        data = PAYLOAD_BYTES[value]
        for sid, eh in expect["hits"].items():
            gh = got_hits[sid]
            if gh["format_id"] != eh["format_id"]:
                ok_all, detail = False, "%s/%s 格式不符" % (value, sid)
                break
            got_req = {canon_frag_key(e["fragment"]): e
                       for e in gh["required"]}
            if set(got_req) != set(eh["required"]):
                ok_all, detail = False, "%s/%s 必需片段集不符" % (value, sid)
                break
            for key, positions in eh["required"].items():
                ev = got_req[key]
                pat_len = len(bytes.fromhex(ev["fragment"]["bytes"]))
                want_matched = data[positions[0]:positions[0] + pat_len].hex()
                if ev["match_count"] != len(positions) or \
                        ev["offsets"] != positions[:8] or \
                        ev["matched_bytes"] != want_matched:
                    ok_all, detail = False, \
                        "%s/%s 片段证据不符: got %r want count=%d offs=%s" % (
                            value, sid, ev, len(positions), positions[:8])
                    break
            if not ok_all:
                break
            # 禁止片段证据：全部命中数 0
            for e in gh["forbidden"]:
                if e["match_count"] != 0 or e["offsets"] != []:
                    ok_all, detail = False, "%s/%s 禁止片段证据异常" % (
                        value, sid)
                    break
        if not ok_all:
            break
    check("oracle 逐对象逐片段证据全部一致", ok_all, detail)

    # 人工表格：逐对象结果（与 oracle 独立的第二重核对）
    ok_hand = all(
        objs[v]["byte_state"] == st and objs[v]["result"] == rs
        and (objs[v]["formats"] == fm if fm is not None
             else objs[v]["formats"] is None)
        for v, (st, rs, fm) in HAND_OBJECTS.items()
    )
    check("人工逐对象表一致", ok_hand)

    # 跨读取块命中：OMEGA@131070（跨 64 KiB 读取边界 131072）
    big = objs["BS-BIG"]
    late = next(h for h in big["hits"] if h["signature_id"] == "sig.omega.late")
    masked = next(h for h in big["hits"]
                  if h["signature_id"] == "sig.omega.masked")
    fixed = next(h for h in big["hits"]
                 if h["signature_id"] == "sig.omega.fixedlate")
    check("跨读取块命中（窗口/掩码/固定偏移 @131070）",
          late["required"][0]["offsets"] == [131070]
          and masked["required"][0]["offsets"] == [131070]
          and fixed["required"][0]["offsets"] == [131070]
          and late["required"][0]["matched_bytes"] == "4f4d454741"
          and masked["required"][0]["matched_bytes"] == "4f4d454741")

    # 同一身份跨包重复：一条记录、两个来源包、两个副本
    alpha = objs["BS-ALPHA"]
    check("同一身份跨包重复只记一次",
          alpha["package_ids"] == ["P1", "P2"]
          and len(alpha["copies"]) == 2
          and all(c.get("verify") == "ok" for c in alpha["copies"]))
    # 相同字节不同身份：分别列出
    check("相同字节不同身份分别列出",
          objs["BS-DUP"]["content_sha256"] == alpha["content_sha256"]
          and objs["BS-DUP"] is not alpha)
    # 扫描按内容复用：11 个 ok 对象、10 种内容
    check("按内容摘要复用扫描（11 ok 对象 / 10 内容）",
          res["stats"]["contents_scanned"] == 10, res["stats"])
    check("每个身份字节均经复核（12 副本）",
          res["stats"]["copies_verified"] == 12, res["stats"])
    # 表示/结构节点不计入
    check("表示与结构节点不计入画像",
          "REP-1" not in objs and "REP-2" not in objs
          and all(o["identifierType"] == "local"
                  for o in doc["objects"]))
    # 绑定
    check("输入绑定（目录摘要 + 包集合及清单摘要）",
          doc["inputs"]["catalog"]["catalog_sha256"] == catalog_sha
          and doc["inputs"]["packages"]["package_set"]
          == ["P1", "P2", "P3", "P4"]
          and isinstance(
              doc["inputs"]["packages"]["package_set_sha256"], str))
    return res


def case_04_rerun_stable(conn, res):
    print("\n[04] 相同输入复跑：稳定标识 + 复用")
    again = fp.run_profile(conn, REPO, "fmt-cat", "2026-11",
                           ["P4", "P3", "P2", "P1"])   # 顺序不同
    check("包顺序不同仍复用同一画像",
          again["reused"] and again["profile_id"] == res["profile_id"])
    sealed = fp.sealed_package_set(conn)
    via_all = fp.run_profile(conn, REPO, "fmt-cat", "2026-11", sealed)
    check("显式范围与 --all-sealed 等价",
          via_all["profile_id"] == res["profile_id"] and via_all["reused"])


def case_05_scope_subset(conn):
    print("\n[05] 范围子集：只看指定包")
    res = fp.run_profile(conn, REPO, "fmt-cat", "2026-11", ["P1"])
    doc = fp.load_profile(conn, REPO, res["profile_id"])
    objs = {o["identifierValue"]: o for o in doc["objects"]}
    check("子集画像只含 P1 身份（9 个）",
          len(objs) == 9 and "BS-BIG" not in objs and "BS-DUP" not in objs)
    check("范围内来源包只列范围内的包",
          objs["BS-ALPHA"]["package_ids"] == ["P1"]
          and len(objs["BS-ALPHA"]["copies"]) == 1)


def case_06_states_not_masked(conn, res):
    print("\n[06] 缺失/损坏/冲突不被签名命中掩盖")
    doc = fp.load_profile(conn, REPO, res["profile_id"])
    objs = {o["identifierValue"]: o for o in doc["objects"]}
    cor = objs["BS-CORRUPT"]
    check("损坏对象：状态+出处，无命中",
          cor["byte_state"] == "bytes_corrupt" and cor["result"] is None
          and cor["hits"] is None
          and cor["copies"][0]["stored_state"] == "bytes_corrupt"
          and cor["package_ids"] == ["P2"])
    mis = objs["BS-MISSING"]
    check("缺失对象：状态+出处，无命中",
          mis["byte_state"] == "bytes_missing" and mis["result"] is None
          and mis["copies"][0]["stored_state"] == "bytes_missing")
    nre = objs["BS-NOTRECV"]
    check("未接收对象：状态+出处",
          nre["byte_state"] == "not_received" and nre["copies"] == [])
    con = objs["BS-CONFLICT"]
    digests = sorted(c["actual_sha256"] for c in con["copies"])
    check("身份冲突：两个不同实际字节都列出，不择一不扫描",
          con["byte_state"] == "identity_conflict" and con["result"] is None
          and len(con["copies"]) == 2 and digests[0] != digests[1]
          and con["package_ids"] == ["P3", "P4"])


def case_07_staging_isolation(conn, res):
    print("\n[07] staging 隔离")
    doc = fp.load_profile(conn, REPO, res["profile_id"])
    objs = {o["identifierValue"] for o in doc["objects"]}
    check("staging 包身份不进入画像", "BS-STAGING" not in objs)
    for scope, code in ((["P1", "P5-STG"], "scope_not_sealed"),
                        (["P-NOPE"], "scope_not_sealed"),
                        ([], "empty_scope")):
        try:
            fp.run_profile(conn, REPO, "fmt-cat", "2026-11", scope)
            check("范围拒绝 %r" % (scope,), False, "竟然运行成功")
        except fp.ProfileError as exc:
            check("范围拒绝 %r" % (scope,), exc.code == code, exc.code)


def case_08_old_profile_coexist(conn, res):
    print("\n[08] 旧画像与新增封包并存")
    old_id = res["profile_id"]
    old_path = os.path.join(REPO, res["profile_path"])
    with open(old_path, "rb") as f:
        old_bytes = f.read()

    bind0 = fp.check_binding(conn, REPO, old_id)
    check("新增前旧画像为当前画像",
          bind0["ok"] and bind0["current"] and not bind0["historical"])

    ingest.receive(conn, REPO, os.path.join(PKGS, "P6"))
    ingest.finish(conn, REPO, "P6")

    bind1 = fp.check_binding(conn, REPO, old_id)
    check("新增封包后旧画像仍可校验但为历史画像",
          bind1["ok"] and bind1["historical"] and not bind1["current"]
          and bind1["bound_package_set"] == ["P1", "P2", "P3", "P4"]
          and bind1["current_sealed_set"] == ["P1", "P2", "P3", "P4", "P6"])

    res_new = fp.run_profile(conn, REPO, "fmt-cat", "2026-11",
                             fp.sealed_package_set(conn))
    check("新封包产生新画像（不改写旧结果）",
          not res_new["reused"] and res_new["profile_id"] != old_id)
    doc_new = fp.load_profile(conn, REPO, res_new["profile_id"])
    objs_new = {o["identifierValue"]: o for o in doc_new["objects"]}
    check("新画像含新对象（BS-NEW -> fmt.gamma）",
          objs_new.get("BS-NEW", {}).get("result") == "identified"
          and objs_new["BS-NEW"]["formats"] == ["fmt.gamma"]
          and len(objs_new) == 16)
    with open(old_path, "rb") as f:
        check("旧画像文件字节不变", f.read() == old_bytes)
    bind2 = fp.check_binding(conn, REPO, res_new["profile_id"])
    check("新画像为当前画像", bind2["ok"] and bind2["current"])
    again = fp.run_profile(conn, REPO, "fmt-cat", "2026-11",
                           ["P1", "P2", "P3", "P4"])
    check("旧范围复跑仍复用旧画像", again["reused"]
          and again["profile_id"] == old_id)
    return res_new


def case_09_offline_verify(conn, res):
    print("\n[09] 结果搬出仓库后校验（不重跑匹配）")
    src = os.path.join(REPO, res["profile_path"])
    moved = os.path.join(OUT, "moved-profile.json")
    os.makedirs(OUT, exist_ok=True)
    shutil.copyfile(src, moved)
    vr = verify_profile.verify_profile(moved)
    check("搬出仓库后校验通过", vr["ok"], vr["errors"][:3])
    check("校验器给出绑定信息",
          vr["bound_package_set"] == ["P1", "P2", "P3", "P4", "P6"]
          and vr["catalog"]["catalog_id"] == "fmt-cat")

    doc = json.loads(open(src, encoding="utf-8").read())
    tampered = dict(doc, summary=dict(doc["summary"], identified=99))
    tpath = os.path.join(OUT, "tampered-summary.json")
    with open(tpath, "w", encoding="utf-8") as f:
        json.dump(tampered, f, ensure_ascii=False)
    vr2 = verify_profile.verify_profile(tpath)
    check("篡改汇总被识破", not vr2["ok"])

    tampered2 = dict(doc, content_sha256="0" * 64)
    tpath2 = os.path.join(OUT, "tampered-digest.json")
    with open(tpath2, "w", encoding="utf-8") as f:
        json.dump(tampered2, f, ensure_ascii=False)
    vr3 = verify_profile.verify_profile(tpath2)
    check("篡改内容摘要被识破", not vr3["ok"])

    # 证据内部一致性：把命中偏移改错（内容摘要随之不符）
    tampered3 = json.loads(json.dumps(doc))
    for o in tampered3["objects"]:
        if o["identifierValue"] == "BS-BIG":
            o["hits"][0]["required"][0]["offsets"] = [7]
    tpath3 = os.path.join(OUT, "tampered-evidence.json")
    with open(tpath3, "w", encoding="utf-8") as f:
        json.dump(tampered3, f, ensure_ascii=False)
    vr4 = verify_profile.verify_profile(tpath3)
    check("篡改证据被识破", not vr4["ok"])


def case_10_catalog_versions(conn, res_v1):
    print("\n[10] 目录版本演进与冲突")
    r = fc.register_catalog(conn, REPO, CAT_V2_PATH)
    check("新目录版本登记", not r["reused"] and r["signature_count"] == 11)
    res_v2 = fp.run_profile(conn, REPO, "fmt-cat", "2027-01",
                            ["P1", "P2", "P3", "P4"])
    check("新版本产生新画像", not res_v2["reused"]
          and res_v2["profile_id"] != res_v1["profile_id"])
    doc2 = fp.load_profile(conn, REPO, res_v2["profile_id"])
    objs2 = {o["identifierValue"]: o for o in doc2["objects"]}
    gamma = objs2["BS-GAMMA"]
    check("新版本下 BS-GAMMA 跨格式歧义（fmt.gamma + fmt.new）",
          gamma["result"] == "ambiguous"
          and gamma["formats"] == ["fmt.gamma", "fmt.new"]
          and {h["signature_id"] for h in gamma["hits"]}
          == {"sig.gamma.masked", "sig.new"})
    check("歧义对象不计入任何格式数",
          doc2["summary"]["formats"].get("fmt.new", 0) == 0
          and doc2["summary"]["ambiguous"] == 2
          and doc2["summary"]["identified"] == 6)
    doc1 = fp.load_profile(conn, REPO, res_v1["profile_id"])
    check("旧版本画像不被改写",
          {o["identifierValue"]: o["result"] for o in doc1["objects"]
           if o["identifierValue"] == "BS-GAMMA"}["BS-GAMMA"] == "identified")

    # 同 (id, version) 不同内容：拒绝
    bad = [dict(CATALOG_LINES[0], note="改动")] + CATALOG_LINES[1:]
    path = os.path.join(WORK, "catalog-conflict.jsonl")
    write_jsonl(path, bad)
    try:
        fc.register_catalog(conn, REPO, path)
        check("同版本不同内容拒绝", False, "竟然登记成功")
    except fc.CatalogError as exc:
        check("同版本不同内容拒绝", exc.code == "catalog_version_conflict",
              exc.code)


def case_11_migration():
    print("\n[11] schema v3 -> v4 迁移")
    path = os.path.join(WORK, "repo-migrate")
    shutil.rmtree(path, ignore_errors=True)
    os.makedirs(path)
    conn = dbmod.connect(path)
    # 模拟 v3 仓：去掉 v4 新表、版本号降回 3
    for t in ("format_profiles", "catalog_signatures", "catalog_formats",
              "format_catalogs"):
        conn.execute("DROP TABLE %s" % t)
    conn.execute("UPDATE meta SET value='3' WHERE key='schema_version'")
    conn.commit()
    conn.close()
    conn = dbmod.connect(path)
    v = conn.execute(
        "SELECT value FROM meta WHERE key='schema_version'").fetchone()[0]
    tables = {r[0] for r in conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
    check("迁移到 v4 且画像表就绪",
          v == "4" and {"format_catalogs", "catalog_formats",
                        "catalog_signatures", "format_profiles"} <= tables,
          v)
    conn.close()


def case_12_cli(conn):
    print("\n[12] CLI 入口")
    env = dict(os.environ)
    env.pop("PYTHONPATH", None)

    def run(*argv, expect=0):
        p = subprocess.run([sys.executable, "-m", "evidrepo.cli"] + list(argv),
                           cwd=REPO_SRC, env=env, capture_output=True,
                           text=True)
        if p.returncode != expect:
            return None, "rc=%d stderr=%s stdout=%s" % (
                p.returncode, p.stderr[-300:], p.stdout[-300:])
        try:
            return json.loads(p.stdout), ""
        except ValueError:
            return p.stdout, ""

    out, err = run("catalogs", REPO)
    check("CLI catalogs", err == "" and len(out) == 2, err)
    out, err = run("catalog-show", REPO, "fmt-cat", "2026-11")
    check("CLI catalog-show", err == "" and out["signature_count"] == 10, err)
    out, err = run("profile-run", REPO, "fmt-cat", "2026-11",
                   "--packages", "P1,P2,P3,P4")
    check("CLI profile-run（复用）", err == "" and out["reused"], err)
    out, err = run("profile-run", REPO, "fmt-cat", "2026-11", "--all-sealed")
    check("CLI profile-run --all-sealed", err == "" and "profile_id" in out,
          err)
    pid = out["profile_id"]
    out, err = run("profiles", REPO)
    check("CLI profiles", err == "" and any(
        r["profile_id"] == pid for r in out), err)
    out, err = run("profile-show", REPO, pid)
    check("CLI profile-show", err == "" and out["summary"]["objects_total"]
          == 16, err)
    out, err = run("profile-check-binding", REPO, pid)
    check("CLI profile-check-binding（当前）",
          err == "" and out["ok"] and out["current"], err)
    out, err = run("profile-verify", os.path.join(
        REPO, "profiles", "fmt-%s.json" % pid))
    check("CLI profile-verify", err == "" and out["ok"], err)
    out, err = run("profile-run", REPO, "fmt-cat", "2026-11",
                   "--packages", "P1,P5-STG", expect=1)
    check("CLI 拒绝 staging 范围", isinstance(out, dict)
          and out.get("error") == "scope_not_sealed", err or out)
    out, err = run("catalog-register", REPO,
                   os.path.join(WORK, "bad-bad-hex.jsonl"), expect=1)
    check("CLI 拒绝无效目录", isinstance(out, dict)
          and out.get("error") == "bad_hex", err or out)


def case_13_regression(conn):
    print("\n[13] 既有功能回归冒烟（谱系/对账/发布）")
    rep = diagnostics.evaluate_representation(conn, "local", "REP-1")
    check("谱系表示评估仍可用（REP-1 verified）", rep["label"] == "verified",
          rep["label"])
    obj = diagnostics.explain_object(conn, "local", "BS-ALPHA")
    check("对象依赖解释仍可用（BS-ALPHA proven）", obj["proven"] is True)

    inv_path = os.path.join(WORK, "inv.jsonl")
    write_jsonl(inv_path, [
        {"record_type": "inventory_header",
         "format_version": "expected-inventory/v1",
         "inventory_id": "inv-reg", "batch_note": "回归"},
        {"record_type": "obligation", "item_id": "I-1",
         "obligation_id": "OBL-1",
         "acceptable_representations": [
             {"identifierType": "local", "identifierValue": "REP-1"}]},
    ])
    invmod.import_inventory(conn, REPO, inv_path)
    rres = reconc.reconcile_and_store(conn, REPO, "inv-reg")
    check("馆藏对账仍可用（OBL-1 满足）",
          rres["summary"]["satisfied"] == 1, rres["summary"])

    req = os.path.join(WORK, "req.jsonl")
    rul = os.path.join(WORK, "rul.jsonl")
    write_jsonl(req, [
        {"record_type": "release_header",
         "format_version": "release-request/v1", "request_id": "RQ",
         "audience": "aud"},
        {"record_type": "representation_selection",
         "identifierType": "local", "identifierValue": "REP-1",
         "external_code": "EXT-1"},
    ])
    write_jsonl(rul, [
        {"record_type": "rules_header", "format_version": "release-rules/v1",
         "rules_id": "RR", "audience": "aud"},
        {"record_type": "rule",
         "bitstream": {"identifierType": "local",
                       "identifierValue": "BS-ALPHA"},
         "action": "release"},
        # BS-DUP 与 BS-ALPHA 同字节：按内容统一落实需要全部别名都有规则
        {"record_type": "rule",
         "bitstream": {"identifierType": "local",
                       "identifierValue": "BS-DUP"},
         "action": "release"},
        # BS-CONFLICT 的 P3 副本也是同字节（blob 级 bytes_ok 别名）
        {"record_type": "rule",
         "bitstream": {"identifierType": "local",
                       "identifierValue": "BS-CONFLICT"},
         "action": "release"},
    ])
    plan, _ = release_plan.build_plan(conn, REPO, req, rul)
    check("发布计划仍可用（REP-1 可交付）",
          plan["summary"]["deliverable"] == 1, plan["summary"])


def main():
    shutil.rmtree(WORK, ignore_errors=True)
    os.makedirs(WORK)
    build_catalogs()
    build_packages()
    conn = fresh_repo()
    for pkg in ("P1", "P2", "P3", "P4"):
        ingest.receive(conn, REPO, os.path.join(PKGS, pkg))
        ingest.finish(conn, REPO, pkg)
    ingest.receive(conn, REPO, os.path.join(PKGS, "P5-STG"))  # 保持 staging

    catalog_sha = case_01_register_and_order(conn)
    case_02_invalid_catalogs(conn)
    res = case_03_main_profile(conn, catalog_sha)
    case_04_rerun_stable(conn, res)
    case_05_scope_subset(conn)
    case_06_states_not_masked(conn, res)
    case_07_staging_isolation(conn, res)
    res_new = case_08_old_profile_coexist(conn, res)
    case_09_offline_verify(conn, res_new)
    case_10_catalog_versions(conn, res)
    case_11_migration()
    case_12_cli(conn)
    case_13_regression(conn)
    conn.close()

    print("\n================ 画像验收结果 ================")
    print("通过 %d 项，失败 %d 项" % (len(PASS), len(FAIL)))
    if FAIL:
        for name, detail in FAIL:
            print("  FAIL: %s — %s" % (name, detail))
        sys.exit(1)
    print("全部通过。")


if __name__ == "__main__":
    main()
