# -*- coding: utf-8 -*-
"""
格式画像规模与资源边界演练（可复跑规模生成器；不提交大数据集）。运行：
  python -I /workspace/evidence_repo/tests/demo_format_profile_scale.py [--quick]

两条规模轴（题目要求：格式数、别名数、载荷体积增大时保持有界内存）：
  A. 载荷体积轴：单对象 64 MiB（--quick 8 MiB）。签名含固定偏移、
     掩码窗口、以及**满幅 1 MiB 搜索窗口**——窗口区域超过单次读取块，
     片段刻意跨 1 MiB 读取边界。断言命中偏移正确、全部 read() <= 1 MiB、
     Python 峰值分配有界（不随载荷增长）。
  B. 格式数/别名数轴：300 个格式（600 条签名）+ 2000 个别名身份
     （--quick 400）共享同一内容摘要。断言按内容复用扫描（只扫 1 次），
     但每个精确身份仍独立写入结果；峰值内存有界。

报告 tracemalloc 峰值与进程 RSS 增量，并对结果做抽查与离线校验。
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import random
import resource
import shutil
import sys
import tracemalloc

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))

from evidrepo import db as dbmod  # noqa: E402
from evidrepo import ingest  # noqa: E402
from evidrepo import format_catalog as fc  # noqa: E402
from evidrepo import format_profile as fp  # noqa: E402
from evidrepo import verify_profile  # noqa: E402

from fixtures import PackageBuilder  # noqa: E402

WORK = "/workspace/runs/format-scale"

PASS, FAIL = [], []


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append((name, detail))
    print(("  [PASS] " if cond else "  [FAIL] ") + name
          + ((" — " + str(detail)) if detail else ""))


def write_jsonl(path, records):
    with open(path, "wb") as f:
        for r in records:
            f.write(json.dumps(r, ensure_ascii=False).encode("utf-8") + b"\n")


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


def _rss_kib():
    return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss


# ---------------------------------------------------------------------------
# 轴 A：大载荷（分块扫描、跨读取块命中、有界内存）
# ---------------------------------------------------------------------------

def axis_large_payload(n_bytes):
    print("\n[A] 载荷体积轴：%d MiB 载荷" % (n_bytes // 1048576))
    root = os.path.join(WORK, "a")
    repo = os.path.join(root, "repo")
    pkgs = os.path.join(root, "pkgs")
    os.makedirs(pkgs, exist_ok=True)

    # 确定性伪随机内容（不提交数据集，运行时生成）
    rng = random.Random(20261120)
    data = bytearray(rng.randbytes(n_bytes))
    # 固定偏移签名
    data[0:5] = b"ALPHA"
    # 掩码窗口签名（窗口 [512, 2048]）
    data[1000:1005] = b"GXMMA"
    # 满幅 1 MiB 窗口：区域 > 1 MiB，片段跨 1 MiB 读取边界
    win_lo = 3 * 1048576
    win_hi = win_lo + 1048576
    plant = win_lo + 1048574          # 片段跨越 win_lo+1048576 读取边界
    data[plant:plant + 5] = b"OMEGA"
    data = bytes(data)
    digest = hashlib.sha256(data).hexdigest()

    cat = os.path.join(root, "cat.jsonl")
    write_jsonl(cat, [
        {"record_type": "catalog_header",
         "format_version": "format-catalog/v1",
         "catalog_id": "scale-a", "catalog_version": "v1"},
        {"record_type": "format", "format_id": "fmt.alpha", "name": "A"},
        {"record_type": "format", "format_id": "fmt.gamma", "name": "G"},
        {"record_type": "format", "format_id": "fmt.omega", "name": "O"},
        {"record_type": "signature", "signature_id": "sig.alpha",
         "format_id": "fmt.alpha",
         "required": [{"bytes": "414c504841", "offset": 0}]},
        {"record_type": "signature", "signature_id": "sig.gamma",
         "format_id": "fmt.gamma",
         "required": [{"bytes": "47414d4d41", "window": [512, 2048],
                       "mask": "ff00ffffff"}]},
        {"record_type": "signature", "signature_id": "sig.omega",
         "format_id": "fmt.omega",
         "required": [{"bytes": "4f4d454741",
                       "window": [win_lo, win_hi]}]},
        # 禁止片段（随机内容不应命中；验证禁止逻辑在大载荷上执行）
        {"record_type": "signature", "signature_id": "sig.never",
         "format_id": "fmt.never",
         "required": [{"bytes": "ff00ff00ff", "offset": 10}],
         "forbidden": [{"bytes": "424144", "window": [0, 1024]}]},
    ])
    # fmt.never 格式补充声明
    lines = open(cat, encoding="utf-8").read().splitlines()
    lines.insert(4, json.dumps({"record_type": "format",
                                "format_id": "fmt.never", "name": "N"}))
    with open(cat, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")

    b = PackageBuilder(pkgs, "BIG", trusted_ingest=("ing-big",))
    b.add_bitstream("BS-BIG", data)
    b.add_representation("R-BIG", ["BS-BIG"], nodes=["n"])
    b.add_event("ing-big", "ingest", outputs=["BS-BIG"])
    b.build()

    conn = dbmod.connect(repo)
    ingest.receive(conn, repo, os.path.join(pkgs, "BIG"))
    ingest.finish(conn, repo, "BIG")
    fc.register_catalog(conn, repo, cat)

    import builtins
    real_open = builtins.open
    read_sizes = []

    def tracking_open(file, mode="r", *a, **kw):
        raw = real_open(file, mode, *a, **kw)
        if "b" in mode and "r" in mode:
            return _TrackingFile(raw, read_sizes)
        return raw

    rss0 = _rss_kib()
    tracemalloc.start()
    builtins.open = tracking_open
    try:
        res = fp.run_profile(conn, repo, "scale-a", "v1", ["BIG"])
    finally:
        builtins.open = real_open
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    rss1 = _rss_kib()

    doc = fp.load_profile(conn, repo, res["profile_id"])
    obj = doc["objects"][0]
    hits = {h["signature_id"]: h for h in obj["hits"]}
    check("A: 大载荷三格式歧义（alpha+gamma+omega）",
          obj["result"] == "ambiguous"
          and obj["formats"] == ["fmt.alpha", "fmt.gamma", "fmt.omega"])
    check("A: 跨 1 MiB 读取边界命中于种植偏移",
          hits["sig.omega"]["required"][0]["offsets"] == [plant]
          and hits["sig.omega"]["required"][0]["matched_bytes"]
          == "4f4d454741")
    check("A: 掩码窗口命中", hits["sig.gamma"]["required"][0]["offsets"]
          == [1000])
    check("A: 禁止片段签名未命中", "sig.never" not in hits)
    check("A: 内容摘要与长度核对", obj["content_sha256"] == digest
          and obj["content_length"] == n_bytes)
    check("A: 全部 read() <= 1 MiB",
          read_sizes and max(read_sizes) <= (1 << 20),
          "max=%d" % (max(read_sizes) if read_sizes else -1))
    peak_mib = peak / 1048576
    check("A: Python 峰值分配有界（< 16 MiB，载荷 %d MiB）"
          % (n_bytes // 1048576), peak_mib < 16.0,
          "peak=%.2f MiB" % peak_mib)
    vr = verify_profile.verify_profile(
        os.path.join(repo, res["profile_path"]))
    check("A: 画像离线校验通过", vr["ok"], vr["errors"][:2])
    conn.close()
    return {
        "axis": "large_payload",
        "payload_mib": n_bytes // 1048576,
        "py_peak_alloc_mib": round(peak_mib, 3),
        "rss_delta_kib": rss1 - rss0,
        "max_read_bytes": max(read_sizes) if read_sizes else None,
        "contents_scanned": res["stats"]["contents_scanned"],
    }


# ---------------------------------------------------------------------------
# 轴 B：格式数 + 别名数（扫描复用、逐身份独立记录、有界内存）
# ---------------------------------------------------------------------------

def axis_many_aliases(n_aliases, n_formats):
    print("\n[B] 格式/别名轴：%d 格式、%d 别名" % (n_formats, n_aliases))
    root = os.path.join(WORK, "b")
    repo = os.path.join(root, "repo")
    pkgs = os.path.join(root, "pkgs")
    os.makedirs(pkgs, exist_ok=True)

    # 每个格式两条签名：tagA@0 与 tagB∈[16,64]；共享内容只带 k007 的标签
    hit_idx = 7
    other_idx = 3
    lines = [{"record_type": "catalog_header",
              "format_version": "format-catalog/v1",
              "catalog_id": "scale-b", "catalog_version": "v1"}]
    for i in range(n_formats):
        lines.append({"record_type": "format",
                      "format_id": "fmt.k%03d" % i, "name": "Fmt %d" % i})
    for i in range(n_formats):
        tag_a = b"TA" + b"%06d" % i
        tag_b = b"TB" + b"%06d" % i
        lines.append({"record_type": "signature",
                      "signature_id": "sig.k%03d.a" % i,
                      "format_id": "fmt.k%03d" % i,
                      "required": [{"bytes": tag_a.hex(), "offset": 0}]})
        lines.append({"record_type": "signature",
                      "signature_id": "sig.k%03d.b" % i,
                      "format_id": "fmt.k%03d" % i,
                      "required": [{"bytes": tag_b.hex(),
                                    "window": [16, 64]}]})
    write_jsonl(os.path.join(root, "cat.jsonl"), lines)

    tag_a = b"TA" + b"%06d" % hit_idx
    tag_b = b"TB" + b"%06d" % hit_idx
    shared = tag_a + b"\x00" * 24 + tag_b + b"\x00" * 200   # tagB@32 ∈ [16,64]
    # 歧义内容：同时带 k003 与 k007 的标签
    amb = (b"TA" + b"%06d" % other_idx) + b"\x00" * 24 \
        + (b"TB" + b"%06d" % other_idx) + b"\x00" * 8 + tag_a + b"\x00" * 8 \
        + tag_b + b"\x00" * 32
    unknown = bytes(range(256))

    b = PackageBuilder(pkgs, "ALIAS", trusted_ingest=("ing-a",))
    for i in range(n_aliases):
        b.add_bitstream("BS-AL%05d" % i, shared)
    b.add_bitstream("BS-AMB", amb)
    b.add_bitstream("BS-UNKNOWN", unknown)
    b.add_representation("R-MAIN", ["BS-AL%05d" % 0], nodes=["n"])
    b.add_event("ing-a", "ingest",
                outputs=["BS-AL%05d" % 0, "BS-AMB", "BS-UNKNOWN"])
    b.build()

    conn = dbmod.connect(repo)
    ingest.receive(conn, repo, os.path.join(pkgs, "ALIAS"))
    ingest.finish(conn, repo, "ALIAS")
    fc.register_catalog(conn, repo, os.path.join(root, "cat.jsonl"))

    rss0 = _rss_kib()
    tracemalloc.start()
    res = fp.run_profile(conn, repo, "scale-b", "v1", ["ALIAS"])
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    rss1 = _rss_kib()

    doc = fp.load_profile(conn, repo, res["profile_id"])
    objs = doc["objects"]
    s = doc["summary"]
    check("B: 对象总数 = 别名 + 2", len(objs) == n_aliases + 2
          and s["objects_total"] == n_aliases + 2)
    check("B: 扫描按内容复用（3 种内容扫描 3 次）",
          res["stats"]["contents_scanned"] == 3, res["stats"])
    check("B: 每个身份字节均复核（%d 副本）" % (n_aliases + 2),
          res["stats"]["copies_verified"] == n_aliases + 2)
    check("B: 汇总（%d identified / 1 ambiguous / 1 unidentified）"
          % n_aliases,
          s["identified"] == n_aliases and s["ambiguous"] == 1
          and s["unidentified"] == 1
          and s["formats"] == {"fmt.k%03d" % hit_idx: n_aliases})
    by_id = {o["identifierValue"]: o for o in objs}
    spot = by_id["BS-AL%05d" % (n_aliases - 1)]
    spot_hits = {h["signature_id"] for h in spot["hits"]}
    check("B: 每个别名独立记录且证据完整",
          spot["result"] == "identified"
          and spot["formats"] == ["fmt.k%03d" % hit_idx]
          and spot_hits == {"sig.k%03d.a" % hit_idx,
                            "sig.k%03d.b" % hit_idx}
          and by_id["BS-AMB"]["result"] == "ambiguous"
          and by_id["BS-AMB"]["formats"] == ["fmt.k%03d" % other_idx,
                                             "fmt.k%03d" % hit_idx])
    peak_mib = peak / 1048576
    check("B: Python 峰值分配有界（< 64 MiB）", peak_mib < 64.0,
          "peak=%.2f MiB" % peak_mib)
    vr = verify_profile.verify_profile(
        os.path.join(repo, res["profile_path"]))
    check("B: 画像离线校验通过", vr["ok"], vr["errors"][:2])
    bind = fp.check_binding(conn, repo, res["profile_id"])
    check("B: 画像为当前仓画像", bind["ok"] and bind["current"])
    conn.close()
    return {
        "axis": "aliases_formats",
        "aliases": n_aliases,
        "formats": n_formats,
        "objects": len(objs),
        "contents_scanned": res["stats"]["contents_scanned"],
        "py_peak_alloc_mib": round(peak_mib, 3),
        "rss_delta_kib": rss1 - rss0,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--quick", action="store_true")
    args = ap.parse_args()
    shutil.rmtree(WORK, ignore_errors=True)
    os.makedirs(WORK)

    n_bytes = 8 * 1048576 if args.quick else 64 * 1048576
    n_aliases = 400 if args.quick else 2000
    n_formats = 60 if args.quick else 300

    r1 = axis_large_payload(n_bytes)
    r2 = axis_many_aliases(n_aliases, n_formats)

    print("\n================ 画像规模演练结果 ================")
    for r in (r1, r2):
        print(json.dumps(r, ensure_ascii=False))
    print("通过 %d 项，失败 %d 项" % (len(PASS), len(FAIL)))
    if FAIL:
        for name, detail in FAIL:
            print("  FAIL: %s — %s" % (name, detail))
        sys.exit(1)
    print("规模演练通过：分块扫描正确、跨读取块命中、峰值内存有界、"
          "扫描按内容复用且逐身份独立记录。")


if __name__ == "__main__":
    main()
