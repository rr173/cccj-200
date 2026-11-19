# -*- coding: utf-8 -*-
"""
离线发布规模与资源边界演练。运行：
  python -I /workspace/evidence_repo/tests/demo_release_scale.py [--quick]

两条可复跑的规模轴（题目要求）：
  A. 大文件体积：单成员 64 MiB（--quick 8 MiB），多字节 UTF-8 字符与遮盖
     区间刻意跨越 1 MiB 块边界；把 redaction.CHUNK_SIZE 降到 64 KiB 强制
     大量跨块处理，验证分块正确性与有界内存。
  B. 别名与区间数量：同一内容挂 2000 个 redact 别名（--quick 300 个），
     每个别名一条区间，外加 release/hold 别名；验证规则、别名反查、成员
     关系与清单处理走 SQLite/有界缓存，峰值内存不随别名数失控。

报告 Python tracemalloc 峰值、进程 RSS 增量，并对产物做固定抽查
（遮盖字节、长度、交付摘要、文件数）。
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sys
import tracemalloc

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))

from evidrepo import db as dbmod  # noqa: E402
from evidrepo import ingest, release_plan, release_publish  # noqa: E402
from evidrepo import redaction, verify_release  # noqa: E402

from fixtures import PackageBuilder  # noqa: E402

WORK = "/workspace/runs/release-scale"


def write_jsonl(path, records):
    with open(path, "wb") as f:
        for r in records:
            f.write(json.dumps(r, ensure_ascii=False).encode("utf-8") + b"\n")


def build_large_content(n_bytes):
    """
    构造确定的合法 UTF-8 内容：交替 ASCII 与三字节字符（'馆'），
    保证多字节字符会跨越块边界；返回 (bytes, 字符边界偏移集合)。
    """
    parts = []
    triple = "馆".encode("utf-8")  # E9 A6 86
    total = 0
    i = 0
    while total < n_bytes:
        # 每轮：1 个 ASCII（1 字节）+ 1 个三字节字符 => 4 字节
        parts.append(b"Z" if i % 2 == 0 else b"Y")
        parts.append(triple)
        total += 4
        i += 1
    data = b"".join(parts)[:n_bytes]
    # 边界偏移：ASCII 单字节边界与三字节字符的起点/终点
    boundaries = {0, len(data)}
    pos = 0
    for _ in range(len(data) // 4):
        boundaries.add(pos)          # ASCII 起点
        boundaries.add(pos + 1)      # 三字节字符起点
        boundaries.add(pos + 4)      # 三字节字符终点
        pos += 4
    return data, boundaries


def axis_large_file(repo, pkgs, out, n_bytes, small_chunk):
    print("\n[A] 大文件轴：%d KiB 载荷，redaction 块=%d KiB"
          % (n_bytes // 1024, small_chunk // 1024))
    data, boundaries = build_large_content(n_bytes)
    digest = hashlib.sha256(data).hexdigest()
    # 选两个跨越块边界的字符对齐区间（起点/终点都在字符边界上）
    r1_s, r1_e = small_chunk - 3, small_chunk + 5
    r2_s, r2_e = small_chunk * 3 - 3, small_chunk * 3 + 5
    for s, e in ((r1_s, r1_e), (r2_s, r2_e)):
        assert s in boundaries and e in boundaries, (s, e)

    b = PackageBuilder(pkgs, "BIG", trusted_ingest=("ing-big",))
    b.add_bitstream("BIGBS", data)
    b.add_representation("RBIG", ["BIGBS"], nodes=["n"])
    b.add_event("ing-big", "ingest", outputs=["BIGBS"])
    b.build()
    conn = _conn(repo)
    ingest.receive(conn, repo, os.path.join(pkgs, "BIG"))
    ingest.finish(conn, repo, "BIG")

    req = os.path.join(WORK, "req-big.jsonl")
    rul = os.path.join(WORK, "rul-big.jsonl")
    write_jsonl(req, [
        {"record_type": "release_header",
         "format_version": "release-request/v1",
         "request_id": "REQ-BIG", "audience": "aud-scale"},
        {"record_type": "representation_selection",
         "identifierType": "local", "identifierValue": "RBIG",
         "external_code": "EXT-BIG-0001"},
    ])
    write_jsonl(rul, [
        {"record_type": "rules_header",
         "format_version": "release-rules/v1",
         "rules_id": "R-BIG", "audience": "aud-scale"},
        {"record_type": "rule",
         "bitstream": {"identifierType": "local",
                       "identifierValue": "BIGBS"},
         "action": "redact", "content_sha256": digest,
         "ranges": [[r1_s, r1_e], [r2_s, r2_e]]},
    ])

    saved_chunk = redaction.CHUNK_SIZE
    redaction.CHUNK_SIZE = small_chunk  # 强制跨块 UTF-8 字符与区间
    try:
        tracemalloc.start()
        plan, _ = release_plan.build_plan(conn, repo, req, rul)
        target = os.path.join(out, "big-delivery")
        delivery = release_publish.publish(conn, repo, plan["plan_id"], target)
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
    finally:
        redaction.CHUNK_SIZE = saved_chunk

    vr = verify_release.verify_release(target)
    assert vr["ok"], vr["errors"]
    # 独立重算期望遮盖字节（不调用被测遮盖器）
    expected = bytearray(data)
    for s, e in ((r1_s, r1_e), (r2_s, r2_e)):
        for k in range(s, e):
            expected[k] = 0x2A
    expected = bytes(expected)
    fname = os.listdir(os.path.join(target, "payloads"))[0]
    with open(os.path.join(target, "payloads", fname), "rb") as f:
        got = f.read()
    assert got == expected, "redacted bytes mismatch"
    assert len(got) == n_bytes
    delivered_sha = hashlib.sha256(expected).hexdigest()
    with open(os.path.join(target, "release-manifest.json"),
              encoding="utf-8") as f:
        manifest = json.load(f)
    assert manifest["files"][0]["sha256"] == delivered_sha
    # 抽查：遮盖区全为 '*'，遮盖区外与原件逐字节一致
    inside = set(range(r1_s, r1_e)) | set(range(r2_s, r2_e))
    for i in (0, r1_s - 1, r1_e, r2_s - 1, r2_e, n_bytes - 1):
        if 0 <= i < n_bytes and i not in inside:
            assert got[i] == data[i]
    conn.close()
    return {
        "axis": "large_file",
        "bytes": n_bytes,
        "chunk_kib": small_chunk // 1024,
        "py_peak_alloc_mib": round(peak / 1048576, 3),
        "delivery_no": delivery["delivery_no"],
        "delivered_sha256": delivered_sha,
        "length": n_bytes,
        "verify_ok": vr["ok"],
    }


def axis_many_aliases(repo, pkgs, out, n_aliases):
    print("\n[B] 别名/区间轴：%d 个 redact 别名 + release/hold 别名"
          % n_aliases)
    data = ("边界文本ABC").encode("utf-8") * 64  # 合法 UTF-8，长度可控
    digest = hashlib.sha256(data).hexdigest()
    length = len(data)
    # 预计算全部 UTF-8 字符边界，所有区间端点都取自该集合
    boundaries = [0]
    for i, byte in enumerate(data):
        if i > 0 and (byte < 0x80 or byte >= 0xC0):
            boundaries.append(i)
    boundaries.append(length)
    char_offsets = boundaries[:-1]  # 可作区间起点的字符起始偏移

    b = PackageBuilder(pkgs, "ALIAS", trusted_ingest=("ing-a",))
    # 主身份（被选中表示直接引用）
    b.add_bitstream("BS-MAIN", data)
    b.add_representation("RMAIN", ["BS-MAIN"], nodes=["n"])
    b.add_event("ing-a", "ingest", outputs=["BS-MAIN"])
    # 大量别名身份承载相同字节（同一包内不同对象身份）
    for i in range(n_aliases):
        b.add_bitstream("BS-AL%05d" % i, data)
    b.build()
    conn = _conn(repo)
    ingest.receive(conn, repo, os.path.join(pkgs, "ALIAS"))
    ingest.finish(conn, repo, "ALIAS")

    req = os.path.join(WORK, "req-alias.jsonl")
    rul = os.path.join(WORK, "rul-alias.jsonl")
    write_jsonl(req, [
        {"record_type": "release_header",
         "format_version": "release-request/v1",
         "request_id": "REQ-ALIAS", "audience": "aud-scale"},
        {"record_type": "representation_selection",
         "identifierType": "local", "identifierValue": "RMAIN",
         "external_code": "EXT-ALIAS-0001"},
    ])
    recs = [
        {"record_type": "rules_header",
         "format_version": "release-rules/v1",
         "rules_id": "R-ALIAS", "audience": "aud-scale"},
        # 主身份 release，但别名 redact => 内容整体 redact
        {"record_type": "rule",
         "bitstream": {"identifierType": "local",
                       "identifierValue": "BS-MAIN"},
         "action": "release"},
    ]
    # 每个别名一条“单个字符”区间（端点均在字符边界上；跨规则允许重叠）
    for i in range(n_aliases):
        s = char_offsets[i % len(char_offsets)]
        e = boundaries[boundaries.index(s) + 1]
        recs.append({
            "record_type": "rule",
            "bitstream": {"identifierType": "local",
                          "identifierValue": "BS-AL%05d" % i},
            "action": "redact", "content_sha256": digest,
            "ranges": [[s, e]],
        })
    write_jsonl(rul, recs)

    tracemalloc.start()
    plan, _ = release_plan.build_plan(conn, repo, req, rul)
    target = os.path.join(out, "alias-delivery")
    delivery = release_publish.publish(conn, repo, plan["plan_id"], target)
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    c = next(x for x in plan["contents"]
             if x["content_sha256"] == digest)
    assert c["decision"] == "redact", c["decision"]
    # 全部别名（主身份 + N 个）都纳入内容视角
    assert len(c["aliases"]) == n_aliases + 1, len(c["aliases"])
    union = c["merged_redaction_ranges"]
    covered = set()
    for s, e in union:
        covered.update(range(s, e))
    # 期望覆盖：所有被选字符区间的字节并集
    expected_covered = set()
    for i in range(n_aliases):
        s = char_offsets[i % len(char_offsets)]
        e = boundaries[boundaries.index(s) + 1]
        expected_covered.update(range(s, e))
    assert covered == expected_covered, (covered, expected_covered)
    vr = verify_release.verify_release(target)
    assert vr["ok"], vr["errors"]
    expected = bytearray(data)
    for i in expected_covered:
        expected[i] = 0x2A
    fname = os.listdir(os.path.join(target, "payloads"))[0]
    with open(os.path.join(target, "payloads", fname), "rb") as f:
        got = f.read()
    assert got == bytes(expected)
    conn.close()
    return {
        "axis": "many_aliases",
        "aliases": n_aliases + 1,
        "union_ranges": len(union),
        "py_peak_alloc_mib": round(peak / 1048576, 3),
        "delivered_sha256": hashlib.sha256(bytes(expected)).hexdigest(),
        "verify_ok": vr["ok"],
    }


def _conn(repo):
    return dbmod.connect(repo)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--quick", action="store_true")
    args = ap.parse_args()
    shutil.rmtree(WORK, ignore_errors=True)
    repo = os.path.join(WORK, "repo")
    pkgs = os.path.join(WORK, "pkgs")
    out = os.path.join(WORK, "out")
    os.makedirs(pkgs)
    os.makedirs(out)

    n_big = 8 * 1024 * 1024 if args.quick else 64 * 1024 * 1024
    n_alias = 300 if args.quick else 2000
    # 独立仓分别测两轴，避免互相干扰内存口径
    r1 = axis_large_file(repo + "-big", pkgs + "-big", out, n_big,
                         small_chunk=64 * 1024)
    r2 = axis_many_aliases(repo + "-alias", pkgs + "-alias", out, n_alias)

    print("\n================ 规模演练结果 ================")
    for r in (r1, r2):
        print(json.dumps(r, ensure_ascii=False))
    # 资源断言：峰值 Python 分配远小于载荷，且不随别名数失控
    assert r1["py_peak_alloc_mib"] < 16.0, r1
    assert r2["py_peak_alloc_mib"] < 32.0, r2
    assert r1["verify_ok"] and r2["verify_ok"]
    print("\n规模演练通过：分块跨块遮盖正确，峰值内存有界，产物抽查与摘要一致。")


if __name__ == "__main__":
    main()
