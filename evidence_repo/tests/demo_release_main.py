# -*- coding: utf-8 -*-
"""
离线发布主演练（end-to-end，合成材料）。运行：
  python -I /workspace/evidence_repo/tests/demo_release_main.py

主例（题目指定）：
  原件 = "A馆B" 的 UTF-8 字节，共 5 字节：
      偏移 0='A'(0x41)  偏移 1..3='馆'(E9 A6 86)  偏移 4='B'(0x42)
  三个不同 bitstream 身份承载**相同字节**：
      BS-DIRECT（被选中表示直接引用，release）
      BS-M1   （未选表示别名，redact [1,4)）
      BS-M2   （未选表示别名，redact [4,5)）
  按内容统一落实 => 区间并集 [1,5)，公开副本必须是 b"A****"（5 字节），
  公开清单只引用这一份交付文件（外加共同成员 BS-OTHER 的放行文件）。

  再加入一个指向相同内容、应暂缓的 **staging** 身份 BS-STAGE：
  staging 对 sealed 视图不可见，计划仍可发布；封存该身份后，旧计划因
  sealed 包集合变化被拒绝（陈旧）；重做计划后，所有含此内容的表示暂缓，
  与它共享其他成员（BS-OTHER）的开放表示仍可交付那个共同成员。

预期字节由本文件内的固定表格独立计算（expected 表），并逐项核对
外发目录树与公开清单字段。
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))

from evidrepo import db as dbmod  # noqa: E402
from evidrepo import ingest, release_plan, release_publish  # noqa: E402
from evidrepo import verify_release  # noqa: E402
from evidrepo.release_rules import ReleaseInputError  # noqa: E402

from fixtures import PackageBuilder  # noqa: E402

WORK = "/workspace/runs/release-main"
PKGS = os.path.join(WORK, "packages")
OUT = os.path.join(WORK, "out")
REPO = os.path.join(WORK, "repo")

CONTENT = "A馆B".encode("utf-8")
CONTENT_SHA = hashlib.sha256(CONTENT).hexdigest()
OTHER = b"shared-other-member"
OTHER_SHA = hashlib.sha256(OTHER).hexdigest()

# ---- 固定预期表（独立短算，不调用被测代码）-------------------------------
EXPECTED = {
    "original_bytes": CONTENT,
    "original_len": 5,
    "original_sha256": CONTENT_SHA,
    "union_ranges": [[1, 4], [4, 5]],
    "merged_union": [[1, 5]],
    "redacted_bytes": b"A****",
    "redacted_len": 5,
    "redacted_sha256": hashlib.sha256(b"A****").hexdigest(),
    "other_bytes": OTHER,
    "other_sha256": OTHER_SHA,
}


def write_jsonl(path, records):
    with open(path, "wb") as f:
        for r in records:
            f.write(json.dumps(r, ensure_ascii=False).encode("utf-8") + b"\n")


def main_request(path, codes):
    write_jsonl(path, [
        {"record_type": "release_header",
         "format_version": "release-request/v1",
         "request_id": "REQ-MAIN", "audience": "reading-room-a"},
        *[
            {"record_type": "representation_selection",
             "identifierType": t, "identifierValue": v,
             "external_code": code}
            for (t, v, code) in codes
        ],
    ])


def rules_main(path, include_stage=False, stage_hold=True):
    recs = [
        {"record_type": "rules_header",
         "format_version": "release-rules/v1",
         "rules_id": "RULES-MAIN", "audience": "reading-room-a"},
        {"record_type": "rule",
         "bitstream": {"identifierType": "local", "identifierValue": "BS-DIRECT"},
         "action": "release"},
        {"record_type": "rule",
         "bitstream": {"identifierType": "local", "identifierValue": "BS-M1"},
         "action": "redact", "content_sha256": CONTENT_SHA,
         "ranges": [[1, 4]]},
        {"record_type": "rule",
         "bitstream": {"identifierType": "local", "identifierValue": "BS-M2"},
         "action": "redact", "content_sha256": CONTENT_SHA,
         "ranges": [[4, 5]]},
        {"record_type": "rule",
         "bitstream": {"identifierType": "local", "identifierValue": "BS-OTHER"},
         "action": "release"},
    ]
    if include_stage:
        if stage_hold:
            recs.append(
                {"record_type": "rule",
                 "bitstream": {"identifierType": "local",
                               "identifierValue": "BS-STAGE"},
                 "action": "hold"})
        # 缺规则情形由 edge 演练覆盖；这里默认显式 hold
    write_jsonl(path, recs)


def build_p1():
    b = PackageBuilder(PKGS, "P1",
                       trusted_ingest=("ing-X", "ing-O"))
    b.add_bitstream("BS-DIRECT", CONTENT)
    b.add_bitstream("BS-M1", CONTENT)
    b.add_bitstream("BS-M2", CONTENT)
    b.add_bitstream("BS-OTHER", OTHER)
    # 主表示：直接引用放行身份 + 共同成员
    b.add_representation("REP-MAIN", ["BS-DIRECT", "BS-OTHER"],
                         nodes=["node-main"])
    # 未选表示：两个遮盖别名
    b.add_representation("REP-ALIAS", ["BS-M1", "BS-M2"], nodes=["node-alias"])
    # 只含共同成员的表示（用于后半段“共享成员仍可交付”）
    b.add_representation("REP-SHARED", ["BS-OTHER"], nodes=["node-shared"])
    b.add_event("ing-X", "ingest",
                outputs=["BS-DIRECT", "BS-M1", "BS-M2"])
    b.add_event("ing-O", "ingest", outputs=["BS-OTHER"])
    return b.build()


def build_p2_stage():
    b = PackageBuilder(PKGS, "P2", trusted_ingest=("ing-S",))
    b.add_bitstream("BS-STAGE", CONTENT)  # 相同内容、不同身份
    b.add_event("ing-S", "ingest", outputs=["BS-STAGE"])
    return b.build()


def setup():
    if os.path.exists(WORK):
        shutil.rmtree(WORK)
    os.makedirs(PKGS)
    os.makedirs(OUT)


def main():
    print("=" * 64)
    print("离线发布主演练  原件 A馆B =", CONTENT, "(%d 字节)" % len(CONTENT))
    print("=" * 64)
    setup()
    conn = dbmod.connect(REPO)

    # ---- 封存 P1 -------------------------------------------------------
    build_p1()
    ingest.receive(conn, REPO, os.path.join(PKGS, "P1"))
    ingest.finish(conn, REPO, "P1")

    req1 = os.path.join(WORK, "request-1.jsonl")
    rules1 = os.path.join(WORK, "rules-1.jsonl")
    main_request(req1, [("local", "REP-MAIN", "EXT-MAIN-0001")])
    rules_main(rules1)

    # ---- 阶段 A：staging 身份存在但不可见，计划仍可发布 ---------------
    build_p2_stage()
    ingest.receive(conn, REPO, os.path.join(PKGS, "P2"))  # 不 finish
    staged = conn.execute(
        "SELECT state FROM packages WHERE package_id='P2'"
    ).fetchone()["state"]
    assert staged == "staging", staged
    print("[A] P2 处于 staging；sealed 视图看不到 BS-STAGE")

    plan1, reused = release_plan.build_plan(conn, REPO, req1, rules1)
    assert reused is False
    s = plan1["summary"]
    print("[A] 计划 %s 摘要: %s" % (plan1["plan_id"][:12],
                                    json.dumps(s, ensure_ascii=False)))
    assert s["deliverable"] == 1 and s["held"] == 0, s
    # 内容 X 的决定必须是 redact，并集为 [1,5)，且纳入全部三个 sealed 别名
    cx = next(c for c in plan1["contents"]
              if c["content_sha256"] == CONTENT_SHA)
    alias_ids = sorted(a["identifierValue"] for a in cx["aliases"])
    assert alias_ids == ["BS-DIRECT", "BS-M1", "BS-M2"], alias_ids
    assert cx["decision"] == "redact" and not cx["blocked"]
    assert cx["merged_redaction_ranges"] == EXPECTED["merged_union"], \
        cx["merged_redaction_ranges"]
    co = next(c for c in plan1["contents"]
              if c["content_sha256"] == OTHER_SHA)
    assert co["decision"] == "release"

    # ---- 阶段 B：发布到全新目标，校验目录与字节 ------------------------
    target1 = os.path.join(OUT, "delivery-1")
    delivery = release_publish.publish(conn, REPO, plan1["plan_id"], target1)
    print("[B] 发布登记:", json.dumps(delivery, ensure_ascii=False))
    vr = verify_release.verify_release(target1)
    assert vr["ok"], vr["errors"]
    print("[B] 离线自校验通过: %s" % vr["checks"])

    tree = []
    for dp, dns, fns in os.walk(target1):
        for fn in sorted(fns):
            tree.append(os.path.relpath(os.path.join(dp, fn), target1))
    print("[B] 外发目录树:", sorted(tree))
    assert sorted(tree)[0].startswith("payloads/")
    assert all(not os.path.islink(os.path.join(target1, x)) for x in tree)

    with open(os.path.join(target1, "release-manifest.json"),
              encoding="utf-8") as f:
        manifest = json.load(f)
    # 公开字段受控：无任何馆内泄漏
    allowed = {"profile", "audience", "files", "representations"}
    assert set(manifest.keys()) == allowed, manifest.keys()
    assert manifest["audience"] == "reading-room-a"
    assert len(manifest["representations"]) == 1
    rep = manifest["representations"][0]
    assert rep["external_code"] == "EXT-MAIN-0001"
    assert set(rep.keys()) == {"external_code", "members"}
    # 两个交付文件：X 的遮盖副本 + OTHER 原字节
    assert len(manifest["files"]) == 2, manifest["files"]
    by_sha = {f["sha256"]: f for f in manifest["files"]}
    red_file = by_sha[EXPECTED["redacted_sha256"]]
    oth_file = by_sha[EXPECTED["other_sha256"]]
    # 文件名受控且不含原件摘要/身份
    for f in manifest["files"]:
        assert f["file"].startswith("payloads/") is False  # 清单内为相对名
        assert f["file"].startswith("f-") and f["file"].endswith(".bin")
        assert CONTENT_SHA not in f["file"]
        assert "BS-" not in f["file"] and "REP-" not in f["file"]
    # 实际遮盖字节核对
    with open(os.path.join(target1, "payloads", red_file["file"]), "rb") as f:
        got = f.read()
    assert got == EXPECTED["redacted_bytes"], got
    assert red_file["size"] == EXPECTED["redacted_len"]
    print("[B] 遮盖副本字节 =", got, " 预期 =", EXPECTED["redacted_bytes"])
    # 放行文件等于原件
    with open(os.path.join(target1, "payloads", oth_file["file"]), "rb") as f:
        got_other = f.read()
    assert got_other == EXPECTED["other_bytes"]
    assert oth_file["size"] == len(OTHER) and oth_file["sha256"] == OTHER_SHA
    # 清单只引用这一份 X 交付文件（同一内容多表示共享，这里仅一个表示）
    x_refs = [m for m in rep["members"]
              if m["sha256"] == EXPECTED["redacted_sha256"]]
    assert len(x_refs) == 1 and len({m["file"] for m in rep["members"]}) == 2
    print("[B] 公开清单仅含外部代号、生成文件名、交付 length/sha256，无馆内字段")

    # 重复发布到同一路径：目标已存在，保留原内容，拒绝
    try:
        release_publish.publish(conn, REPO, plan1["plan_id"], target1)
        raise AssertionError("existing target must be preserved")
    except release_publish.PublishError as exc:
        assert exc.code == "target_exists", exc.code
        print("[B] 同路径重复发布被拒绝（target_exists），原目录保留")

    # ---- 阶段 C：封存 P2 -> 旧计划陈旧，必须拒绝 -----------------------
    ingest.finish(conn, REPO, "P2")
    print("[C] P2 已封存；BS-STAGE 进入 sealed 视图")
    target2 = os.path.join(OUT, "delivery-2")
    try:
        release_publish.publish(conn, REPO, plan1["plan_id"], target2)
        raise AssertionError("stale plan must not be delivered")
    except release_publish.PublishError as exc:
        assert exc.code == "stale_plan", exc.code
        assert not os.path.exists(target2), "失败后正式路径不得出现"
        print("[C] 旧计划被拒绝（stale_plan），正式路径不存在:",
              not os.path.exists(target2))

    # ---- 阶段 D：重做计划（含 stage 规则）-> 含 X 的表示全暂缓 ---------
    req2 = os.path.join(WORK, "request-2.jsonl")
    rules2 = os.path.join(WORK, "rules-2.jsonl")
    main_request(req2, [
        ("local", "REP-MAIN", "EXT-MAIN-0002"),
        ("local", "REP-SHARED", "EXT-SHARED-0001"),
    ])
    rules_main(rules2, include_stage=True, stage_hold=True)
    plan2, _ = release_plan.build_plan(conn, REPO, req2, rules2)
    s2 = plan2["summary"]
    print("[D] 重做计划摘要:", json.dumps(s2, ensure_ascii=False))
    cx2 = next(c for c in plan2["contents"]
               if c["content_sha256"] == CONTENT_SHA)
    # 四个别名（含 BS-STAGE），其中 hold -> 内容整体暂缓
    assert sorted(a["identifierValue"] for a in cx2["aliases"]) == [
        "BS-DIRECT", "BS-M1", "BS-M2", "BS-STAGE"]
    assert cx2["decision"] == "held", cx2["decision"]
    assert any("explicit_hold" in r for r in cx2["reasons"]), cx2["reasons"]
    dec = {r["external_code"]: r["decision"]
           for r in plan2["representations"]}
    assert dec == {"EXT-MAIN-0002": "held",
                   "EXT-SHARED-0001": "deliverable"}, dec
    print("[D] 含该内容的 REP-MAIN 暂缓；REP-SHARED 仍可交付共同成员")

    # 含暂缓表示的计划：整体发布只会交付 deliverable 部分
    target3 = os.path.join(OUT, "delivery-3")
    d3 = release_publish.publish(conn, REPO, plan2["plan_id"], target3)
    vr3 = verify_release.verify_release(target3)
    assert vr3["ok"], vr3["errors"]
    with open(os.path.join(target3, "release-manifest.json"),
              encoding="utf-8") as f:
        m3 = json.load(f)
    # 只有 REP-SHARED，且只含 OTHER；X 的任何副本都不得外发
    assert [r["external_code"] for r in m3["representations"]] == [
        "EXT-SHARED-0001"]
    all_sha = {f["sha256"] for f in m3["files"]}
    assert all_sha == {OTHER_SHA}, all_sha
    assert EXPECTED["redacted_sha256"] not in all_sha
    assert CONTENT_SHA not in all_sha
    print("[D] 交付目录仅含共同成员 OTHER；暂缓内容 X 留在馆内。交付号",
          d3["delivery_no"])

    # ---- 阶段 E：计划内容寻址、只增不改、可复跑 ------------------------
    plan2b, reused2 = release_plan.build_plan(conn, REPO, req2, rules2)
    assert reused2 is True and plan2b["plan_id"] == plan2["plan_id"]
    plans = release_plan.list_plans(conn)
    assert len(plans) == 2, len(plans)
    print("[E] 相同输入复用 plan_id（%s）；计划登记表只增不改，共 %d 份"
          % (plan2["plan_id"][:12], len(plans)))

    conn.close()
    print("\n主演练全部断言通过。预期表与外发字节、目录树、清单字段一致。")


if __name__ == "__main__":
    main()
