# -*- coding: utf-8 -*-
"""
离线发布边界演练。运行：
  python -I /workspace/evidence_repo/tests/demo_release_edges.py

覆盖：
  1. 字符边界校验：被 [1,4) 完整覆盖的 [2,3) 仍被发现（2、3 是延续字节）
  2. 规则语法错误 => 计划失败；缺规则 => 业务暂缓（两者显式区分）
  3. 重复/冲突规则、重复外部代号、非法区间、未知动作、坏版本/BOM/坏 JSON
  4. 绑定摘要不符 => blocked，阻止产生可发布结果并可定位失败对象
  5. 非 UTF-8 原件 => blocked
  6. 源字节变更（交付前篡改封存文件）=> 发布失败、正式路径不存在
  7. 交付前并发封存 => 旧计划拒绝（明确先后顺序）
  8. 发布中断（模拟 os.rename 前异常）=> 正式路径不存在、无半成品
  9. 目录移动后注入多余文件/符号链接/缺文件/摘要错误 => 离线校验拒绝
 10. 跨包重复声明（相同成员集合合并）、相同 value 不同 type、
     来源身份冲突（identity_conflict 表示暂缓）
 11. 路径逃逸文件名由受控命名规则根除；外部代号 ASCII 安全格式
 12. 公开清单不含任何馆内字段
"""
from __future__ import annotations

import hashlib
import io
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
from evidrepo import redaction as red  # noqa: E402

from fixtures import PackageBuilder  # noqa: E402

WORK = "/workspace/runs/release-edge"
PASS, FAIL = [], []


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append((name, detail))
    print(("  [PASS] " if cond else "  [FAIL] ") + name
          + ((" — " + detail) if detail else ""))


def fresh():
    shutil.rmtree(WORK, ignore_errors=True)
    os.makedirs(os.path.join(WORK, "pkgs"))
    return dbmod.connect(os.path.join(WORK, "repo"))


def write_jsonl(path, records, raw_lines=None):
    with open(path, "wb") as f:
        if raw_lines is not None:
            for line in raw_lines:
                raw = line if isinstance(line, bytes) else line.encode("utf-8")
                f.write(raw)
                if not raw.endswith(b"\n"):
                    f.write(b"\n")
            return
        for r in records:
            f.write(json.dumps(r, ensure_ascii=False).encode("utf-8") + b"\n")


def header(aud="aud-E", rid="REQ-E", kind="request"):
    if kind == "request":
        return {"record_type": "release_header",
                "format_version": "release-request/v1",
                "request_id": rid, "audience": aud}
    return {"record_type": "rules_header",
            "format_version": "release-rules/v1",
            "rules_id": "RULES-E", "audience": aud}


def sel(t, v, code):
    return {"record_type": "representation_selection",
            "identifierType": t, "identifierValue": v,
            "external_code": code}


def rule(v, action, digest=None, ranges=None, t="local"):
    rec = {"record_type": "rule",
           "bitstream": {"identifierType": t, "identifierValue": v},
           "action": action}
    if digest:
        rec["content_sha256"] = digest
    if ranges:
        rec["ranges"] = ranges
    return rec


def seal_simple(conn, pkg_id, builder):
    builder.build()
    ingest.receive(conn, os.path.join(WORK, "repo"),
                   os.path.join(WORK, "pkgs", pkg_id))
    ingest.finish(conn, os.path.join(WORK, "repo"), pkg_id)


# --------------------------------------------------------------------------

def case_character_boundary_covered_range():
    print("\n[1] 字符边界：被 [1,4) 覆盖的 [2,3) 仍被发现")
    conn = fresh()
    data = "A馆B".encode("utf-8")  # E9 A6 86 位于偏移 1..4
    sha = hashlib.sha256(data).hexdigest()
    b = PackageBuilder(WORK + "/pkgs", "P1", trusted_ingest=("i1",))
    b.add_bitstream("B1", data)
    b.add_representation("R1", ["B1"], nodes=["n"])
    b.add_event("i1", "ingest", outputs=["B1"])
    seal_simple(conn, "P1", b)
    req = os.path.join(WORK, "req.jsonl")
    rul = os.path.join(WORK, "rul.jsonl")
    write_jsonl(req, [header(), sel("local", "R1", "EXT-1")])
    write_jsonl(rul, [header(kind="rules"),
                      rule("B1", "redact", sha, [[1, 4], [2, 3]])])
    plan, _ = release_plan.build_plan(conn, WORK + "/repo", req, rul)
    c = plan["contents"][0]
    check("被覆盖的非法区间仍使内容 blocked", c["blocked"] is True,
          str(c["reasons"]))
    check("原因码为区间不对齐",
          any("range_not_character_aligned" in r for r in c["reasons"]),
          str(c["reasons"]))
    rep = plan["representations"][0]
    check("对应表示不可交付", rep["decision"] == "held")
    try:
        release_publish.publish(conn, WORK + "/repo", plan["plan_id"],
                                WORK + "/out-x")
        check("blocked 计划禁止发布", False)
    except release_publish.PublishError as exc:
        check("blocked 计划禁止发布（%s）" % exc.code, exc.code in
              ("content_not_publishable", "no_deliverable"))
    conn.close()


def case_missing_rule_vs_syntax_error():
    print("\n[2] 缺规则=业务暂缓；语法错误=计划失败")
    conn = fresh()
    b = PackageBuilder(WORK + "/pkgs", "P1", trusted_ingest=("i1", "i2"))
    b.add_bitstream("B1", b"hello"); b.add_bitstream("B2", b"world")
    b.add_representation("R1", ["B1", "B2"], nodes=["n"])
    b.add_event("i1", "ingest", outputs=["B1"])
    b.add_event("i2", "ingest", outputs=["B2"])
    seal_simple(conn, "P1", b)
    req = os.path.join(WORK, "req.jsonl")
    rul = os.path.join(WORK, "rul.jsonl")
    write_jsonl(req, [header(), sel("local", "R1", "EXT-1")])
    # 只给 B1 规则；B2 缺规则（业务暂缓，计划仍生成）
    write_jsonl(rul, [header(kind="rules"), rule("B1", "release")])
    plan, _ = release_plan.build_plan(conn, WORK + "/repo", req, rul)
    check("缺规则时计划照常生成", plan is not None)
    check("缺规则内容决定为 held",
          all(c["decision"] == "held" for c in plan["contents"]
              if any("without_rule" in r for r in c["reasons"])))
    check("表示因内容暂缓而 held",
          plan["representations"][0]["decision"] == "held")
    # 语法错误：未知动作 -> 计划失败，不落库
    write_jsonl(rul, [header(kind="rules"), rule("B1", "vaporize")])
    before = len(release_plan.list_plans(conn))
    try:
        release_plan.build_plan(conn, WORK + "/repo", req, rul)
        check("未知动作拒绝（计划失败）", False)
    except ReleaseInputError as exc:
        check("未知动作拒绝（code=%s）" % exc.code,
              exc.code == "unknown_action")
    check("语法错误不留计划", len(release_plan.list_plans(conn)) == before)
    conn.close()


def case_input_validation_matrix():
    print("\n[3] 输入校验矩阵（重复/冲突/非法区间/代号/版本/BOM/JSON）")
    conn = fresh()
    b = PackageBuilder(WORK + "/pkgs", "P1", trusted_ingest=("i1",))
    b.add_bitstream("B1", b"abc"); b.add_representation("R1", ["B1"],
                                                          nodes=["n"])
    b.add_event("i1", "ingest", outputs=["B1"])
    seal_simple(conn, "P1", b)
    sha = hashlib.sha256(b"abc").hexdigest()
    req = os.path.join(WORK, "req.jsonl")
    rul = os.path.join(WORK, "rul.jsonl")

    def expect_fail(label, req_recs, rul_recs, code, raw_req=None, raw_rul=None):
        if raw_req is not None:
            write_jsonl(req, None, raw_lines=raw_req)
        else:
            write_jsonl(req, req_recs or [header(), sel("local", "R1", "EXT-1")])
        if raw_rul is not None:
            write_jsonl(rul, None, raw_lines=raw_rul)
        else:
            write_jsonl(rul, rul_recs or [header(kind="rules"),
                                          rule("B1", "release")])
        try:
            release_plan.build_plan(conn, WORK + "/repo", req, rul)
            check(label, False, "should have failed")
        except ReleaseInputError as exc:
            check(label, exc.code == code, "code=%s" % exc.code)

    expect_fail("重复外部代号",
                [header(), sel("local", "R1", "EXT-1"),
                 sel("local", "R1", "EXT-1")], None, "duplicate_selection")
    expect_fail("重复外部代号（不同表示同代号）",
                [header(), sel("local", "R1", "EXT-1"),
                 {"record_type": "representation_selection",
                  "identifierType": "local", "identifierValue": "R2",
                  "external_code": "EXT-1"}], None, "duplicate_external_code")
    expect_fail("代号含非 ASCII",
                [header(), sel("local", "R1", "EXT-馆")], None,
                "bad_external_code")
    expect_fail("代号非法首字符",
                [header(), sel("local", "R1", "-EXT")], None,
                "bad_external_code")
    expect_fail("冲突规则（同身份两条）", None,
                [header(kind="rules"), rule("B1", "release"),
                 rule("B1", "hold")], "duplicate_rule")
    expect_fail("空区间", None,
                [header(kind="rules"),
                 rule("B1", "redact", sha, [[2, 2]])], "bad_range")
    expect_fail("越界结构（负端点）", None,
                [header(kind="rules"),
                 rule("B1", "redact", sha, [[-1, 2]])], "bad_range")
    expect_fail("redact 缺绑定摘要", None,
                [header(kind="rules"),
                 {"record_type": "rule",
                  "bitstream": {"identifierType": "local",
                                "identifierValue": "B1"},
                  "action": "redact", "ranges": [[0, 1]]}],
                "bad_bound_digest")
    expect_fail("release 携带 ranges", None,
                [header(kind="rules"),
                 {"record_type": "rule",
                  "bitstream": {"identifierType": "local",
                                "identifierValue": "B1"},
                  "action": "release", "ranges": [[0, 1]]}],
                "bad_rule_fields")
    expect_fail("坏请求版本", None, None, "bad_format_version",
                raw_req=[json.dumps({
                    "record_type": "release_header",
                    "format_version": "release-request/v9",
                    "request_id": "x", "audience": "aud-E"})])
    expect_fail("BOM 拒绝", None, None, "bad_encoding",
                raw_req=[b"\xef\xbb\xbf" + json.dumps(header()).encode()])
    expect_fail("坏 JSON 拒绝", None, None, "bad_json",
                raw_req=[b"{not json"])
    expect_fail("受众不一致", None,
                [{"record_type": "rules_header",
                  "format_version": "release-rules/v1",
                  "rules_id": "r", "audience": "other-aud"},
                 rule("B1", "release")], "audience_mismatch")
    conn.close()


def case_bound_digest_mismatch_and_non_utf8():
    print("\n[4/5] 绑定摘要不符 / 非 UTF-8 原件 => blocked 且可定位")
    conn = fresh()
    b = PackageBuilder(WORK + "/pkgs", "P1", trusted_ingest=("i1", "i2"))
    b.add_bitstream("B1", b"abc")
    b.add_bitstream("B2", b"\xff\xfe\x00not-utf8")
    b.add_representation("R1", ["B1"], nodes=["n1"])
    b.add_representation("R2", ["B2"], nodes=["n2"])
    b.add_event("i1", "ingest", outputs=["B1"])
    b.add_event("i2", "ingest", outputs=["B2"])
    seal_simple(conn, "P1", b)
    req = os.path.join(WORK, "req.jsonl")
    rul = os.path.join(WORK, "rul.jsonl")
    write_jsonl(req, [header(), sel("local", "R1", "EXT-1"),
                      sel("local", "R2", "EXT-2")])
    fake_sha = "0" * 64
    write_jsonl(rul, [
        header(kind="rules"),
        rule("B1", "redact", fake_sha, [[0, 1]]),
        rule("B2", "redact", hashlib.sha256(b"\xff\xfe\x00not-utf8")
             .hexdigest(), [[0, 1]]),
    ])
    plan, _ = release_plan.build_plan(conn, WORK + "/repo", req, rul)
    by_rep = {r["external_code"]: r for r in plan["representations"]}
    check("两个表示都不可交付",
          all(r["decision"] == "held" for r in by_rep.values()))
    reasons = " ".join(x for c in plan["contents"] for x in c["reasons"])
    check("含绑定摘要不符原因", "bound_digest_mismatch" in reasons, reasons)
    check("含非 UTF-8 原因", "not_valid_utf8" in reasons, reasons)
    try:
        release_publish.publish(conn, WORK + "/repo", plan["plan_id"],
                                WORK + "/out-blocked")
        check("全部 blocked 时发布被拒", False)
    except release_publish.PublishError as exc:
        check("全部 blocked 时发布被拒（%s）" % exc.code, True)
    check("正式路径未出现", not os.path.exists(WORK + "/out-blocked"))
    conn.close()


def case_source_tamper_and_concurrent_seal_and_interrupt():
    print("\n[6/7/8] 源字节变更 / 并发封存 / 发布中断")
    conn = fresh()
    data = "A馆B".encode("utf-8")
    sha = hashlib.sha256(data).hexdigest()
    b = PackageBuilder(WORK + "/pkgs", "P1", trusted_ingest=("i1",))
    b.add_bitstream("B1", data)
    b.add_representation("R1", ["B1"], nodes=["n"])
    b.add_event("i1", "ingest", outputs=["B1"])
    seal_simple(conn, "P1", b)
    req = os.path.join(WORK, "req.jsonl")
    rul = os.path.join(WORK, "rul.jsonl")
    write_jsonl(req, [header(), sel("local", "R1", "EXT-1")])
    write_jsonl(rul, [header(kind="rules"),
                      rule("B1", "redact", sha, [[0, 1]])])
    plan, _ = release_plan.build_plan(conn, WORK + "/repo", req, rul)

    # 6. 篡改封存文件（保留长度，改一个字节）
    blob_row = conn.execute(
        "SELECT stored_path FROM blobs WHERE state='bytes_ok' LIMIT 1"
    ).fetchone()
    blob_abs = os.path.join(WORK + "/repo", blob_row["stored_path"])
    with open(blob_abs, "r+b") as f:
        f.seek(4)
        f.write(b"X")
    target = os.path.join(WORK, "out-tamper")
    try:
        release_publish.publish(conn, WORK + "/repo", plan["plan_id"], target)
        check("篡改后发布失败", False)
    except red.RedactionError as exc:
        check("篡改触发 SHA-256 不符（%s）" % exc.code,
              exc.code == "digest_mismatch")
    check("失败后正式路径不存在", not os.path.exists(target))
    check("失败后无 staging 残留",
          not any(x.startswith("out-tamper.stage-")
                  for x in os.listdir(WORK)))
    # 还原，供后续场景
    with open(blob_abs, "r+b") as f:
        f.seek(4)
        f.write(b"B")

    # 7. 并发封存：发布期间 finish 一个新包 -> 包集合变化 -> 拒绝
    b2 = PackageBuilder(WORK + "/pkgs", "P2", trusted_ingest=("i2",))
    b2.add_bitstream("B9", b"other")
    b2.add_event("i2", "ingest", outputs=["B9"])
    b2.build()
    ingest.receive(conn, WORK + "/repo", WORK + "/pkgs/P2")
    # 在 _build_payloads 之前注入“恰好封存”：直接先 finish，再尝试旧计划
    ingest.finish(conn, WORK + "/repo", "P2")
    target2 = os.path.join(WORK, "out-concurrent")
    try:
        release_publish.publish(conn, WORK + "/repo", plan["plan_id"], target2)
        check("交付前封存 => 旧计划拒绝", False)
    except release_publish.PublishError as exc:
        check("交付前封存 => 旧计划拒绝（%s）" % exc.code,
              exc.code == "stale_plan")
    check("并发场景正式路径不存在", not os.path.exists(target2))

    # 8. 发布中断：monkey-patch os.rename 抛错，断言无半成品
    conn2 = dbmod.connect(WORK + "/repo")
    plan2, _ = release_plan.build_plan(conn2, WORK + "/repo", req, rul)
    target3 = os.path.join(WORK, "out-interrupt")
    real_rename = os.rename
    def boom(src, dst):
        if os.path.basename(dst) == os.path.basename(target3):
            raise OSError("simulated crash before final rename")
        return real_rename(src, dst)
    os.rename = boom
    try:
        try:
            release_publish.publish(conn2, WORK + "/repo",
                                    plan2["plan_id"], target3)
            check("中断时发布抛错", False)
        except OSError:
            check("中断时发布抛错", True)
    finally:
        os.rename = real_rename
    check("中断后正式路径不存在", not os.path.exists(target3))
    check("中断后无 staging 残留",
          not any(x.startswith("out-interrupt.stage-")
                  for x in os.listdir(WORK)))
    # 重跑成功（可重入）
    d = release_publish.publish(conn2, WORK + "/repo",
                                plan2["plan_id"], target3)
    check("中断后重跑成功", verify_release.verify_release(target3)["ok"])
    conn2.close()
    conn.close()


def case_moved_dir_attacks():
    print("\n[9] 移动后注入：多余文件/符号链接/缺文件/摘要错误 全拒绝")
    conn = fresh()
    data = b"plain-bytes"
    b = PackageBuilder(WORK + "/pkgs", "P1", trusted_ingest=("i1",))
    b.add_bitstream("B1", data)
    b.add_representation("R1", ["B1"], nodes=["n"])
    b.add_event("i1", "ingest", outputs=["B1"])
    seal_simple(conn, "P1", b)
    req = os.path.join(WORK, "req.jsonl")
    rul = os.path.join(WORK, "rul.jsonl")
    write_jsonl(req, [header(), sel("local", "R1", "EXT-1")])
    write_jsonl(rul, [header(kind="rules"), rule("B1", "release")])
    plan, _ = release_plan.build_plan(conn, WORK + "/repo", req, rul)
    target = os.path.join(WORK, "moved-delivery")
    release_publish.publish(conn, WORK + "/repo", plan["plan_id"], target)
    assert verify_release.verify_release(target)["ok"]
    payload = os.path.join(target, "payloads")
    fname = os.listdir(payload)[0]

    # 多余文件
    with open(os.path.join(payload, "extra.bin"), "wb") as f:
        f.write(b"x")
    r = verify_release.verify_release(target)
    check("多余 payload 文件被拒", not r["ok"]
          and any("not controlled" in e for e in r["errors"]))
    os.remove(os.path.join(payload, "extra.bin"))

    # 根目录多余文件
    with open(os.path.join(target, "leak.txt"), "wb") as f:
        f.write(b"internal notes")
    r = verify_release.verify_release(target)
    check("根目录多余文件被拒", not r["ok"]
          and any("unexpected" in e for e in r["errors"]))
    os.remove(os.path.join(target, "leak.txt"))

    # 符号链接
    link = os.path.join(payload, "link.bin")
    os.symlink(fname, link)
    r = verify_release.verify_release(target)
    check("符号链接被拒", not r["ok"]
          and any("symlink" in e for e in r["errors"]))
    os.remove(link)

    # 缺文件（改清单删掉 files 项但保留引用 -> 引用错误；直接删磁盘文件）
    os.remove(os.path.join(payload, fname))
    r = verify_release.verify_release(target)
    check("缺文件被拒", not r["ok"]
          and any("differs from manifest" in e or "missing" in e
                  for e in r["errors"]))
    # 恢复后再制造摘要错误
    with open(os.path.join(payload, fname), "wb") as f:
        f.write(data)
    mp = os.path.join(target, "release-manifest.json")
    with open(mp, encoding="utf-8") as f:
        m = json.load(f)
    m["files"][0]["sha256"] = "f" * 64
    with open(mp, "w", encoding="utf-8") as f:
        json.dump(m, f)
    r = verify_release.verify_release(target)
    check("摘要错误被拒", not r["ok"]
          and any("sha256 mismatch" in e for e in r["errors"]))
    conn.close()


def case_cross_pkg_and_type_and_conflict():
    print("\n[10] 跨包重复声明 / 同 value 不同 type / 身份冲突")
    conn = fresh()
    b1 = PackageBuilder(WORK + "/pkgs", "P1", trusted_ingest=("i1",))
    b1.add_bitstream("B1", b"same-content")
    b1.add_representation("RR", ["B1"], nodes=["n"])
    b1.add_event("i1", "ingest", outputs=["B1"])
    b1.build()
    ingest.receive(conn, WORK + "/repo", WORK + "/pkgs/P1")
    ingest.finish(conn, WORK + "/repo", "P1")
    # P2：同一表示身份 RR、完全相同成员集合（跨包重复声明，合法合并）
    b2 = PackageBuilder(WORK + "/pkgs", "P2")
    b2.add_ref_only("B1")
    b2.add_representation("RR", ["B1"])
    b2.build()
    ingest.receive(conn, WORK + "/repo", WORK + "/pkgs/P2")
    ingest.finish(conn, WORK + "/repo", "P2")
    req = os.path.join(WORK, "req.jsonl")
    rul = os.path.join(WORK, "rul.jsonl")
    write_jsonl(req, [header(), sel("local", "RR", "EXT-1")])
    write_jsonl(rul, [header(kind="rules"), rule("B1", "release")])
    plan, _ = release_plan.build_plan(conn, WORK + "/repo", req, rul)
    rep = plan["representations"][0]
    check("跨包相同成员集合合并、可交付",
          rep["decision"] == "deliverable" and not rep["member_set_conflict"])

    # 相同 value、不同 type 是两个独立身份；后者缺规则 => 内容视角不合并，
    # 但同一表示若同时引用两者，缺规则者按内容暂缓处理。
    b3 = PackageBuilder(WORK + "/pkgs", "P3", trusted_ingest=("i3",))
    b3.add_bitstream("B1", b"other-type-content", id_type="doi")
    b3.add_representation("RT", [("doi", "B1")], id_type="local")
    b3.add_event("i3", "ingest", outputs=[("doi", "B1")])
    b3.build()
    ingest.receive(conn, WORK + "/repo", WORK + "/pkgs/P3")
    ingest.finish(conn, WORK + "/repo", "P3")
    write_jsonl(req, [header(), sel("local", "RT", "EXT-2")])
    plan2, _ = release_plan.build_plan(conn, WORK + "/repo", req, rul)
    rep2 = next(r for r in plan2["representations"]
                if r["external_code"] == "EXT-2")
    check("同 value 不同 type 独立：doi/B1 缺规则 => 暂缓",
          rep2["decision"] == "held"
          and any("without_rule" in x for c in plan2["contents"]
                  for x in c["reasons"]))

    # 身份冲突：local/B1 在 P4 被不同字节占用
    b4 = PackageBuilder(WORK + "/pkgs", "P4", trusted_ingest=("i4",))
    b4.add_bitstream("B1", b"different-bytes-conflict")
    b4.add_event("i4", "ingest", outputs=["B1"])
    b4.build()
    ingest.receive(conn, WORK + "/repo", WORK + "/pkgs/P4")
    ingest.finish(conn, WORK + "/repo", "P4")
    write_jsonl(req, [header(), sel("local", "RR", "EXT-3")])
    write_jsonl(rul, [header(kind="rules"), rule("B1", "release")])
    plan3, _ = release_plan.build_plan(conn, WORK + "/repo", req, rul)
    rep3 = plan3["representations"][0]
    member_problem = any(
        "member_identity_conflict" in c["reasons"]
        for c in rep3["member_checks"]
    )
    check("身份冲突成员使表示暂缓",
          rep3["decision"] == "held" and member_problem,
          str(rep3["reasons"]))
    conn.close()


def case_no_internal_leak_in_manifest():
    print("\n[11/12] 受控文件名与公开清单无馆内泄漏")
    conn = fresh()
    b = PackageBuilder(WORK + "/pkgs", "P1", trusted_ingest=("i1",))
    b.add_bitstream("SECRETID", b"data-x")
    b.add_representation("REPSECRET", ["SECRETID"], nodes=["n"])
    b.add_event("i1", "ingest", outputs=["SECRETID"])
    seal_simple(conn, "P1", b)
    req = os.path.join(WORK, "req.jsonl")
    rul = os.path.join(WORK, "rul.jsonl")
    write_jsonl(req, [header(), sel("local", "REPSECRET", "EXT-PUB-1")])
    write_jsonl(rul, [header(kind="rules"), rule("SECRETID", "release")])
    plan, _ = release_plan.build_plan(conn, WORK + "/repo", req, rul)
    target = os.path.join(WORK, "out-leak")
    release_publish.publish(conn, WORK + "/repo", plan["plan_id"], target)
    raw = open(os.path.join(target, "release-manifest.json"), "rb").read()
    text = raw.decode("utf-8")
    for needle in ("SECRETID", "REPSECRET", "store/", "content/",
                   "package", "P1", "rule", "reason", "plan_id",
                   "identifierType"):
        check("清单不含 %r" % needle, needle not in text)
    # 文件名不得取自原件摘要（清单的 sha256 字段记录交付字节摘要，
    # 放行时自然等于原件摘要，这是公开格式允许的）
    orig_sha = hashlib.sha256(b"data-x").hexdigest()
    names = [f["file"] for f in json.loads(
        open(os.path.join(target, "release-manifest.json"),
             encoding="utf-8").read())["files"]]
    check("生成文件名不含原件摘要/身份",
          all(orig_sha not in n and "SECRET" not in n for n in names),
          str(names))
    r = verify_release.verify_release(target)
    check("目录离线自校验通过", r["ok"], str(r["errors"]))
    conn.close()


def case_alias_without_rule_holds_whole_content():
    print("\n[附] 未选表示别名缺规则 => 整份内容暂缓（按内容统一落实）")
    conn = fresh()
    data = b"same-bytes-for-two"
    b = PackageBuilder(WORK + "/pkgs", "P1", trusted_ingest=("i1",))
    b.add_bitstream("BS-SEL", data)
    b.add_bitstream("BS-ALIAS", data)  # 相同字节、不同身份、未选表示
    b.add_representation("RSEL", ["BS-SEL"], nodes=["n"])
    b.add_representation("RALIAS", ["BS-ALIAS"], nodes=["m"])
    b.add_event("i1", "ingest", outputs=["BS-SEL", "BS-ALIAS"])
    seal_simple(conn, "P1", b)
    req = os.path.join(WORK, "req.jsonl")
    rul = os.path.join(WORK, "rul.jsonl")
    write_jsonl(req, [header(), sel("local", "RSEL", "EXT-1")])
    # 只给被选身份规则；别名缺规则
    write_jsonl(rul, [header(kind="rules"), rule("BS-SEL", "release")])
    plan, _ = release_plan.build_plan(conn, WORK + "/repo", req, rul)
    c = next(c for c in plan["contents"])
    check("两个身份都进入内容视角",
          sorted(a["identifierValue"] for a in c["aliases"])
          == ["BS-ALIAS", "BS-SEL"])
    check("别名缺规则 => 内容 held", c["decision"] == "held")
    check("原因可定位到缺规则身份",
          any("BS-ALIAS" in r and "without_rule" in r for r in c["reasons"]))
    check("被选表示因此不可对外列出",
          plan["representations"][0]["decision"] == "held")
    conn.close()


def main():
    case_character_boundary_covered_range()
    case_missing_rule_vs_syntax_error()
    case_input_validation_matrix()
    case_bound_digest_mismatch_and_non_utf8()
    case_source_tamper_and_concurrent_seal_and_interrupt()
    case_moved_dir_attacks()
    case_cross_pkg_and_type_and_conflict()
    case_no_internal_leak_in_manifest()
    case_alias_without_rule_holds_whole_content()
    print("\n==== 离线发布边界演练：%d PASS / %d FAIL ===="
          % (len(PASS), len(FAIL)))
    for name, detail in FAIL:
        print("  FAIL:", name, detail)
    if FAIL:
        sys.exit(1)


if __name__ == "__main__":
    main()
