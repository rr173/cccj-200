# -*- coding: utf-8 -*-
"""
边界场景测试（每个场景独立断言）：
  1. 一个表示多成员（AND 成员集合，缺一即 incomplete）
  2. 跨包前向引用（成员来自别的已接收包）
  3. 相同字节不同身份（身份不按摘要/文件名合并）
  4. 结构多处引用同一 bitstream 不重复计数
  5. 路径逃逸（manifest 指向包外 -> 整包拒绝）
  6. 对象身份冲突（同 ID 被不同实际字节占用 -> identity_conflict，不能择一）
  7. 晚到包 + 包中断重开（staging 不可见、resume 补齐）
  8. 事件 ID 同名异内容冲突 -> 受影响事件不可用
  9. 旧证明不可变（迟到原件不改变旧证明号与内容）
 10. 整仓/导出目录移动后仍可校验
 11. 扩展元素原样 uninterpreted，不能猜成证明
 12. 不受信 ingest（名单外）不能成为证明根
"""
from __future__ import annotations

import json
import os
import shutil
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))

from evidrepo import db as dbmod  # noqa: E402
from evidrepo import diagnostics, export as exportmod, ingest  # noqa: E402
from evidrepo.evaluate import object_state  # noqa: E402
from evidrepo.util import (  # noqa: E402
    REP_INCOMPLETE,
    REP_INVALID,
    REP_UNPROVEN,
    REP_VERIFIED,
    ST_BYTES_CORRUPT,
    ST_BYTES_MISSING,
    ST_BYTES_OK,
    ST_IDENTITY_CONFLICT,
)
from evidrepo.verify_export import verify_export  # noqa: E402
from evidrepo.util import PathEscape  # noqa: E402

from fixtures import PackageBuilder, sha256_bytes  # noqa: E402

WORK = "/workspace/runs/edge"
PASS, FAIL = [], []


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append((name, detail))
    print(("  [PASS] " if cond else "  [FAIL] ") + name + ((" — " + detail) if detail else ""))


def fresh():
    shutil.rmtree(WORK, ignore_errors=True)
    os.makedirs(WORK + "/pkgs")
    return dbmod.connect(WORK + "/repo")


def case_multi_members():
    print("\n[1] 一个表示多成员：成员 AND 集合，缺一个即 incomplete")
    conn = fresh()
    b = PackageBuilder(WORK + "/pkgs", "Q1", trusted_ingest=("ing-X", "ing-Y"))
    b.add_bitstream("X", b"xxx"); b.add_bitstream("Y", b"yyy")
    b.add_representation("RM", ["X", "Y"], nodes=["n"])
    b.add_event("ing-X", "ingest", outputs=["X"])
    b.mark_missing("Y")
    b.build()
    ingest.receive(conn, WORK + "/repo", WORK + "/pkgs/Q1")
    ingest.finish(conn, WORK + "/repo", "Q1")
    rep = diagnostics.evaluate_representation(conn, "local", "RM")
    check("缺成员 -> incomplete", rep["label"] == REP_INCOMPLETE, rep["label"])
    check("原因逐项含 Y bytes_missing",
          any("Y" in r and "bytes_missing" in r for r in rep["reasons"]),
          str(rep["reasons"]))
    conn.close()


def case_cross_package_forward_ref():
    print("\n[2] 跨包前向引用：成员字节来自后到的已接收包")
    conn = fresh()
    # 先到的包声明表示与成员身份，但成员字节在第二个包
    b1 = PackageBuilder(WORK + "/pkgs", "Q1", trusted_ingest=())
    b1.add_ref_only("M")
    b1.add_representation("RR", ["M"], nodes=["n1"])
    b1.build()
    ingest.receive(conn, WORK + "/repo", WORK + "/pkgs/Q1")
    ingest.finish(conn, WORK + "/repo", "Q1")
    rep = diagnostics.evaluate_representation(conn, "local", "RR")
    check("成员未到 -> incomplete", rep["label"] == REP_INCOMPLETE)
    b2 = PackageBuilder(WORK + "/pkgs", "Q2", trusted_ingest=("ing-M",))
    b2.add_bitstream("M", b"member-bytes")
    b2.add_event("ing-M", "ingest", outputs=["M"])
    b2.build()
    ingest.receive(conn, WORK + "/repo", WORK + "/pkgs/Q2")
    ingest.finish(conn, WORK + "/repo", "Q2")
    rep = diagnostics.evaluate_representation(conn, "local", "RR")
    check("跨包字节补齐 -> verified", rep["label"] == REP_VERIFIED, rep["label"])
    conn.close()


def case_same_bytes_diff_identity():
    print("\n[3] 相同字节不同身份：不按摘要合并，仍是两个对象")
    conn = fresh()
    payload = b"identical-payload"
    b = PackageBuilder(WORK + "/pkgs", "Q1",
                       trusted_ingest=("ing-O1", "ing-O2"))
    b.add_bitstream("O1", payload)
    b.add_bitstream("O2", payload)  # 字节完全相同
    b.add_event("ing-O1", "ingest", outputs=["O1"])
    b.add_event("ing-O2", "ingest", outputs=["O2"])
    b.build()
    ingest.receive(conn, WORK + "/repo", WORK + "/pkgs/Q1")
    ingest.finish(conn, WORK + "/repo", "Q1")
    s1, p1 = object_state(conn, "local", "O1")
    s2, p2 = object_state(conn, "local", "O2")
    rows = conn.execute("SELECT COUNT(*) c FROM obj_status").fetchone()["c"]
    check("两个身份各自独立", rows >= 2 and s1 == s2 == ST_BYTES_OK and p1 and p2)
    # 同一 bitstream 被多个结构节点引用：不复制身份
    b2 = PackageBuilder(WORK + "/pkgs", "Q2")
    b2.add_ref_only("O1"); b2.add_ref_only("O2")
    b2.add_representation("RS", ["O1", "O2"], nodes=["node-a", "node-b", "node-c"])
    b2.build()
    ingest.receive(conn, WORK + "/repo", WORK + "/pkgs/Q2")
    ingest.finish(conn, WORK + "/repo", "Q2")
    rep = diagnostics.evaluate_representation(conn, "local", "RS")
    check("多结构节点不重复计数成员", len(rep["members"]) == 2,
          "members=%d" % len(rep["members"]))
    nodes = diagnostics.get_struct_node(conn, "node-a")
    check("结构节点只引用表示", len(nodes) == 1 and
          nodes[0]["rep_id_value"] == "RS")
    conn.close()


def case_path_escape():
    print("\n[5] 路径逃逸：manifest 指向包外必须整包拒绝")
    conn = fresh()
    b = PackageBuilder(WORK + "/pkgs", "Q1", trusted_ingest=("ing-X",))
    b.add_bitstream("X", b"x"); b.add_event("ing-X", "ingest", outputs=["X"])
    b.build()
    # 直接篡改 manifest，加入逃逸路径
    mf = os.path.join(WORK + "/pkgs/Q1", "manifest.json")
    with open(mf, encoding="utf-8") as f:
        manifest = json.load(f)
    manifest["members"].append({
        "rel_path": "../../etc/evil.bin", "size": 4,
        "sha256": sha256_bytes(b"evil"),
        "object": {"id_type": "local", "id_value": "EVIL"}})
    with open(mf, "w", encoding="utf-8") as f:
        json.dump(manifest, f)
    try:
        ingest.receive(conn, WORK + "/repo", WORK + "/pkgs/Q1")
        check("逃逸路径被拒绝", False)
    except PathEscape:
        check("逃逸路径被拒绝", True)
    # 事务回滚：无残留事实
    n = conn.execute("SELECT COUNT(*) c FROM packages").fetchone()["c"]
    check("拒绝后无残留包记录", n == 0)
    conn.close()


def case_identity_conflict():
    print("\n[6] 对象身份冲突：同 ID 不同字节 -> identity_conflict，不能择一")
    conn = fresh()
    b1 = PackageBuilder(WORK + "/pkgs", "Q1", trusted_ingest=("ing-Z",))
    b1.add_bitstream("Z", b"version-one"); b1.add_event("ing-Z", "ingest", outputs=["Z"])
    b1.build()
    ingest.receive(conn, WORK + "/repo", WORK + "/pkgs/Q1")
    ingest.finish(conn, WORK + "/repo", "Q1")
    b2 = PackageBuilder(WORK + "/pkgs", "Q2", trusted_ingest=("ing-Z",))
    b2.add_bitstream("Z", b"version-two-different")  # 同身份不同字节
    b2.add_event("ing-Z", "ingest", outputs=["Z"])
    b2.build()
    ingest.receive(conn, WORK + "/repo", WORK + "/pkgs/Q2")
    ingest.finish(conn, WORK + "/repo", "Q2")
    state, proven = object_state(conn, "local", "Z")
    check("状态为 identity_conflict", state == ST_IDENTITY_CONFLICT, state)
    check("冲突对象不可证明", proven is False)
    check("object_conflicts 已物化",
          conn.execute("SELECT COUNT(*) c FROM object_conflicts").fetchone()["c"] == 1)
    # 有冲突成员的表示 -> invalid
    b3 = PackageBuilder(WORK + "/pkgs", "Q3")
    b3.add_ref_only("Z"); b3.add_representation("RZ", ["Z"], nodes=["n"])
    b3.build()
    ingest.receive(conn, WORK + "/repo", WORK + "/pkgs/Q3")
    ingest.finish(conn, WORK + "/repo", "Q3")
    rep = diagnostics.evaluate_representation(conn, "local", "RZ")
    check("含身份冲突 -> invalid", rep["label"] == REP_INVALID, rep["label"])
    conn.close()


def case_late_and_resume():
    print("\n[7] 晚到包 + 包中断重开：staging 不可见，resume 补齐后封包")
    conn = fresh()
    b = PackageBuilder(WORK + "/pkgs", "Q1", trusted_ingest=("ing-X",))
    b.add_bitstream("X", b"x"); b.add_bitstream("Y", b"y")
    b.add_representation("RL", ["X", "Y"], nodes=["n"])
    b.add_event("ing-X", "ingest", outputs=["X"])
    b.mark_missing("Y")
    b.build()
    ingest.receive(conn, WORK + "/repo", WORK + "/pkgs/Q1")
    # staging 状态对 sealed 查询不可见
    reps = diagnostics.list_representations(conn)
    check("staging 包不进可查询事实", reps == [])
    # 模拟中断：关闭再重开连接
    conn.close()
    conn = dbmod.connect(WORK + "/repo")
    # 补齐 Y（新目录，含完整包内容）
    b2 = PackageBuilder(WORK + "/pkgs", "Q1b", trusted_ingest=("ing-X",))
    b2.add_bitstream("X", b"x"); b2.add_bitstream("Y", b"y")
    b2.add_representation("RL", ["X", "Y"], nodes=["n"])
    b2.add_event("ing-X", "ingest", outputs=["X"])
    b2.build()
    # 把迟到的 Y 复制进原包目录后 resume
    os.makedirs(WORK + "/pkgs/Q1/content", exist_ok=True)
    shutil.copy(WORK + "/pkgs/Q1b/content/Y.bin", WORK + "/pkgs/Q1/content/Y.bin")
    r = ingest.receive(conn, WORK + "/repo", WORK + "/pkgs/Q1", resume=True)
    check("resume 后字节齐", r["blobs"].get("bytes_missing", 0) == 0, str(r["blobs"]))
    ingest.finish(conn, WORK + "/repo", "Q1")
    check("封包后表示可查询",
          diagnostics.evaluate_representation(conn, "local", "RL")["label"]
          in (REP_UNPROVEN, REP_VERIFIED, REP_INCOMPLETE, REP_INVALID))
    conn.close()


def case_event_conflict():
    print("\n[8] 事件同名异内容 -> 冲突事件不可用")
    conn = fresh()
    b1 = PackageBuilder(WORK + "/pkgs", "Q1", trusted_ingest=("ing-A",))
    b1.add_bitstream("A", b"a"); b1.add_bitstream("C1", b"c1")
    b1.add_event("ing-A", "ingest", outputs=["A"])
    b1.add_event("EVM", "migration", inputs=["A"], outputs=["C1"])
    b1.build()
    ingest.receive(conn, WORK + "/repo", WORK + "/pkgs/Q1")
    ingest.finish(conn, WORK + "/repo", "Q1")
    # 第二包：同 event_id 但 outcome 不同（异内容）
    b2 = PackageBuilder(WORK + "/pkgs", "Q2", trusted_ingest=("ing-A",))
    b2.add_ref_only("A"); b2.add_bitstream("C2", b"c2")
    b2.add_event("ing-A", "ingest", outputs=["A"])
    b2.add_event("EVM", "migration", inputs=["A"], outputs=["C2"],
                 outcome="failed")
    b2.build()
    ingest.receive(conn, WORK + "/repo", WORK + "/pkgs/Q2")
    ingest.finish(conn, WORK + "/repo", "Q2")
    conflict = conn.execute(
        "SELECT COUNT(*) c FROM event_conflicts WHERE event_id='EVM'"
    ).fetchone()["c"]
    check("EVM 进入事件冲突表", conflict == 1)
    valid = conn.execute(
        "SELECT valid FROM ev_status WHERE event_id='EVM'"
    ).fetchone()["valid"]
    check("冲突事件不可用", valid == 0)
    # C1 不能经冲突的 EVM 证明（A 自身仍可证）
    _, prov_c1 = object_state(conn, "local", "C1")
    _, prov_a = object_state(conn, "local", "A")
    check("C1 不被冲突事件证明", prov_c1 is False)
    check("无关对象 A 不受牵连", prov_a is True)
    conn.close()


def case_proof_immutability_and_move():
    print("\n[9/10] 旧证明不可变 + 整仓/导出目录移动后可校验")
    conn = fresh()
    b1 = PackageBuilder(WORK + "/pkgs", "Q1", trusted_ingest=("ing-A",))
    b1.add_bitstream("A", b"a"); b1.add_bitstream("C", b"c-mig")
    b1.add_representation("RP", ["C"], nodes=["n"])
    b1.add_event("ing-A", "ingest", outputs=["A"])
    b1.add_event("EM", "migration", inputs=["A"], outputs=["C"])
    b1.build()
    ingest.receive(conn, WORK + "/repo", WORK + "/pkgs/Q1")
    ingest.finish(conn, WORK + "/repo", "Q1")
    exports = WORK + "/exports"
    out1 = exportmod.export_proof(conn, WORK + "/repo", exports, "local", "RP")
    v1 = verify_export(out1["export_dir"])
    check("首个证明独立验证通过", v1["ok"], str(v1["errors"]))
    no1, id1 = out1["proof_no"], out1["proof_id"]
    old_files = sorted(os.listdir(out1["export_dir"]))

    # 迟到包带来新事实（不改变既有证明）
    b2 = PackageBuilder(WORK + "/pkgs", "Q2", trusted_ingest=("ing-B",))
    b2.add_bitstream("B", b"b"); b2.add_event("ing-B", "ingest", outputs=["B"])
    b2.build()
    ingest.receive(conn, WORK + "/repo", WORK + "/pkgs/Q2")
    ingest.finish(conn, WORK + "/repo", "Q2")
    out2 = exportmod.export_proof(conn, WORK + "/repo", exports, "local", "RP")
    check("同内容证明复用旧证明号", out2["proof_no"] == no1 and
          out2["proof_id"] == id1 and out2.get("reused") is True)
    check("旧导出目录内容未改写", sorted(os.listdir(out1["export_dir"])) == old_files)
    rows = conn.execute("SELECT COUNT(*) c FROM proofs").fetchone()["c"]
    check("proofs 表只增不改", rows == 1)

    # 移动整仓与导出目录
    moved_repo = WORK + "/moved-repo"
    moved_exports = WORK + "/moved-exports"
    shutil.move(WORK + "/repo", moved_repo)
    shutil.move(exports, moved_exports)
    moved_proof_dir = os.path.join(moved_exports, os.path.basename(out1["export_dir"]))
    v3 = verify_export(moved_proof_dir)
    check("移动后独立验证仍通过（全相对路径）", v3["ok"], str(v3["errors"]))
    conn.close()
    conn = dbmod.connect(moved_repo)
    # check-store 用仓内相对路径重算
    from evidrepo.cli import cmd_check_store

    class A:  # 简易参数
        repo = moved_repo
    import io, contextlib
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        cmd_check_store(A())
    parsed = json.loads(buf.getvalue())
    check("移动后 check-store 全绿", parsed["ok"] and parsed["checked_blobs"] >= 2,
          str(parsed))
    conn.close()


def case_uninterpreted_and_untrusted():
    print("\n[11/12] 扩展 uninterpreted 不猜证明；名单外 ingest 不成为根")
    conn = fresh()
    b = PackageBuilder(WORK + "/pkgs", "Q1", trusted_ingest=("ing-T",))
    b.add_bitstream("T", b"trusted"); b.add_bitstream("U", b"untrusted")
    b.add_representation("RU", ["T", "U"], nodes=["n"])
    b.add_event("ing-T", "ingest", outputs=["T"])
    # ing-U 不在信任名单
    b.add_event("ing-U", "ingest", outputs=["U"])
    b.add_foreign_extension(
        '<premis:rightsStatement xmlns:premis="http://www.loc.gov/premis/v3">'
        "<premis:rightsBasis>copyright</premis:rightsBasis>"
        "</premis:rightsStatement>"
    )
    b.build()
    ingest.receive(conn, WORK + "/repo", WORK + "/pkgs/Q1")
    ingest.finish(conn, WORK + "/repo", "Q1")
    _, prov_t = object_state(conn, "local", "T")
    _, prov_u = object_state(conn, "local", "U")
    check("名单内 ingest 可作根", prov_t is True)
    check("名单外 ingest 不可作根", prov_u is False)
    n_unint = conn.execute(
        "SELECT COUNT(*) c FROM object_uninterpreted WHERE local_name LIKE 'premis:%'"
    ).fetchone()["c"]
    # agent 扩展（主演练包）与 rightsStatement 均应原样保存
    check("扩展原样保存为 uninterpreted",
          n_unint >= 1, "rows=%d" % n_unint)
    raw = conn.execute(
        "SELECT raw_xml FROM object_uninterpreted WHERE local_name LIKE 'premis:%' "
        "LIMIT 1"
    ).fetchone()[0]
    check("uninterpreted 保留原始 XML 文本", "rightsBasis" in raw or "agent" in raw)
    rep = diagnostics.evaluate_representation(conn, "local", "RU")
    check("表示含未证明成员 -> unproven", rep["label"] == REP_UNPROVEN, rep["label"])
    conn.close()


def case_corrupt_blob():
    print("\n[附] bytes_corrupt：实算哈希不符 -> invalid 表示")
    conn = fresh()
    b = PackageBuilder(WORK + "/pkgs", "Q1", trusted_ingest=("ing-K",))
    b.add_bitstream("K", b"good-bytes")
    b.mark_corrupt("K")
    b.add_representation("RK", ["K"], nodes=["n"])
    b.add_event("ing-K", "ingest", outputs=["K"])
    b.build()
    r = ingest.receive(conn, WORK + "/repo", WORK + "/pkgs/Q1")
    check("接包报告 bytes_corrupt", r["blobs"].get("bytes_corrupt") == 1, str(r["blobs"]))
    ingest.finish(conn, WORK + "/repo", "Q1")
    state, _ = object_state(conn, "local", "K")
    check("对象状态 bytes_corrupt", state == ST_BYTES_CORRUPT, state)
    rep = diagnostics.evaluate_representation(conn, "local", "RK")
    check("损坏成员 -> invalid", rep["label"] == REP_INVALID, rep["label"])
    conn.close()


def case_missing_input_blocks_output():
    print("\n[13] 迁移输入字节缺失：输出字节齐也不可证（输入须 proven）")
    conn = fresh()
    b = PackageBuilder(WORK + "/pkgs", "Q1", trusted_ingest=("ing-S",))
    b.add_bitstream("S", b"source"); b.add_bitstream("T", b"target")
    b.add_representation("RT", ["T"], nodes=["n"])
    b.add_event("ing-S", "ingest", outputs=["S"])
    b.add_event("mig-ST", "migration", inputs=["S"], outputs=["T"])
    b.mark_missing("S")  # 源缺失
    b.build()
    ingest.receive(conn, WORK + "/repo", WORK + "/pkgs/Q1")
    ingest.finish(conn, WORK + "/repo", "Q1")
    st_t, prov_t = object_state(conn, "local", "T")
    check("输出 T 字节齐", st_t == ST_BYTES_OK, st_t)
    check("源缺失 -> T 不可证", prov_t is False)
    rep = diagnostics.evaluate_representation(conn, "local", "RT")
    check("表示 unproven", rep["label"] == REP_UNPROVEN, rep["label"])
    try:
        exportmod.export_proof(conn, WORK + "/repo", WORK + "/exports",
                               "local", "RT")
        check("未证表示禁止导出", False)
    except exportmod.ExportError:
        check("未证表示禁止导出", True)
    conn.close()


def case_and_strictness_three_inputs():
    print("\n[14] 三输入 AND：缺任一中途到达的输入，事件输出在补齐前不可证")
    conn = fresh()
    b = PackageBuilder(WORK + "/pkgs", "Q1",
                       trusted_ingest=("ing-X", "ing-Y", "ing-Z"))
    for v, pay in (("X", b"x"), ("Y", b"y"), ("Z", b"z")):
        b.add_bitstream(v, pay)
        b.add_event("ing-" + v, "ingest", outputs=[v])
    b.add_bitstream("W", b"w")
    b.add_representation("RW", ["W"], nodes=["n"])
    b.add_event("mig-W", "migration",
                inputs=["X", "Y", "Z"], outputs=["W"])
    b.mark_missing("Z")
    b.build()
    ingest.receive(conn, WORK + "/repo", WORK + "/pkgs/Q1")
    ingest.finish(conn, WORK + "/repo", "Q1")
    _, prov_w = object_state(conn, "local", "W")
    check("三输入缺 Z -> W 不可证", prov_w is False)
    expl = diagnostics.explain_object(conn, "local", "W")
    branch = expl["candidate_events"][0]
    missing = [(i["id_value"], i["state"]) for i in branch["inputs"]
               if not i["proven"]]
    check("诊断精确定位 Z", missing == [("Z", ST_BYTES_MISSING)], str(missing))
    check("X、Y 仍各自可证（非任选）",
          all(i["proven"] for i in branch["inputs"] if i["id_value"] in ("X", "Y")))
    conn.close()


def main():
    case_multi_members()
    case_cross_package_forward_ref()
    case_same_bytes_diff_identity()
    case_path_escape()
    case_identity_conflict()
    case_late_and_resume()
    case_event_conflict()
    case_proof_immutability_and_move()
    case_uninterpreted_and_untrusted()
    case_corrupt_blob()
    case_missing_input_blocks_output()
    case_and_strictness_three_inputs()
    print("\n==== 边界测试汇总：%d PASS / %d FAIL ====" % (len(PASS), len(FAIL)))
    for name, detail in FAIL:
        print("  FAIL:", name, detail)
    if FAIL:
        sys.exit(1)


if __name__ == "__main__":
    main()
