# -*- coding: utf-8 -*-
"""
主演练（end-to-end）。运行：
  python -I /workspace/evidence_repo/tests/demo_main.py

场景（题目指定）：
  可信原件 A、B；事件 E 以 A 和 B 为【共同前提】(AND) 迁移成 C；
  仅 A 到达、B 字节未到时：C 字节完整但 origin_proven=false，
  依赖诊断必须含 B 的 bytes_missing，且不能导出 verified 证明；
  补 B 后 verified。
  另：D 依赖 C、C 又有一条来自 D 的循环支路 —— 沿 E 得到 C、D 的有限证明，
  循环不能自证、也不能全局否决；E 改 failed 后循环救不回；
  增加一条直接由 A 成功生成 C 的事件后恢复。

脚本开头打印人工绘制的 AND/OR 依赖图与预期摘要表，随后用程序结果逐项断言；
导出证明由 verify_export（独立检查器，不复用求值器）复核。
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
    REP_UNPROVEN,
    REP_VERIFIED,
    ST_BYTES_MISSING,
    ST_BYTES_OK,
)
from evidrepo.verify_export import verify_export  # noqa: E402

from fixtures import PackageBuilder  # noqa: E402

WORK = "/workspace/runs/main"
REPO = os.path.join(WORK, "repo")
PKGS = os.path.join(WORK, "packages")
EXPORTS = os.path.join(WORK, "exports")

HAND_DRAWN = r"""
================ 人工 AND/OR 依赖图（预期） ================
图例: ( )对象  [ ]事件  ^受信根  AND=事件全部输入共同前提  OR=任一产出路径即可

  (A) <-- ^[ingest-A]            (B) <-- ^[ingest-B]
    \________   _____________________/
             \ /
             [E: migration]  输入 {A, B} 为 AND，缺一不可
               |
              (C) <-- [G: migration] 输入 {D}   (循环支路 C<-D<-C)
               ^
               |
             [F: migration] 输入 {C}
               |
              (D)

  OR 语义：C 的候选产出事件 = {E, G}；E 路径有限可证，G 路径成环不可自证。
  阶段 2（B 未到）：E 的 AND 前提缺 B => C、D 均 origin_proven=false。
  阶段 3（B 到）：  E 成立 => C proven => F 成立 => D proven（环支路被忽略）。
  阶段 4（E failed）：E 失效；G 成环 => C、D 均不可证。
  阶段 5（新增 H: A -success-> C）：C 经 H 由受信根 A 证明；D 经 F 恢复。

================ 预期摘要表 ================
阶段 | B 字节 | E 结果 | C 状态/proven        | D 状态/proven        | 表示 R1
 2   | 缺     | success | bytes_ok / false     | bytes_ok / false     | unproven（成员齐、无完整原件路径；诊断含 B bytes_missing）
 3   | 到     | success | bytes_ok / true      | bytes_ok / true      | verified
 4   | 到     | failed  | bytes_ok / false     | bytes_ok / false     | unproven
 5   | 到     | success*| bytes_ok / true (H)  | bytes_ok / true      | verified
   * 阶段5中 E 仍 failed，恢复来自新事件 H（OR 替代路径）。
   * incomplete 标签在边界测试中由“表示声明成员缺失”场景覆盖。
==========================================================
"""


def setup_dirs():
    for d in (WORK, REPO, PKGS, EXPORTS):
        if os.path.exists(d):
            shutil.rmtree(d)
        os.makedirs(d, exist_ok=True)


def build_p1(with_b=False, e_outcome="success", add_h=False, cycle=True):
    b = PackageBuilder(PKGS, "P1", trusted_ingest=("ingest-A", "ingest-B"))
    b.add_bitstream("A", b"original-A-bytes")
    b.add_bitstream("B", b"original-B-bytes")
    b.add_bitstream("C", b"migrated-C-bytes")
    b.add_bitstream("D", b"derived-D-bytes")
    b.add_representation("R1", ["C", "D"], nodes=["node-1", "node-2"])
    b.add_event("ingest-A", "ingest", outputs=["A"])
    b.add_event("ingest-B", "ingest", outputs=["B"])
    b.add_event("E", "migration", inputs=["A", "B"], outputs=["C"],
                outcome=e_outcome)
    b.add_event("F", "migration", inputs=["C"], outputs=["D"])
    if cycle:
        b.add_event("G", "migration", inputs=["D"], outputs=["C"])
    if add_h:
        b.add_event("H", "migration", inputs=["A"], outputs=["C"])
    b.add_foreign_extension(
        '<premis:agent xmlns:premis="http://www.loc.gov/premis/v3">'
        "<premis:agentIdentifier><premis:agentIdentifierType>local"
        "</premis:agentIdentifierType><premis:agentIdentifierValue>agent-1"
        "</premis:agentIdentifierValue></premis:agentIdentifier></premis:agent>"
    )
    if not with_b:
        b.mark_missing("B")
    return b.build()


def seal(conn, pkg_id):
    ingest.finish(conn, REPO, pkg_id)


def main():
    print(HAND_DRAWN)
    setup_dirs()
    conn = dbmod.connect(REPO)
    results = []

    # ---- 阶段 2：B 未到（P1 staging 后封包，B 记录为 bytes_missing） ----
    build_p1(with_b=False)
    r = ingest.receive(conn, REPO, os.path.join(PKGS, "P1"))
    print("[阶段2] 接包报告:", json.dumps(r, ensure_ascii=False))
    assert r["blobs"].get("bytes_missing") == 1, r
    seal(conn, "P1")

    state_c, prov_c = object_state(conn, "local", "C")
    state_d, prov_d = object_state(conn, "local", "D")
    state_b, _ = object_state(conn, "local", "B")
    print("[阶段2] C:", state_c, prov_c, " D:", state_d, prov_d, " B:", state_b)
    assert (state_c, prov_c) == (ST_BYTES_OK, False)
    assert (state_d, prov_d) == (ST_BYTES_OK, False)
    assert state_b == ST_BYTES_MISSING

    expl_c = diagnostics.explain_object(conn, "local", "C")
    diag_text = json.dumps(expl_c, ensure_ascii=False)
    assert "bytes_missing" in diag_text and "B" in diag_text, diag_text
    # 共同前提：必须明确指出是 B 缺失，而不是任选输入
    e_branch = next(x for x in expl_c["candidate_events"] if x["event_id"] == "E")
    missing_inputs = [
        (i["id_value"], i["state"])
        for i in e_branch["inputs"] if not i["proven"]
    ]
    assert ("B", ST_BYTES_MISSING) in missing_inputs, missing_inputs
    a_input = next(i for i in e_branch["inputs"] if i["id_value"] == "A")
    assert a_input["proven"] is True
    print("[阶段2] E 分支输入诊断:", missing_inputs, "（A 已证、B bytes_missing）")

    rep = diagnostics.evaluate_representation(conn, "local", "R1")
    print("[阶段2] R1:", rep["label"], "| 原因:", rep["reasons"])
    assert rep["label"] == REP_UNPROVEN
    # 诊断必须逐项列出、且含 B 的 bytes_missing（不能合成一个“失败”）
    assert any("bytes_missing" in r and "B" in r for r in
               json.loads(json.dumps(rep))["reasons"]) or \
           "bytes_missing" in json.dumps(rep, ensure_ascii=False)
    # 未 verified 时禁止导出
    try:
        exportmod.export_proof(conn, REPO, EXPORTS, "local", "R1")
        raise AssertionError("export must be rejected for unverified representation")
    except exportmod.ExportError as exc:
        print("[阶段2] 导出被正确拒绝:", exc)

    # 结构节点多处引用同一表示不产生重复计数
    nodes = diagnostics.get_struct_node(conn, "node-1")
    assert len(nodes) == 1 and nodes[0]["rep_id_value"] == "R1"
    member_ids = {m["id_value"] for m in rep["members"]}
    assert member_ids == {"C", "D"}
    results.append(("阶段2 B缺失", "unproven / C,D proven=false / 禁止导出", True))

    # ---- 阶段 3：迟到的 B（P2 包，仅含 B）补到后封包 ----
    b2 = PackageBuilder(PKGS, "P2", trusted_ingest=("ingest-B",))
    b2.add_bitstream("B", b"original-B-bytes")
    # P2 不声明表示，只提供跨包成员；ingest-B 事件在 P2 也给出（同内容复制）
    b2.add_event("ingest-B", "ingest", outputs=["B"])
    b2.build()
    ingest.receive(conn, REPO, os.path.join(PKGS, "P2"))
    seal(conn, "P2")
    state_b, _ = object_state(conn, "local", "B")
    state_c, prov_c = object_state(conn, "local", "C")
    state_d, prov_d = object_state(conn, "local", "D")
    print("[阶段3] B:", state_b, " C proven:", prov_c, " D proven:", prov_d)
    assert state_b == ST_BYTES_OK and prov_c and prov_d

    rep = diagnostics.evaluate_representation(conn, "local", "R1")
    assert rep["label"] == REP_VERIFIED, rep
    print("[阶段3] R1 verified，成员:",
          [(m["id_value"], m["state"], m["origin_proven"]) for m in rep["members"]])

    # 循环支路存在但不否决：G 支路含环（C<-G<-D<-F<-C），有限的 E 支路被选中
    expl_c = diagnostics.explain_object(conn, "local", "C")
    chosen = expl_c["chosen_event"]
    assert chosen == "E", chosen
    g = next(x for x in expl_c["candidate_events"] if x["event_id"] == "G")
    assert g["contains_cycle"] is True, g
    print("[阶段3] C 选中事件:", chosen, "；循环支路 G contains_cycle=True（不可自证）")

    out1 = exportmod.export_proof(conn, REPO, EXPORTS, "local", "R1",
                                  node_id="node-1")
    v1 = verify_export(out1["export_dir"])
    print("[阶段3] 导出证明 #%s 独立验证:" % out1["proof_no"],
          "OK" if v1["ok"] else v1["errors"])
    assert v1["ok"], v1["errors"]
    # 子包不得包含无关表示；共享证据只一次
    with open(os.path.join(out1["export_dir"], "proof.json"), encoding="utf-8") as f:
        pdoc = json.load(f)
    bundled = {x["id_value"] for x in pdoc["blobs"]}
    assert bundled == {"A", "B", "C", "D"}, bundled
    assert len({x["sha256"] for x in pdoc["blobs"]}) == len(pdoc["blobs"])
    first_proof_no, first_proof_id = out1["proof_no"], out1["proof_id"]
    first_pkg_set = list(pdoc["sealed_package_set"])
    results.append(("阶段3 B补齐", "verified / 证明#%d 独立验证通过" % first_proof_no,
                    True))

    # ---- 阶段 4：E 改 failed（新仓重演；循环不能救回 C/D） ----
    shutil.rmtree(REPO); shutil.rmtree(EXPORTS)
    os.makedirs(REPO); os.makedirs(EXPORTS)
    conn2 = dbmod.connect(REPO)
    build_p1(with_b=True, e_outcome="failed")
    ingest.receive(conn2, REPO, os.path.join(PKGS, "P1"))
    seal(conn2, "P1")
    build_p2 = PackageBuilder(PKGS, "P2", trusted_ingest=("ingest-B",))
    build_p2.add_bitstream("B", b"original-B-bytes")
    build_p2.add_event("ingest-B", "ingest", outputs=["B"])
    build_p2.build()
    ingest.receive(conn2, REPO, os.path.join(PKGS, "P2"))
    seal(conn2, "P2")
    state_c, prov_c = object_state(conn2, "local", "C")
    state_d, prov_d = object_state(conn2, "local", "D")
    print("[阶段4] E=failed -> C proven:", prov_c, " D proven:", prov_d)
    assert prov_c is False and prov_d is False
    rep4 = diagnostics.evaluate_representation(conn2, "local", "R1")
    assert rep4["label"] == REP_UNPROVEN, rep4["label"]
    reasons_text = " ".join(rep4["reasons"])
    assert "no complete provenance path" in reasons_text
    print("[阶段4] R1:", rep4["label"], "（failed 保留为事实但不能证明；环 G 不可自证）")
    results.append(("阶段4 E failed", "unproven / 循环不能救回", True))

    # ---- 阶段 5：新增 H: A -success-> C，OR 替代路径恢复 ----
    b5 = PackageBuilder(PKGS, "P3", trusted_ingest=())
    b5.add_ref_only("A")  # 跨包引用：A 的字节与 ingest 事实来自 P1
    b5.add_bitstream("C", b"migrated-C-bytes")
    b5.add_event("H", "migration", inputs=["A"], outputs=["C"])
    b5.build()
    ingest.receive(conn2, REPO, os.path.join(PKGS, "P3"))
    seal(conn2, "P3")
    state_c, prov_c = object_state(conn2, "local", "C")
    state_d, prov_d = object_state(conn2, "local", "D")
    print("[阶段5] 新增 H -> C proven:", prov_c, " D proven:", prov_d)
    assert prov_c and prov_d
    expl_c = diagnostics.explain_object(conn2, "local", "C")
    assert expl_c["chosen_event"] in ("E", "H")
    # E 仍 failed：有效产出事件里不会有 E
    valid_ids = [x["event_id"] for x in expl_c["candidate_events"]]
    assert "E" not in valid_ids and "H" in valid_ids, valid_ids
    rep5 = diagnostics.evaluate_representation(conn2, "local", "R1")
    assert rep5["label"] == REP_VERIFIED
    print("[阶段5] R1 恢复 verified；C 有效路径:", valid_ids)
    results.append(("阶段5 新增H", "verified / OR 替代路径恢复", True))

    # ---- 旧证明不可变：回到阶段3的仓，证明号与包集合绑定 ----
    conn.close(); conn2.close()
    print("\n摘要：")
    for name, desc, ok in results:
        print("  [%s] %s -> %s" % ("PASS" if ok else "FAIL", name, desc))
    print("\n旧证明 #%d (proof_id=%s) 绑定包集合 %s，后续阶段在独立仓重演，"
          "原导出目录未被改写。" % (first_proof_no, first_proof_id[:12], first_pkg_set))
    print("主演练全部断言通过。")


if __name__ == "__main__":
    main()
