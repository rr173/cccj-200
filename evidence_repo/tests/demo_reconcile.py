# -*- coding: utf-8 -*-
"""
预期馆藏对账的验收测试（独立人工预期，不复用产品匹配/对账函数）。

每一场景的“预期”均为人工绘制的二分图、最大匹配基数与歧义集合；
断言只看产品输出的业务字段，不看其内部数据结构。

场景：
  01  贪心会少满足义务的重叠候选图（必须求最大匹配，不是贪心）
  02  存在多个最大分配、基数相同的图（歧义必须标出，不能伪装唯一）
  03  完全缺收
  04  已收但谱系未证（unproven，仍应匹配为“已出现”）
  05  已收但字节损坏（invalid，仍应匹配为“已出现”）
  06  相同 identifierValue、不同 identifierType 不得混淆
  07  实际身份冲突（同一表示身份，不同成员集合声明）不得静默择一
  08  重复结构引用不增加候选
  09  表示跨包重复出现仍是一个候选
  10  额外表示（清单未预期、未被分配）
  11  staging 包隔离（staging 不进入实际侧）
  12  导入中断/无效清单不得暴露半份数据
  13  迟到包后的新旧报告并存（旧报告不变）
  14  同输入重复运行稳定（report_id 与业务结果一致）
  15  报告移动后校验（内容哈希 + 输入绑定）
  16  大清单与大量封存表示的有界内存处理

另：用独立暴力枚举核对产品对人工小图的匹配基数、可现边、强制边、
    C_AMB 语义（见 case_02/oracle）。
"""
from __future__ import annotations

import io
import json
import os
import resource
import shutil
import sys
import tracemalloc

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))

from evidrepo import db as dbmod  # noqa: E402
from evidrepo import ingest  # noqa: E402
from evidrepo import inventory as invmod  # noqa: E402
from evidrepo import reconcile as reconc  # noqa: E402

from fixtures import PackageBuilder  # noqa: E402

WORK = "/workspace/runs/recon"
PASS, FAIL = [], []


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append((name, detail))
    print(("  [PASS] " if cond else "  [FAIL] ") + name +
          ((" — " + detail) if detail else ""))


def fresh_repo(sub="repo"):
    path = os.path.join(WORK, sub)
    shutil.rmtree(path, ignore_errors=True)
    os.makedirs(path)
    return dbmod.connect(path), path


# ---------------------------------------------------------------------------
# 独立暴力 oracle（不 import 产品匹配/对账代码）
# ---------------------------------------------------------------------------

def brute_all_matchings(nL, nR, edges):
    res = []

    def rec(u, cur, usedR):
        if u == nL:
            res.append(frozenset(cur))
            return
        rec(u + 1, cur, usedR)
        for v in range(nR):
            if v in usedR or (u, v) not in edges:
                continue
            rec(u + 1, cur + [(u, v)], usedR | {v})

    rec(0, [], set())
    return res


def brute_expectations(obligation_ids, actual_keys, candidates):
    """
    candidates: {obligation_id: [(type,value), ...]}
    返回人工可复算的期望：
      size, allowed_edges {(obl, rep)}, forced_edges, ambiguous_obligations,
      satisfiable_some, satisfiable_all
    """
    idx_obl = {o: i for i, o in enumerate(obligation_ids)}
    idx_rep = {r: i for i, r in enumerate(actual_keys)}
    edges = set()
    for o in obligation_ids:
        for key in candidates[o]:
            if key in idx_rep:
                edges.add((idx_obl[o], idx_rep[key]))
    ms = brute_all_matchings(len(obligation_ids), len(actual_keys), edges)
    k = max((len(m) for m in ms), default=0)
    maxes = [m for m in ms if len(m) == k]
    allowed = {(obligation_ids[u], actual_keys[v]) for m in maxes for u, v in m}
    forced = (set.intersection(*[set(m) for m in maxes])
              if maxes else set())
    forced = {(obligation_ids[u], actual_keys[v]) for u, v in forced}
    sat_some, sat_all = {}, {}
    for o in obligation_ids:
        sat_some[o] = any(any(u == idx_obl[o] for u, v in m) for m in maxes)
        sat_all[o] = all(any(u == idx_obl[o] for u, v in m) for m in maxes)
    ambig = sorted(o for o in obligation_ids if sat_some[o] and not sat_all[o])
    return {
        "size": k,
        "maxes": maxes,
        "allowed": allowed,
        "forced": forced,
        "sat_some": sat_some,
        "sat_all": sat_all,
        "ambiguous": ambig,
    }


def run_reconcile(conn, repo, inventory_id):
    res = reconc.reconcile_and_store(conn, repo, inventory_id)
    doc = reconc.load_report(conn, repo, res["report_id"])
    return res, doc


def summarize(doc):
    s = doc["summary"]
    return {
        "total": s["obligation_total"],
        "satisfied": s["satisfied"],
        "unsatisfied": s["unsatisfied"],
        "ambiguous": s["ambiguous"],
        "extra": s["extra"],
    }


# ---------------------------------------------------------------------------
# 场景
# ---------------------------------------------------------------------------

def case_01_greedy_trap():
    print("\n[01] 贪心会少满足义务的重叠候选图 —— 必须求最大匹配")
    # 义务 L1 可接受 {A, B}；L2 只接受 {A}；L3 只接受 {B}。
    # 贪心若先满足 L1=A，则 L2、L3 只能再满足其一（总数 2）；
    # 正确最大分配为 L1=B, L2=A, L3=C? 不 —— 设 A、B、C 都在实际侧：
    #   L1:{A,B}, L2:{A}, L3:{B}  最大=3（L1->? 无可用时 L1 只能让位）
    # 实际图：最大匹配 3 不可达（A、B 只有两个），因此改成经典陷阱：
    #   L1:{A,B}, L2:{A}, L3:{B,C}，实际 {A,B,C}
    #   贪心 L1=A -> 只剩 B,C；L2 无 A，L3 可 C => 满足 2
    #   最优 L1=B, L2=A, L3=C => 满足 3
    conn, repo = fresh_repo("c01")
    b = PackageBuilder(WORK + "/pkg01", "P1", trusted_ingest=("ing-A",))
    b.add_bitstream("M", b"m")
    for rep in ("A", "B", "C"):
        b.add_representation("R" + rep, ["M"], nodes=["n-" + rep],
                             filegrp="G-" + rep)
    b.add_event("ing-A", "ingest", outputs=["M"])
    b.build()
    ingest.receive(conn, repo, WORK + "/pkg01/P1")
    ingest.finish(conn, repo, "P1")

    inv = write_inventory(
        "c01",
        [
            ("L1", [("local", "RA"), ("local", "RB")]),
            ("L2", [("local", "RA")]),
            ("L3", [("local", "RB"), ("local", "RC")]),
        ],
    )
    invmod.import_inventory(conn, repo, inv)
    res, doc = run_reconcile(conn, repo, "c01")
    exp = brute_expectations(
        ["L1", "L2", "L3"],
        sorted([("local", "RA"), ("local", "RB"), ("local", "RC")]),
        {
            "L1": [("local", "RA"), ("local", "RB")],
            "L2": [("local", "RA")],
            "L3": [("local", "RB"), ("local", "RC")],
        },
    )
    s = summarize(doc)
    check("最大匹配基数=3（贪心只能 2）", s["satisfied"] == exp["size"] == 3,
          json.dumps(s))
    check("未满足=0", s["unsatisfied"] == 0)
    assign = {a["obligation_id"]: a["representation"]["identifierValue"]
              for a in doc["assignments"]}
    # 人工预期唯一最优解：L1=B, L2=A, L3=C
    check("逐项分配 = L1→RB, L2→RA, L3→RC",
          assign == {"L1": "RB", "L2": "RA", "L3": "RC"}, json.dumps(assign))
    check("各分配均稳定（唯一最大分配）",
          all(a["stable_across_all_maximum_assignments"]
              for a in doc["assignments"]))
    check("歧义义务=0", s["ambiguous"] == 0)
    check("额外=0", s["extra"] == 0)
    # 与人工 oracle 的逐边预期对照
    assigned_edges = {(a["obligation_id"],
                       (a["representation"]["identifierType"],
                        a["representation"]["identifierValue"]))
                      for a in doc["assignments"]}
    check("oracle：唯一最大分配 = 人工预期边集",
          assigned_edges == exp["forced"] == {
              ("L1", ("local", "RB")),
              ("L2", ("local", "RA")),
              ("L3", ("local", "RC")),
          }, json.dumps(sorted(assigned_edges)))
    conn.close()


def case_02_ambiguous_same_cardinality():
    print("\n[02] 多个最大分配、基数相同 —— 歧义必须显式标出")
    # 义务 L1:{A}, L2:{A}, L3:{B}。实际 A、B 都存在。
    # 最大基数=2，但 L1/L2 谁拿 A 不唯一；L3 稳定拿 B。
    # 人工预期：L3 在所有最大分配中都被满足；L1、L2 各只在一半中满足；
    # 可现边 {(L1,A),(L2,A),(L3,B)}，forced={(L3,B)}（A 被两个义务争）。
    conn, repo = fresh_repo("c02")
    b = PackageBuilder(WORK + "/pkg02", "P1", trusted_ingest=("ing-M",))
    b.add_bitstream("M", b"m")
    for rep in ("A", "B"):
        b.add_representation("R" + rep, ["M"], nodes=["n-" + rep],
                             filegrp="G-" + rep)
    b.add_event("ing-M", "ingest", outputs=["M"])
    b.build()
    ingest.receive(conn, repo, WORK + "/pkg02/P1")
    ingest.finish(conn, repo, "P1")
    inv = write_inventory(
        "c02",
        [
            ("L1", [("local", "RA")]),
            ("L2", [("local", "RA")]),
            ("L3", [("local", "RB")]),
        ],
    )
    invmod.import_inventory(conn, repo, inv)
    res, doc = run_reconcile(conn, repo, "c02")
    exp = brute_expectations(
        ["L1", "L2", "L3"],
        sorted([("local", "RA"), ("local", "RB")]),
        {"L1": [("local", "RA")], "L2": [("local", "RA")],
         "L3": [("local", "RB")]},
    )
    s = summarize(doc)
    check("最大匹配基数=2", s["satisfied"] == exp["size"] == 2, json.dumps(s))
    check("歧义义务=2（L1、L2）",
          sorted(a["obligation_id"] for a in doc["ambiguous_obligations"])
          == exp["ambiguous"] == ["L1", "L2"],
          json.dumps([a["obligation_id"] for a in doc["ambiguous_obligations"]]))
    check("未满足=1（在稳定分配中让位的那条）", s["unsatisfied"] == 1)
    check("满足数 + 未满足 = 义务总数",
          s["satisfied"] + s["unsatisfied"] == s["total"] == 3)
    # 稳定分配的强制边：L3->RB 出现在所有最大分配中
    check("L3→RB 标记为稳定",
          next(a for a in doc["assignments"]
               if a["obligation_id"] == "L3")
          ["stable_across_all_maximum_assignments"] is True)
    check("L1/L2 的分配边标记为可变化",
          len(doc["ambiguous_edges"]) >= 1 and
          all(not e["assignable_in_all_maximum_assignments"]
              for e in doc["ambiguous_edges"]))
    # 未满足义务必须给出候选被“其他义务占用”的原因
    uns = doc["unsatisfied_obligations"][0]
    check("未满足原因 = 候选已被其他义务占用",
          uns["reason_code"] == "all_acceptable_candidates_assigned_elsewhere",
          uns["reason_code"])
    cand = uns["candidates"][0]
    check("候选原因含占用方 obligation_id",
          cand["state"] == "assigned_to_another_obligation" and
          cand.get("taken_by_obligation_id") in ("L1", "L2"),
          json.dumps(cand, ensure_ascii=False))
    check("未满足义务被标为在某些最大分配中可满足",
          uns["satisfiable_in_some_maximum_assignment"] is True and
          uns["satisfied_in_all_maximum_assignments"] is False)
    # oracle：可现边集合与强制边集合必须与人工暴力枚举一致
    product_allowed = {
        (a["obligation_id"], (a["representation"]["identifierType"],
                              a["representation"]["identifierValue"]))
        for a in doc["assignments"]
    } | {
        (e["obligation_id"], (e["representation"]["identifierType"],
                              e["representation"]["identifierValue"]))
        for e in doc["ambiguous_edges"]
    }
    product_forced = {
        (a["obligation_id"], (a["representation"]["identifierType"],
                              a["representation"]["identifierValue"]))
        for a in doc["assignments"]
        if a["stable_across_all_maximum_assignments"]
    }
    check("可现边集合与暴力枚举一致（含 L1/L2 争 A 的两条）",
          product_allowed == exp["allowed"], json.dumps(sorted(product_allowed)))
    check("强制边集合与暴力枚举一致（仅 L3→RB）",
          product_forced == exp["forced"],
          json.dumps(sorted(product_forced)))
    check("未被匹配的义务在 oracle 中也可能被满足（歧义语义一致）",
          exp["sat_some"][uns["obligation_id"]] is True and
          exp["sat_all"][uns["obligation_id"]] is False)
    conn.close()


def case_03_all_missing():
    print("\n[03] 完全缺收")
    conn, repo = fresh_repo("c03")
    b = PackageBuilder(WORK + "/pkg03", "P1", trusted_ingest=("ing-M",))
    b.add_bitstream("M", b"m"); b.add_event("ing-M", "ingest", outputs=["M"])
    b.build()
    ingest.receive(conn, repo, WORK + "/pkg03/P1")
    ingest.finish(conn, repo, "P1")
    inv = write_inventory("c03", [
        ("L1", [("local", "R-NOPE1")]),
        ("L2", [("local", "R-NOPE2"), ("local", "R-NOPE3")]),
    ])
    invmod.import_inventory(conn, repo, inv)
    res, doc = run_reconcile(conn, repo, "c03")
    s = summarize(doc)
    check("满足=0", s["satisfied"] == 0, json.dumps(s))
    check("未满足=2", s["unsatisfied"] == 2)
    check("全部未满足原因为“无任何可接受表示出现”",
          all(u["reason_code"] == "no_acceptable_representation_present"
              for u in doc["unsatisfied_obligations"]))
    check("额外=0（实际侧没有表示）", s["extra"] == 0)
    conn.close()


def case_04_unproven_still_matched():
    print("\n[04] 已收但谱系未证 —— 仍匹配为已出现，质量保留 unproven")
    conn, repo = fresh_repo("c04")
    b = PackageBuilder(WORK + "/pkg04", "P1", trusted_ingest=())
    # 成员字节齐全，但没有任何事件把它接到受信 ingest 根 => bytes_ok 但未证
    b.add_bitstream("M", b"real-member-bytes")
    b.add_representation("RUP", ["M"], nodes=["n"])
    b.build()
    ingest.receive(conn, repo, WORK + "/pkg04/P1")
    ingest.finish(conn, repo, "P1")
    inv = write_inventory("c04", [("L1", [("local", "RUP")])])
    invmod.import_inventory(conn, repo, inv)
    res, doc = run_reconcile(conn, repo, "c04")
    s = summarize(doc)
    check("已收表示匹配成功（satisfied=1）", s["satisfied"] == 1,
          json.dumps(s))
    a = doc["assignments"][0]
    check("质量标签保留 unproven（未提升为 verified）",
          a["quality"]["label"] == "unproven", a["quality"]["label"])
    check("原因逐项保留", len(a["quality"]["reasons"]) >= 1,
          json.dumps(a["quality"]["reasons"], ensure_ascii=False))
    check("附 package_id", a["package_id"] == "P1", str(a.get("package_id")))
    conn.close()


def case_05_corrupt_still_matched():
    print("\n[05] 已收但字节损坏 —— 仍匹配为已出现，质量保留 invalid")
    conn, repo = fresh_repo("c05")
    b = PackageBuilder(WORK + "/pkg05", "P1", trusted_ingest=("ing-K",))
    b.add_bitstream("K", b"good-bytes"); b.mark_corrupt("K")
    b.add_representation("RK", ["K"], nodes=["n"])
    b.add_event("ing-K", "ingest", outputs=["K"])
    b.build()
    ingest.receive(conn, repo, WORK + "/pkg05/P1")
    ingest.finish(conn, repo, "P1")
    inv = write_inventory("c05", [("L1", [("local", "RK")])])
    invmod.import_inventory(conn, repo, inv)
    res, doc = run_reconcile(conn, repo, "c05")
    a = doc["assignments"][0]
    check("损坏表示仍匹配成功", doc["summary"]["satisfied"] == 1)
    check("质量标签保留 invalid", a["quality"]["label"] == "invalid",
          a["quality"]["label"])
    conn.close()


def case_06_identifier_type_matters():
    print("\n[06] 相同 identifierValue、不同 identifierType 不得混淆")
    conn, repo = fresh_repo("c06")
    b = PackageBuilder(WORK + "/pkg06", "P1", trusted_ingest=("ing-M",))
    b.add_bitstream("M", b"m")
    b.add_representation("SAME", ["M"], nodes=["n"], id_type="local")
    b.add_event("ing-M", "ingest", outputs=["M"])
    b.build()
    ingest.receive(conn, repo, WORK + "/pkg06/P1")
    ingest.finish(conn, repo, "P1")
    # 实际侧只有 (local, SAME)；清单要求 (uuid, SAME) 与 (local, SAME)
    inv = write_inventory("c06", [
        ("L-uuid", [("uuid", "SAME")]),
        ("L-local", [("local", "SAME")]),
    ])
    invmod.import_inventory(conn, repo, inv)
    res, doc = run_reconcile(conn, repo, "c06")
    s = summarize(doc)
    check("只有精确二元组匹配成功（satisfied=1）", s["satisfied"] == 1,
          json.dumps(s))
    uns = doc["unsatisfied_obligations"]
    check("uuid 类型义务未满足", len(uns) == 1 and
          uns[0]["obligation_id"] == "L-uuid", json.dumps(uns, ensure_ascii=False))
    check("未满足原因 = 无可接受表示出现",
          uns[0]["reason_code"] == "no_acceptable_representation_present")
    conn.close()


def case_07_identity_conflict():
    print("\n[07] 实际身份冲突（同身份不同成员集合）不得静默择一")
    conn, repo = fresh_repo("c07")
    # P1：表示 RCONF 成员 {M1}
    b1 = PackageBuilder(WORK + "/pkg07", "P1", trusted_ingest=("ing-M1",))
    b1.add_bitstream("M1", b"m1")
    b1.add_representation("RCONF", ["M1"], nodes=["n1"])
    b1.add_event("ing-M1", "ingest", outputs=["M1"])
    b1.build()
    ingest.receive(conn, repo, WORK + "/pkg07/P1")
    ingest.finish(conn, repo, "P1")
    # P2：同身份 RCONF 但成员 {M2} —— 事实冲突
    b2 = PackageBuilder(WORK + "/pkg07", "P2", trusted_ingest=("ing-M2",))
    b2.add_bitstream("M2", b"m2")
    b2.add_representation("RCONF", ["M2"], nodes=["n2"],
                          filegrp="G2")
    b2.add_event("ing-M2", "ingest", outputs=["M2"])
    b2.build()
    ingest.receive(conn, repo, WORK + "/pkg07/P2")
    ingest.finish(conn, repo, "P2")
    inv = write_inventory("c07", [("L1", [("local", "RCONF")])])
    invmod.import_inventory(conn, repo, inv)
    res, doc = run_reconcile(conn, repo, "c07")
    check("冲突列入 identity_conflicts", doc["summary"]["identity_conflicts"] == 1,
          json.dumps(doc["identity_conflicts"], ensure_ascii=False))
    conf = doc["identity_conflicts"][0]
    check("冲突类型为成员集合不一致",
          "representation_member_set_mismatch" in conf["kinds"],
          json.dumps(conf["kinds"]))
    check("冲突列出全部相关包（不择一）",
          conf["package_ids"] == ["P1", "P2"], json.dumps(conf["package_ids"]))
    a = doc["assignments"][0]
    check("分配条目不静默择一：package_id 置空", a["package_id"] is None,
          str(a.get("package_id")))
    check("分配条目保留全部相关包", a["package_ids"] == ["P1", "P2"])
    check("分配条目保留冲突原因", a["identity_conflict"] is not None and
          "representation_member_set_mismatch" in a["identity_conflict"]["kinds"])
    conn.close()


def case_08_struct_dup_no_extra_candidates():
    print("\n[08] 重复结构引用不增加候选")
    conn, repo = fresh_repo("c08")
    b = PackageBuilder(WORK + "/pkg08", "P1", trusted_ingest=("ing-M",))
    b.add_bitstream("M", b"m")
    b.add_representation("RDUP", ["M"], nodes=["n1", "n2", "n3", "n4"])
    b.add_event("ing-M", "ingest", outputs=["M"])
    b.build()
    ingest.receive(conn, repo, WORK + "/pkg08/P1")
    ingest.finish(conn, repo, "P1")
    inv = write_inventory("c08", [
        ("L1", [("local", "RDUP")]),
        ("L2", [("local", "RDUP")]),
    ])
    invmod.import_inventory(conn, repo, inv)
    res, doc = run_reconcile(conn, repo, "c08")
    s = summarize(doc)
    check("结构节点 4 处引用只产生 1 个实际身份",
          doc["summary"]["actual_representation_identities"] == 1,
          json.dumps(doc["summary"]))
    check("两条义务争同一身份 => 满足 1、歧义 2、未满足 1",
          s["satisfied"] == 1 and s["ambiguous"] == 2 and s["unsatisfied"] == 1,
          json.dumps(s))
    conn.close()


def case_09_cross_package_same_candidate():
    print("\n[09] 表示跨包重复出现仍是一个候选")
    conn, repo = fresh_repo("c09")
    b1 = PackageBuilder(WORK + "/pkg09", "P1", trusted_ingest=("ing-M",))
    b1.add_bitstream("M", b"m")
    b1.add_representation("RXP", ["M"], nodes=["n1"])
    b1.add_event("ing-M", "ingest", outputs=["M"])
    b1.build()
    ingest.receive(conn, repo, WORK + "/pkg09/P1")
    ingest.finish(conn, repo, "P1")
    # P2 再次声明同一表示（同一成员集合）
    b2 = PackageBuilder(WORK + "/pkg09", "P2", trusted_ingest=("ing-M",))
    b2.add_ref_only("M")
    b2.add_representation("RXP", ["M"], nodes=["n2"])
    b2.add_event("ing-M", "ingest", outputs=["M"])
    b2.build()
    ingest.receive(conn, repo, WORK + "/pkg09/P2")
    ingest.finish(conn, repo, "P2")
    inv = write_inventory("c09", [("L1", [("local", "RXP")])])
    invmod.import_inventory(conn, repo, inv)
    res, doc = run_reconcile(conn, repo, "c09")
    check("跨包重复声明只算 1 个实际身份",
          doc["summary"]["actual_representation_identities"] == 1,
          json.dumps(doc["summary"]))
    check("不产生额外表示（extra=0）", doc["summary"]["extra"] == 0)
    check("`身份冲突`也不产生（成员集合相同）",
          doc["summary"]["identity_conflicts"] == 0)
    a = doc["assignments"][0]
    check("确定性选 package_id = P1（最小包）", a["package_id"] == "P1",
          str(a.get("package_id")))
    check("仍列出全部包", a["package_ids"] == ["P1", "P2"])
    conn.close()


def case_10_extra_representations():
    print("\n[10] 额外表示（清单未预期、未被分配）")
    conn, repo = fresh_repo("c10")
    b = PackageBuilder(WORK + "/pkg10", "P1", trusted_ingest=("ing-M",))
    b.add_bitstream("M", b"m")
    b.add_representation("RWANT", ["M"], nodes=["n1"])
    b.add_representation("REXTRA", ["M"], nodes=["n2"], filegrp="G2")
    b.add_event("ing-M", "ingest", outputs=["M"])
    b.build()
    ingest.receive(conn, repo, WORK + "/pkg10/P1")
    ingest.finish(conn, repo, "P1")
    inv = write_inventory("c10", [("L1", [("local", "RWANT")])])
    invmod.import_inventory(conn, repo, inv)
    res, doc = run_reconcile(conn, repo, "c10")
    s = summarize(doc)
    check("满足=1、额外=1", s["satisfied"] == 1 and s["extra"] == 1,
          json.dumps(s))
    ex = doc["extra_representations"][0]
    check("额外表示是 REXTRA", ex["representation"]["identifierValue"]
          == "REXTRA")
    check("额外表示附质量与来源包", ex["quality"]["label"] in
          ("verified", "unproven", "incomplete", "invalid") and
          ex["package_id"] == "P1")
    conn.close()


def case_11_staging_isolation():
    print("\n[11] staging 包隔离")
    conn, repo = fresh_repo("c11")
    b1 = PackageBuilder(WORK + "/pkg11", "P1", trusted_ingest=("ing-M",))
    b1.add_bitstream("M", b"m")
    b1.add_representation("RSEALED", ["M"], nodes=["n1"])
    b1.add_event("ing-M", "ingest", outputs=["M"])
    b1.build()
    ingest.receive(conn, repo, WORK + "/pkg11/P1")
    ingest.finish(conn, repo, "P1")
    # P2 只 staging，不 finish
    b2 = PackageBuilder(WORK + "/pkg11", "P2", trusted_ingest=())
    b2.add_ref_only("M")
    b2.add_representation("RSTAGING", ["M"], nodes=["n2"])
    b2.build()
    ingest.receive(conn, repo, WORK + "/pkg11/P2")
    inv = write_inventory("c11", [
        ("L1", [("local", "RSEALED")]),
        ("L2", [("local", "RSTAGING")]),
    ])
    invmod.import_inventory(conn, repo, inv)
    res, doc = run_reconcile(conn, repo, "c11")
    s = summarize(doc)
    check("staging 表示不入实际侧 => satisfied=1", s["satisfied"] == 1,
          json.dumps(s))
    check("staging 不计入实际身份数",
          doc["summary"]["actual_representation_identities"] == 1)
    check("清单中 staging 的 RSTAGING 不被匹配",
          all(a["representation"]["identifierValue"] != "RSTAGING"
              for a in doc["assignments"]))
    check("sealed 包集合只含 P1",
          doc["inputs"]["sealed"]["package_set"] == ["P1"],
          json.dumps(doc["inputs"]["sealed"]))
    conn.close()


def case_12_atomic_import():
    print("\n[12] 导入中断/无效清单不得暴露半份数据")
    conn, repo = fresh_repo("c12")
    # 好行 + 坏行（重复 obligation）
    bad = "\n".join([
        json.dumps({"record_type": "inventory_header",
                    "format_version": "expected-inventory/v1",
                    "inventory_id": "c12bad", "batch_note": "x"}),
        json.dumps({"item_id": "I1", "obligation_id": "O1",
                    "acceptable_representations": [
                        {"identifierType": "local", "identifierValue": "R1"}]}),
        json.dumps({"item_id": "I2", "obligation_id": "O1",
                    "acceptable_representations": [
                        {"identifierType": "local", "identifierValue": "R2"}]}),
    ]) + "\n"
    path = os.path.join(WORK, "c12_bad.jsonl")
    with open(path, "w", encoding="utf-8") as f:
        f.write(bad)
    try:
        invmod.import_inventory(conn, repo, path)
        check("无效清单被拒绝", False)
    except invmod.InventoryError as exc:
        check("无效清单被拒绝", True, exc.code)
    n_inv = conn.execute("SELECT COUNT(*) c FROM inventories").fetchone()["c"]
    n_obl = conn.execute(
        "SELECT COUNT(*) c FROM inventory_obligations").fetchone()["c"]
    n_acc = conn.execute(
        "SELECT COUNT(*) c FROM inventory_acceptable").fetchone()["c"]
    check("无任何半份清单行写入", n_inv == 0 and n_obl == 0 and n_acc == 0,
          "inv=%d obl=%d acc=%d" % (n_inv, n_obl, n_acc))
    check("无残留清单副本文件",
          not os.path.exists(os.path.join(repo, "inventories")) or
          not os.listdir(os.path.join(repo, "inventories")))

    # BOM / 非 UTF-8 / 空候选 / 重复候选 / 控制字符 / 版本不符
    bad_cases = {
        "bom": b"\xef\xbb\xbf" + json.dumps({
            "format_version": "expected-inventory/v1",
            "inventory_id": "b"}).encode(),
        "non_utf8": b'{"format_version":"expected-inventory/v1",'
                    b'"inventory_id":"x","item_id":"I","obligation_id":"O",'
                    b'"acceptable_representations":[{"identifierType":"local",'
                    b'"identifierValue":"\xff\xfe"}]}\n',
        "bad_version": json.dumps({
            "format_version": "expected-inventory/v9",
            "inventory_id": "v"}).encode() + b"\n",
    }
    for name, payload in bad_cases.items():
        p = os.path.join(WORK, "c12_%s.jsonl" % name)
        with open(p, "wb") as f:
            f.write(payload)
        try:
            invmod.import_inventory(conn, repo, p)
            check("拒绝 %s" % name, False)
        except invmod.InventoryError:
            check("拒绝 %s" % name, True)
    n_inv = conn.execute("SELECT COUNT(*) c FROM inventories").fetchone()["c"]
    check("全部失败后仍无半份清单", n_inv == 0)

    # 重复候选身份（同一义务内）
    dup_cand = "\n".join([
        json.dumps({"format_version": "expected-inventory/v1",
                    "inventory_id": "c12dup"}),
        json.dumps({"item_id": "I", "obligation_id": "O",
                    "acceptable_representations": [
                        {"identifierType": "local", "identifierValue": "R"},
                        {"identifierType": "local", "identifierValue": "R"}]}),
    ]) + "\n"
    p = os.path.join(WORK, "c12_dupcand.jsonl")
    with open(p, "w", encoding="utf-8") as f:
        f.write(dup_cand)
    try:
        invmod.import_inventory(conn, repo, p)
        check("拒绝重复候选身份", False)
    except invmod.InventoryError as exc:
        check("拒绝重复候选身份", exc.code == "duplicate_candidate",
              exc.code)

    # 控制字符
    ctrl = (json.dumps({"format_version": "expected-inventory/v1",
                        "inventory_id": "c12ctrl"}) + "\n" +
            json.dumps({"item_id": "I", "obligation_id": "O",
                        "note": "a\tb",
                        "acceptable_representations": [
                            {"identifierType": "local",
                             "identifierValue": "R"}]}) + "\n")
    p = os.path.join(WORK, "c12_ctrl.jsonl")
    with open(p, "w", encoding="utf-8") as f:
        f.write(ctrl)
    try:
        invmod.import_inventory(conn, repo, p)
        check("拒绝控制字符", False)
    except invmod.InventoryError as exc:
        check("拒绝控制字符", exc.code == "bad_text", exc.code)
    conn.close()


def case_13_late_package_reports():
    print("\n[13] 迟到包后的新旧报告并存（旧报告不变）")
    conn, repo = fresh_repo("c13")
    b = PackageBuilder(WORK + "/pkg13", "P1", trusted_ingest=("ing-M",))
    b.add_bitstream("M", b"m")
    b.add_representation("RA", ["M"], nodes=["n1"])
    b.add_event("ing-M", "ingest", outputs=["M"])
    b.build()
    ingest.receive(conn, repo, WORK + "/pkg13/P1")
    ingest.finish(conn, repo, "P1")
    inv = write_inventory("c13", [("L1", [("local", "RA"), ("local", "RB")])])
    invmod.import_inventory(conn, repo, inv)
    res1, doc1 = run_reconcile(conn, repo, "c13")
    old_path = os.path.join(repo, res1["report_path"])
    with open(old_path, "rb") as f:
        old_bytes = f.read()
    check("首轮 RA 满足", doc1["summary"]["satisfied"] == 1)

    # 迟到包：带来 RB
    b2 = PackageBuilder(WORK + "/pkg13", "P2", trusted_ingest=("ing-M2",))
    b2.add_bitstream("M2", b"m2")
    b2.add_representation("RB", ["M2"], nodes=["n2"], filegrp="G2")
    b2.add_event("ing-M2", "ingest", outputs=["M2"])
    b2.build()
    ingest.receive(conn, repo, WORK + "/pkg13/P2")
    ingest.finish(conn, repo, "P2")
    res2, doc2 = run_reconcile(conn, repo, "c13")
    check("新报告 ID 不同", res2["report_id"] != res1["report_id"])
    with open(old_path, "rb") as f:
        check("旧报告文件逐字节未改写", f.read() == old_bytes)
    check("旧报告仍在 reports 列表",
          {r["report_id"] for r in reconc.list_reports(conn, "c13")}
          == {res1["report_id"], res2["report_id"]})
    check("新报告绑定新包集合", doc2["inputs"]["sealed"]["package_set"]
          == ["P1", "P2"], json.dumps(doc2["inputs"]["sealed"]))
    check("旧报告绑定旧包集合", doc1["inputs"]["sealed"]["package_set"]
          == ["P1"])
    check("新报告出现候选歧义边（RA 与 RB 二选一）",
          doc2["summary"]["ambiguous_edges"] == 2 and
          {e["representation"]["identifierValue"]
           for e in doc2["ambiguous_edges"]} == {"RA", "RB"},
          json.dumps(doc2["ambiguous_edges"], ensure_ascii=False))
    conn.close()


def case_14_deterministic():
    print("\n[14] 同输入重复运行稳定")
    conn, repo = fresh_repo("c14")
    b = PackageBuilder(WORK + "/pkg14", "P1", trusted_ingest=("ing-M",))
    b.add_bitstream("M", b"m")
    for i, rep in enumerate(("RA", "RB", "RC")):
        b.add_representation(rep, ["M"], nodes=["n%d" % i], filegrp="G%d" % i)
    b.add_event("ing-M", "ingest", outputs=["M"])
    b.build()
    ingest.receive(conn, repo, WORK + "/pkg14/P1")
    ingest.finish(conn, repo, "P1")
    inv = write_inventory("c14", [
        ("L1", [("local", "RA"), ("local", "RB")]),
        ("L2", [("local", "RB"), ("local", "RC")]),
        ("L3", [("local", "RC"), ("local", "RA")]),
    ])
    invmod.import_inventory(conn, repo, inv)
    r1, d1 = run_reconcile(conn, repo, "c14")
    r2, d2 = run_reconcile(conn, repo, "c14")
    check("相同输入 -> 相同 report_id", r1["report_id"] == r2["report_id"])
    check("第二次复用既有报告（不新增行）", r2["reused"] is True)
    check("业务结果逐字段一致",
          json.dumps(reconc._content_for_hash(d1), sort_keys=True) ==
          json.dumps(reconc._content_for_hash(d2), sort_keys=True))
    n = conn.execute(
        "SELECT COUNT(*) c FROM reconciliation_reports").fetchone()["c"]
    check("reports 表只有 1 行", n == 1, str(n))

    # 行序不同但内容等价 -> 分配与计数不变（业务结果独立于输入行序）
    inv2 = write_inventory("c14b", [
        ("L3", [("local", "RC"), ("local", "RA")]),
        ("L1", [("local", "RA"), ("local", "RB")]),
        ("L2", [("local", "RB"), ("local", "RC")]),
    ])
    invmod.import_inventory(conn, repo, inv2)
    r3, d3 = run_reconcile(conn, repo, "c14b")
    check("不同行序的等价清单：满足/未满足/歧义计数相同",
          summarize(d3) == summarize(d1) or
          (summarize(d3)["satisfied"] == summarize(d1)["satisfied"] and
           summarize(d3)["ambiguous"] == summarize(d1)["ambiguous"]),
          json.dumps([summarize(d1), summarize(d3)]))
    conn.close()


def case_15_report_movable():
    print("\n[15] 报告移动后独立校验")
    conn, repo = fresh_repo("c15")
    b = PackageBuilder(WORK + "/pkg15", "P1", trusted_ingest=("ing-M",))
    b.add_bitstream("M", b"m")
    b.add_representation("RA", ["M"], nodes=["n1"])
    b.add_event("ing-M", "ingest", outputs=["M"])
    b.build()
    ingest.receive(conn, repo, WORK + "/pkg15/P1")
    ingest.finish(conn, repo, "P1")
    inv = write_inventory("c15", [("L1", [("local", "RA")])])
    invmod.import_inventory(conn, repo, inv)
    res, doc = run_reconcile(conn, repo, "c15")
    orig = os.path.join(repo, res["report_path"])
    check("原位校验通过", reconc.verify_report(orig)["ok"],
          json.dumps(reconc.verify_report(orig), ensure_ascii=False))

    moved = os.path.join(WORK, "moved-report.json")
    shutil.copy(orig, moved)
    v = reconc.verify_report(moved)
    check("搬迁后独立校验通过", v["ok"], json.dumps(v, ensure_ascii=False))
    check("校验得到的 inventory_id 与包集合一致",
          v["inventory_id"] == "c15" and v["sealed_package_set"] == ["P1"])

    # 篡改业务字段 -> 内容哈希不符
    with open(moved, "r", encoding="utf-8") as f:
        tampered = json.load(f)
    tampered["assignments"][0]["quality"]["label"] = "verified"
    tampered["assignments"][0]["quality"]["reasons"] = ["tampered"]
    p2 = os.path.join(WORK, "tampered-report.json")
    with open(p2, "w", encoding="utf-8") as f:
        json.dump(tampered, f, ensure_ascii=False, indent=2, sort_keys=True)
    v2 = reconc.verify_report(p2)
    check("篡改质量标签 -> 校验失败", not v2["ok"], json.dumps(v2["errors"]))

    # 篡改包集合绑定 -> 校验失败
    with open(moved, "r", encoding="utf-8") as f:
        tampered2 = json.load(f)
    tampered2["inputs"]["sealed"]["package_set"] = ["P1", "P-EVIL"]
    p3 = os.path.join(WORK, "tampered2-report.json")
    with open(p3, "w", encoding="utf-8") as f:
        json.dump(tampered2, f, ensure_ascii=False, indent=2, sort_keys=True)
    v3 = reconc.verify_report(p3)
    check("篡改包集合 -> 校验失败", not v3["ok"],
          json.dumps(v3["errors"], ensure_ascii=False))
    conn.close()


def case_16_bounded_memory():
    print("\n[16] 大清单和大量封存表示下的有界内存")
    conn, repo = fresh_repo("c16")
    n_rep = 400
    n_obl = 1500
    b = PackageBuilder(WORK + "/pkg16", "P1", trusted_ingest=("ing-M",))
    b.add_bitstream("M", b"m")
    for i in range(n_rep):
        b.add_representation("RP%04d" % i, ["M"], nodes=["n%04d" % i],
                             filegrp="G%04d" % i)
    b.add_event("ing-M", "ingest", outputs=["M"])
    b.build()
    ingest.receive(conn, repo, WORK + "/pkg16/P1")
    ingest.finish(conn, repo, "P1")

    lines = [json.dumps({"format_version": "expected-inventory/v1",
                         "inventory_id": "c16", "batch_note": "big"})]
    for i in range(n_obl):
        # 形成稀疏重叠图：每个义务 1..3 个候选
        cands = [{"identifierType": "local",
                  "identifierValue": "RP%04d" % ((i * 7 + k) % n_rep)}
                 for k in range(1 + (i % 3))]
        # 去重
        seen, uniq = set(), []
        for c in cands:
            k = (c["identifierType"], c["identifierValue"])
            if k not in seen:
                seen.add(k); uniq.append(c)
        lines.append(json.dumps({
            "item_id": "I%05d" % i,
            "obligation_id": "O%05d" % i,
            "acceptable_representations": uniq,
        }))
    path = os.path.join(WORK, "c16_big.jsonl")
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")

    tracemalloc.start()
    invmod.import_inventory(conn, repo, path)
    res, doc = run_reconcile(conn, repo, "c16")
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    s = doc["summary"]
    check("大清单满足 + 未满足 = 义务总数",
          s["satisfied"] + s["unsatisfied"] == n_obl,
          json.dumps(s))
    check("最大匹配基数 = min(实际身份, 义务) 且受图约束",
          s["satisfied"] <= min(n_rep, n_obl))
    check("每次运行内存有界（峰值 < 64 MiB）", peak < 64 * 1024 * 1024,
          "peak=%.1f MiB" % (peak / 1048576))
    print("    （义务 %d、实际身份 %d：峰值 %.1f MiB，满足 %d、歧义 %d、额外 %d）"
          % (n_obl, s["actual_representation_identities"],
             peak / 1048576, s["satisfied"], s["ambiguous"], s["extra"]))
    conn.close()


# ---------------------------------------------------------------------------
# 工具
# ---------------------------------------------------------------------------


def case_17_no_state_mutation():
    print("\n[17] 对账不改变既有字节/谱系状态，也不把 bitstream/节点当表示")
    conn, repo = fresh_repo("c17")
    b = PackageBuilder(WORK + "/pkg17", "P1", trusted_ingest=("ing-M",))
    b.add_bitstream("M", b"m")
    b.add_representation("RA", ["M"], nodes=["n1"])
    b.add_event("ing-M", "ingest", outputs=["M"])
    b.build()
    ingest.receive(conn, repo, WORK + "/pkg17/P1")
    ingest.finish(conn, repo, "P1")

    def snapshot():
        return {
            "obj_status": [tuple(r) for r in conn.execute(
                "SELECT * FROM obj_status ORDER BY id_type,id_value")],
            "ev_status": [tuple(r) for r in conn.execute(
                "SELECT * FROM ev_status ORDER BY event_id")],
            "objects": conn.execute(
                "SELECT COUNT(*) FROM objects").fetchone()[0],
            "events": conn.execute(
                "SELECT COUNT(*) FROM events").fetchone()[0],
            "obj_conflicts": conn.execute(
                "SELECT COUNT(*) FROM object_conflicts").fetchone()[0],
        }

    before = snapshot()
    # 清单里故意把 bitstream 身份 M 与结构节点名 n1 当成候选
    inv = write_inventory("c17", [
        ("L-bitstream", [("local", "M")]),
        ("L-node", [("mets", "n1")]),
        ("L-rep", [("local", "RA")]),
    ])
    invmod.import_inventory(conn, repo, inv)
    res, doc = run_reconcile(conn, repo, "c17")
    after = snapshot()
    check("obj_status / ev_status / objects / events 完全未变",
          before == after, json.dumps({"before": before, "after": after},
                                      ensure_ascii=False))
    check("bitstream 身份 M 不被当作实际表示",
          all(a["representation"]["identifierValue"] != "M"
              for a in doc["assignments"]))
    check("结构节点名 n1 不被当作实际表示",
          all(a["representation"]["identifierValue"] != "n1"
              for a in doc["assignments"]))
    s = doc["summary"]
    check("只有真正的表示 RA 满足（satisfied=1、unsatisfied=2）",
          s["satisfied"] == 1 and s["unsatisfied"] == 2, json.dumps(s))
    check("实际侧身份数只含 RA",
          s["actual_representation_identities"] == 1)
    conn.close()


def write_inventory(inventory_id, obligations, batch_note="test batch"):
    header = {
        "record_type": "inventory_header",
        "format_version": "expected-inventory/v1",
        "inventory_id": inventory_id,
        "batch_note": batch_note,
    }
    lines = [json.dumps(header, ensure_ascii=False)]
    for i, (obligation_id, cands) in enumerate(obligations):
        lines.append(json.dumps({
            "record_type": "obligation",
            "inventory_id": inventory_id,
            "item_id": "ITEM-%04d" % i,
            "obligation_id": obligation_id,
            "acceptable_representations": [
                {"identifierType": t, "identifierValue": v} for t, v in cands
            ],
        }, ensure_ascii=False))
    path = os.path.join(WORK, "inv_%s.jsonl" % inventory_id)
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    return path


def main():
    shutil.rmtree(WORK, ignore_errors=True)
    os.makedirs(WORK)
    case_01_greedy_trap()
    case_02_ambiguous_same_cardinality()
    case_03_all_missing()
    case_04_unproven_still_matched()
    case_05_corrupt_still_matched()
    case_06_identifier_type_matters()
    case_07_identity_conflict()
    case_08_struct_dup_no_extra_candidates()
    case_09_cross_package_same_candidate()
    case_10_extra_representations()
    case_11_staging_isolation()
    case_12_atomic_import()
    case_13_late_package_reports()
    case_14_deterministic()
    case_15_report_movable()
    case_16_bounded_memory()
    case_17_no_state_mutation()
    print("\n==== 对账验收测试汇总：%d PASS / %d FAIL ===="
          % (len(PASS), len(FAIL)))
    for name, detail in FAIL:
        print("  FAIL:", name, detail)
    if FAIL:
        sys.exit(1)


if __name__ == "__main__":
    main()
