# -*- coding: utf-8 -*-
"""
预期馆藏对账引擎。

回答“本批预期交付由哪些实际表示承担”，不替代字节完整性、来源谱系判定，
也不导出证明子包。

匹配模型
--------
- 左侧（义务）：清单中每条 obligation_id 是一个独立义务；
- 右侧（实际）：**sealed 包中声明的 representation 身份**，按
  (identifierType, identifierValue) 去重，一个身份一个节点；
  staging 包、bitstream 对象、METS 结构节点、跨包重复提及都不增加候选；
- 边：义务的可接受身份若出现在实际集合中，则连边；
- 求**最大一对一匹配**（Hopcroft–Karp；遍历顺序固定，结果与输入行序无关）。

稳定展示 vs 全部最大分配都成立的事实
------------------------------------
先求任一最大匹配 M，再在剩余图上分析：
  Zf = 从未匹配义务出发沿增广路正向（未匹配边 L→R）可达的节点；
  Zr = 从空余实际身份出发沿反向（匹配边 R→L）可达的节点；
  SCC = 有向剩余图的强连通分量。
据此可判定（与逐边强制/排除重解最大匹配等价，见 tests 中人工图）：

  非匹配边 (u,v) 可出现在某个最大匹配中
      ⇔ u ∈ Zf ∨ v ∈ Zr ∨ u、v 同属一个 SCC
  匹配边始终可出现在该最大匹配中。
  边 (u,v) 出现在**所有**最大匹配中
      ⇔ 可出现在某最大匹配 且
        ( u ∉ Zf 且 u 在可现边中出度为 1 ) 或
        ( v ∉ Zr 且 v 在可现边中入度为 1 )。
  义务 u 在某个最大匹配中被满足 ⇔ 有匹配边或任一条可现边；
  义务 u 在**所有**最大匹配中都被满足 ⇔ 当前匹配覆盖 u 且 u ∉ Zf；
  实际身份 v 在某个最大匹配中被使用 ⇔ 有匹配边或任一条可现边；
  实际身份 v 在**所有**最大匹配中都被使用 ⇔ 当前匹配覆盖 v 且 v ∉ Zr。

因此报告能区分“这组稳定分配”与“所有最大分配都成立的事实”，不会把
任意一次匹配伪装成唯一答案。

身份事实冲突
------------
同一 representation 身份若在 sealed 事实中出现冲突（类别不一致、成员集合
不一致、或字节身份冲突），候选**不静默择一**：作为 conflict 原因逐项展示，
且分配的 package_id 置空、只给出全部相关包；质量标签沿用既有求值结果。
"""
from __future__ import annotations

import collections
import datetime
import hashlib
import json
import os

from . import diagnostics
from .db import sealed_filter
from .util import (
    REP_INCOMPLETE,
)

REPORT_PROFILE = "offline-evidence-repo/reconciliation/v1"
ENGINE_VERSION = "reconciliation/v1"

# 未满足原因（可解释、不合成单一“失败”）
R_UNSAT_NONE = "no_acceptable_representation_present"
R_UNSAT_CONFLICT = "acceptable_candidates_identity_conflict"
R_UNSAT_ALL_TAKEN = "all_acceptable_candidates_assigned_elsewhere"
R_UNSAT_MIXED = "acceptable_candidates_unavailable_or_assigned_elsewhere"

# 候选状态
C_ABSENT = "absent_from_sealed_representations"
C_CONFLICT = "identity_conflict"
C_TAKEN = "assigned_to_another_obligation"
C_AVAILABLE = "available_unassigned"
C_ASSIGNED = "assigned_to_this_obligation"


class ReconciliationError(Exception):
    pass


def _now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def _canon(obj):
    return json.dumps(
        obj, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def _sha(data):
    return hashlib.sha256(data).hexdigest()


# ===========================================================================
# 实际侧事实（只读 sealed；staging 永远不可见）
# ===========================================================================

def sealed_package_set(conn):
    return sorted(
        r[0]
        for r in conn.execute(
            "SELECT package_id FROM packages WHERE state='sealed'"
        ).fetchall()
    )


def _load_actual(conn):
    """
    返回：
      reps: {(type,value): {"package_ids": [...]}}
      conflict: {(type,value): {"kinds":[...], "package_ids":[...], ...}}
    所有查询只针对 sealed 包；按身份去重，跨包重复提及不增加节点。
    """
    reps = collections.OrderedDict()
    for r in conn.execute(
        "SELECT DISTINCT id_type, id_value, package_id FROM objects "
        "WHERE category='representation' AND " + sealed_filter("objects") +
        " ORDER BY id_type, id_value, package_id"
    ):
        key = (r["id_type"], r["id_value"])
        reps.setdefault(key, {"package_ids": []})["package_ids"].append(
            r["package_id"]
        )
    if not reps:
        return reps, {}

    # 冲突 1：同一身份在 sealed 事实中同时被声明为 representation 与 bitstream
    category_mismatch = set()
    for r in conn.execute(
        "SELECT id_type, id_value FROM objects WHERE " + sealed_filter("objects") +
        " GROUP BY id_type, id_value HAVING COUNT(DISTINCT category) > 1"
    ):
        category_mismatch.add((r["id_type"], r["id_value"]))

    # 冲突 2：同一表示身份在不同 sealed 包中声明了**不一致的成员集合**。
    # 逐包比较身份集合；完全相同的声明（迟到包重复记载同一表示）不冲突。
    member_mismatch = {}
    per_rep = collections.defaultdict(dict)  # rep -> {package_id: {members}}
    for r in conn.execute(
        "SELECT rep_id_type, rep_id_value, package_id, member_type, member_value "
        "FROM rep_members WHERE " + sealed_filter("rep_members")
    ):
        key = (r["rep_id_type"], r["rep_id_value"])
        per_rep[key].setdefault(r["package_id"], set()).add(
            (r["member_type"], r["member_value"])
        )
    for key, by_pkg in per_rep.items():
        signatures = {frozenset(m) for m in by_pkg.values()}
        if len(signatures) > 1:
            member_mismatch[key] = sorted(by_pkg)

    # 冲突 3：既有物化的位流字节身份冲突（同一身份被不同实际字节占用）
    byte_conflicts = {
        (r["id_type"], r["id_value"])
        for r in conn.execute(
            "SELECT id_type, id_value FROM object_conflicts"
        ).fetchall()
    }
    object_conflict_pkgs = {}
    for key in byte_conflicts:
        rows = conn.execute(
            "SELECT DISTINCT ob.package_id FROM object_blobs ob JOIN blobs b "
            "ON b.package_id=ob.package_id AND b.rel_path=ob.blob_rel "
            "WHERE ob.id_type=? AND ob.id_value=? AND b.state='bytes_ok' "
            "ORDER BY ob.package_id",
            key,
        ).fetchall()
        object_conflict_pkgs[key] = [r["package_id"] for r in rows]

    conflicts = {}
    for key, info in reps.items():
        kinds, details = [], {}
        if key in category_mismatch:
            kinds.append("object_category_mismatch")
            details["object_category_mismatch"] = {
                "packages": sorted(
                    r["package_id"]
                    for r in conn.execute(
                        "SELECT DISTINCT package_id FROM objects WHERE "
                        "id_type=? AND id_value=? AND " + sealed_filter("objects"),
                        key,
                    ).fetchall()
                )
            }
        if key in member_mismatch:
            kinds.append("representation_member_set_mismatch")
            details["representation_member_set_mismatch"] = {
                "packages": member_mismatch[key]
            }
        if key in byte_conflicts:
            kinds.append("byte_identity_conflict")
            details["byte_identity_conflict"] = {
                "packages": object_conflict_pkgs.get(key, [])
            }
        if kinds:
            conflicts[key] = {"kinds": kinds, "details": details}
    return reps, conflicts


# ===========================================================================
# 匹配与歧义分析
# ===========================================================================

def _hopcroft_karp(nL, adj, nR):
    """返回 (pairU, pairV)；遍历顺序固定 => 匹配结果确定。"""
    INF = float("inf")
    pairU = [-1] * nL
    pairV = [-1] * nR
    dist = [0] * nL

    def bfs():
        q = collections.deque()
        found = False
        for u in range(nL):
            if pairU[u] == -1:
                dist[u] = 0
                q.append(u)
            else:
                dist[u] = -1
        while q:
            u = q.popleft()
            for v in adj[u]:
                w = pairV[v]
                if w == -1:
                    found = True
                elif dist[w] == -1:
                    dist[w] = dist[u] + 1
                    q.append(w)
        return found

    def dfs_iter(start):
        # 显式栈的增广路 DFS（避免依赖递归深度）
        stack = [[start, 0, -1]]
        while stack:
            frame = stack[-1]
            u = frame[0]
            advanced = False
            while frame[1] < len(adj[u]):
                v = adj[u][frame[1]]
                frame[1] += 1
                w = pairV[v]
                if w == -1:
                    frame[2] = v
                    for f in stack:
                        pairU[f[0]] = f[2]
                        pairV[f[2]] = f[0]
                    return True
                if dist[w] == dist[u] + 1:
                    frame[2] = v
                    stack.append([w, 0, -1])
                    advanced = True
                    break
            if advanced:
                continue
            dist[u] = -1
            stack.pop()
        return False

    while bfs():
        for u in range(nL):
            if pairU[u] == -1 and dist[u] == 0:
                dfs_iter(u)
    return pairU, pairV


def _scc(N, fwd, rev):
    """Kosaraju 迭代版：返回每个节点的强连通分量编号。"""
    visited = [False] * N
    order = []
    for s in range(N):
        if visited[s]:
            continue
        visited[s] = True
        stack = [(s, 0)]
        while stack:
            node, idx = stack[-1]
            if idx < len(fwd[node]):
                w = fwd[node][idx]
                stack[-1] = (node, idx + 1)
                if not visited[w]:
                    visited[w] = True
                    stack.append((w, 0))
            else:
                order.append(node)
                stack.pop()
    comp = [-1] * N
    cid = 0
    for s in reversed(order):
        if comp[s] != -1:
            continue
        comp[s] = cid
        stack = [s]
        while stack:
            node = stack.pop()
            for w in rev[node]:
                if comp[w] == -1:
                    comp[w] = cid
                    stack.append(w)
        cid += 1
    return comp


def analyze_matching(nL, nR, edges, adj):
    """
    edges: set of (u, v)  [u in 0..nL-1, v in 0..nR-1]
    返回 dict，包含稳定匹配与显式歧义语义（公式见模块 docstring）。
    """
    pairU, pairV = _hopcroft_karp(nL, adj, nR)
    N = nL + nR
    fwd = [[] for _ in range(N)]
    rev = [[] for _ in range(N)]

    def add(a, b):
        fwd[a].append(b)
        rev[b].append(a)

    for (u, v) in edges:
        if pairU[u] == v:
            add(nL + v, u)          # 匹配边：R -> L
        else:
            add(u, nL + v)          # 未匹配边：L -> R

    def reach(starts, adjacency):
        seen = set(starts)
        st = list(starts)
        while st:
            x = st.pop()
            for y in adjacency[x]:
                if y not in seen:
                    seen.add(y)
                    st.append(y)
        return seen

    Zf = reach([u for u in range(nL) if pairU[u] == -1], fwd)
    Zr = reach([nL + v for v in range(nR) if pairV[v] == -1], rev)
    comp = _scc(N, fwd, rev)

    allowed = set()
    out_deg = [0] * nL
    in_deg = [0] * nR
    for (u, v) in edges:
        r = nL + v
        if pairU[u] == v or u in Zf or r in Zr or comp[u] == comp[r]:
            allowed.add((u, v))
            out_deg[u] += 1
            in_deg[v] += 1

    forced = set()
    for (u, v) in allowed:
        if (u not in Zf and out_deg[u] == 1) or (
            (nL + v) not in Zr and in_deg[v] == 1
        ):
            forced.add((u, v))

    sat_some = [pairU[u] != -1 or out_deg[u] > 0 for u in range(nL)]
    sat_all = [pairU[u] != -1 and u not in Zf for u in range(nL)]
    used_some = [pairV[v] != -1 or in_deg[v] > 0 for v in range(nR)]
    used_all = [
        pairV[v] != -1 and (nL + v) not in Zr for v in range(nR)
    ]
    return {
        "pairU": pairU,
        "pairV": pairV,
        "size": sum(1 for x in pairU if x != -1),
        "allowed": allowed,
        "forced": forced,
        "sat_some": sat_some,
        "sat_all": sat_all,
        "used_some": used_some,
        "used_all": used_all,
        "Zf": Zf,
        "Zr": Zr,
    }


# ===========================================================================
# 对账
# ===========================================================================

def _load_obligations(conn, inventory_id):
    obs = []
    for r in conn.execute(
        "SELECT obligation_id,item_id,note,source_line FROM "
        "inventory_obligations WHERE inventory_id=? ORDER BY obligation_id",
        (inventory_id,),
    ).fetchall():
        cand = [
            (c["id_type"], c["id_value"])
            for c in conn.execute(
                "SELECT id_type,id_value FROM inventory_acceptable WHERE "
                "inventory_id=? AND obligation_id=? ORDER BY ord",
                (inventory_id, r["obligation_id"]),
            ).fetchall()
        ]
        obs.append(
            {
                "obligation_id": r["obligation_id"],
                "item_id": r["item_id"],
                "note": r["note"],
                "source_line": r["source_line"],
                "candidates": cand,
            }
        )
    return obs


def _identity_obj(t, v):
    return {"identifierType": t, "identifierValue": v}


def _quality(conn, key):
    """沿用既有表示质量评估（只读；绝不因匹配而提升状态）。"""
    try:
        res = diagnostics.evaluate_representation(conn, key[0], key[1])
    except Exception as exc:  # 诊断失败不应吞成 verified
        return {
            "label": REP_INCOMPLETE,
            "reasons": ["quality assessment failed: %s" % exc],
        }
    return {"label": res["label"], "reasons": list(res["reasons"])}


def _package_view(key, reps, conflicts):
    """
    冲突时**不择一**：package_id 置空，只给出全部相关包。
    """
    pkgs = list(reps.get(key, {}).get("package_ids", []))
    if key in conflicts:
        return None, pkgs
    return (pkgs[0] if pkgs else None), pkgs


def _candidate_state(conn, key, reps, conflicts, pairV, actual_index, u,
                     obligation_ids):
    """
    返回候选的逐项状态（不静默择一冲突）。
    """
    if key not in reps:
        return {"state": C_ABSENT}
    if key in conflicts:
        return {
            "state": C_CONFLICT,
            "conflict": {
                "kinds": conflicts[key]["kinds"],
                "details": conflicts[key]["details"],
            },
        }
    v = actual_index[key]
    owner = pairV[v]
    if owner == u:
        return {"state": C_ASSIGNED}
    if owner != -1:
        return {
            "state": C_TAKEN,
            "taken_by_obligation_id": obligation_ids[owner],
        }
    return {"state": C_AVAILABLE}


def reconcile(conn, inventory_id):
    """
    对某份已导入清单执行对账。只读实际侧，只写报告；绝不改清单/包/状态。
    返回报告 dict（不含落盘）。
    """
    from .inventory import InventoryError  # 避免循环导入

    inv = conn.execute(
        "SELECT * FROM inventories WHERE inventory_id=?", (inventory_id,)
    ).fetchone()
    if inv is None:
        raise InventoryError(
            "unknown inventory_id %r" % inventory_id,
            None,
            "unknown_inventory",
        )

    obs = _load_obligations(conn, inventory_id)
    reps, conflicts = _load_actual(conn)
    actual_keys = sorted(reps.keys())
    actual_index = {k: i for i, k in enumerate(actual_keys)}
    nL, nR = len(obs), len(actual_keys)

    # 义务 -> 实际索引边（候选身份精确匹配；跨义务可重叠）
    edges = set()
    adj = [[] for _ in range(nL)]
    candidate_keys = set()
    for u, ob in enumerate(obs):
        seen_v = set()
        for key in ob["candidates"]:
            candidate_keys.add(key)
            if key in actual_index:
                v = actual_index[key]
                if v not in seen_v:
                    seen_v.add(v)
                    edges.add((u, v))
        adj[u] = sorted(seen_v)

    analysis = analyze_matching(nL, nR, edges, adj)
    pairU, pairV = analysis["pairU"], analysis["pairV"]
    allowed = analysis["allowed"]
    forced = analysis["forced"]

    assignments = []
    for u, ob in enumerate(obs):
        v = pairU[u]
        if v == -1:
            continue
        key = actual_keys[v]
        pkg_id, pkg_ids = _package_view(key, reps, conflicts)
        assignments.append(
            {
                "obligation_id": ob["obligation_id"],
                "item_id": ob["item_id"],
                "source_line": ob["source_line"],
                "representation": _identity_obj(*key),
                "package_id": pkg_id,
                "package_ids": pkg_ids,
                "quality": _quality(conn, key),
                "identity_conflict": (
                    {
                        "kinds": conflicts[key]["kinds"],
                        "details": conflicts[key]["details"],
                    }
                    if key in conflicts
                    else None
                ),
                "stable_across_all_maximum_assignments": (u, v) in forced,
                "may_change_between_maximum_assignments": (u, v) not in forced,
            }
        )
    assignments.sort(key=lambda a: a["obligation_id"])

    unsatisfied = []
    obligation_ids = [o["obligation_id"] for o in obs]
    for u, ob in enumerate(obs):
        if pairU[u] != -1:
            continue
        cand_states = []
        present = conflict_any = taken_any = absent_any = available_any = False
        for key in ob["candidates"]:
            st = _candidate_state(
                conn, key, reps, conflicts, pairV, actual_index, u,
                obligation_ids,
            )
            entry = {"representation": _identity_obj(*key), **st}
            if st["state"] == C_ABSENT:
                absent_any = True
            elif st["state"] == C_CONFLICT:
                conflict_any = True
                present = True
            elif st["state"] == C_TAKEN:
                taken_any = True
                present = True
            elif st["state"] == C_AVAILABLE:
                available_any = True
                present = True
            cand_states.append(entry)
        if not present:
            code = R_UNSAT_NONE
        elif conflict_any and not taken_any and not absent_any and not available_any:
            code = R_UNSAT_CONFLICT
        elif taken_any and not conflict_any and not absent_any and not available_any:
            code = R_UNSAT_ALL_TAKEN
        else:
            code = R_UNSAT_MIXED
        unsatisfied.append(
            {
                "obligation_id": ob["obligation_id"],
                "item_id": ob["item_id"],
                "source_line": ob["source_line"],
                "reason_code": code,
                "satisfiable_in_some_maximum_assignment": bool(
                    analysis["sat_some"][u]
                ),
                "satisfied_in_all_maximum_assignments": bool(
                    analysis["sat_all"][u]
                ),
                "ambiguous": bool(
                    analysis["sat_some"][u] and not analysis["sat_all"][u]
                ),
                "candidates": cand_states,
            }
        )
    unsatisfied.sort(key=lambda a: a["obligation_id"])

    # 歧义义务：某些最大分配满足、某些不满足
    ambiguous_obligations = []
    for u, ob in enumerate(obs):
        if analysis["sat_some"][u] and not analysis["sat_all"][u]:
            possible = sorted(
                actual_keys[v] for (uu, v) in allowed if uu == u
            )
            ambiguous_obligations.append(
                {
                    "obligation_id": ob["obligation_id"],
                    "item_id": ob["item_id"],
                    "source_line": ob["source_line"],
                    "satisfied_in_stable_assignment": pairU[u] != -1,
                    "satisfiable_in_some_maximum_assignment": True,
                    "satisfied_in_all_maximum_assignments": False,
                    "possible_representations": [
                        _identity_obj(*k) for k in possible
                    ],
                }
            )
    ambiguous_obligations.sort(key=lambda a: a["obligation_id"])

    # 可变的分配边（出现在某些最大分配、但非全部）
    ambiguous_edges = []
    for (u, v) in sorted(allowed):
        if (u, v) in forced:
            continue
        ambiguous_edges.append(
            {
                "obligation_id": obs[u]["obligation_id"],
                "representation": _identity_obj(*actual_keys[v]),
                "in_stable_assignment": pairU[u] == v,
                "assignable_in_some_maximum_assignment": True,
                "assignable_in_all_maximum_assignments": False,
            }
        )

    # 额外表示：清单任何义务都未预期（不在候选中），且未被分配
    extras = []
    for key in actual_keys:
        if key in candidate_keys:
            continue
        pkg_id, pkg_ids = _package_view(key, reps, conflicts)
        extras.append(
            {
                "representation": _identity_obj(*key),
                "package_id": pkg_id,
                "package_ids": pkg_ids,
                "quality": _quality(conn, key),
                "identity_conflict": (
                    {
                        "kinds": conflicts[key]["kinds"],
                        "details": conflicts[key]["details"],
                    }
                    if key in conflicts
                    else None
                ),
            }
        )

    # 身份冲突清单（候选或额外中出现）
    identity_conflicts = []
    for key in sorted(conflicts):
        if key not in reps:
            continue
        identity_conflicts.append(
            {
                "representation": _identity_obj(*key),
                "package_ids": list(reps[key]["package_ids"]),
                "kinds": conflicts[key]["kinds"],
                "details": conflicts[key]["details"],
            }
        )

    pkg_set = sealed_package_set(conn)
    pkg_set_sha = _sha(_canon(pkg_set))

    summary = {
        "obligation_total": nL,
        "satisfied": analysis["size"],
        "unsatisfied": nL - analysis["size"],
        "ambiguous": len(ambiguous_obligations),
        "extra": len(extras),
        "always_satisfied": sum(1 for x in analysis["sat_all"] if x),
        "satisfiable_in_some_maximum_assignment": sum(
            1 for x in analysis["sat_some"] if x
        ),
        "ambiguous_edges": len(ambiguous_edges),
        "identity_conflicts": len(identity_conflicts),
        "maximum_matching_size": analysis["size"],
        "actual_representation_identities": nR,
    }
    # 汇总自洽检查（义务总数 = 满足 + 未满足）
    assert summary["satisfied"] + summary["unsatisfied"] == summary["obligation_total"]

    return {
        "profile": REPORT_PROFILE,
        "engine": ENGINE_VERSION,
        "inputs": {
            "inventory": {
                "inventory_id": inv["inventory_id"],
                "format_version": inv["format_version"],
                "source_sha256": inv["source_sha256"],
                "source_bytes": inv["source_bytes"],
                "obligation_count": inv["obligation_count"],
                "item_count": inv["item_count"],
            },
            "sealed": {
                "package_set": pkg_set,
                "package_set_sha256": pkg_set_sha,
            },
        },
        "semantics": {
            "matching": "maximum_one_to_one_bipartite",
            "ambiguity": "alternating_reachability_plus_scc",
            "identity": "identifierType+identifierValue exact tuple",
            "actual_side": "sealed representation identities only",
            "quality": "inherited from existing provenance/bytes evaluator; "
                       "never promoted by reconciliation",
        },
        "summary": summary,
        "assignments": assignments,
        "unsatisfied_obligations": unsatisfied,
        "ambiguous_obligations": ambiguous_obligations,
        "ambiguous_edges": ambiguous_edges,
        "extra_representations": extras,
        "identity_conflicts": identity_conflicts,
    }


# ===========================================================================
# 报告落盘 / 内容寻址 / 独立校验
# ===========================================================================

def _content_for_hash(report):
    """参与内容寻址的业务事实（排除时间戳与自身 ID）。"""
    return {k: v for k, v in report.items() if k not in ("generated_at", "report_id", "content_sha256")}


def report_content_sha256(report):
    return _sha(_canon(_content_for_hash(report)))


def _report_rel_path(report_id):
    return "reports/recon-%s.json" % report_id


def reconcile_and_store(conn, repo_root, inventory_id):
    """
    对账并落盘。相同清单 + 相同 sealed 包集合 => 相同 report_id，
    复用既有报告（不重写文件）；否则产生新报告。旧报告只增不改。
    """
    report = reconcile(conn, inventory_id)
    report["generated_at"] = _now()
    content_sha = report_content_sha256(report)
    report["content_sha256"] = content_sha
    report["report_id"] = content_sha

    existing = conn.execute(
        "SELECT report_no,report_path FROM reconciliation_reports "
        "WHERE report_id=?",
        (content_sha,),
    ).fetchone()
    if existing is not None:
        return {
            "report_id": content_sha,
            "report_no": existing["report_no"],
            "report_path": existing["report_path"],
            "summary": report["summary"],
            "reused": True,
        }

    body = json.dumps(
        report, ensure_ascii=False, sort_keys=True, indent=2
    ).encode("utf-8") + b"\n"
    rel = _report_rel_path(content_sha)
    abs_path = os.path.join(repo_root, rel)
    os.makedirs(os.path.dirname(abs_path), exist_ok=True)
    tmp = abs_path + ".tmp-%d" % os.getpid()
    with open(tmp, "wb") as f:
        f.write(body)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, abs_path)

    conn.execute(
        "INSERT INTO reconciliation_reports(report_id,inventory_id,"
        "inventory_sha256,package_set_sha256,content_sha256,created_at,"
        "report_path) VALUES(?,?,?,?,?,?,?)",
        (
            content_sha,
            inventory_id,
            report["inputs"]["inventory"]["source_sha256"],
            report["inputs"]["sealed"]["package_set_sha256"],
            content_sha,
            report["generated_at"],
            rel,
        ),
    )
    conn.commit()
    row = conn.execute(
        "SELECT report_no FROM reconciliation_reports WHERE report_id=?",
        (content_sha,),
    ).fetchone()
    return {
        "report_id": content_sha,
        "report_no": row["report_no"],
        "report_path": rel,
        "summary": report["summary"],
        "reused": False,
    }


def load_report(conn, repo_root, report_id):
    row = conn.execute(
        "SELECT * FROM reconciliation_reports WHERE report_id=?", (report_id,)
    ).fetchone()
    if row is None:
        raise ReconciliationError("unknown report_id %r" % report_id)
    path = os.path.join(repo_root, row["report_path"])
    with open(path, "rb") as f:
        doc = json.load(f)
    return doc


def list_reports(conn, inventory_id=None):
    sql = (
        "SELECT r.report_no,r.report_id,r.inventory_id,r.inventory_sha256,"
        "r.package_set_sha256,r.created_at,r.report_path,"
        "i.source_sha256 FROM reconciliation_reports r "
        "JOIN inventories i ON i.inventory_id=r.inventory_id"
    )
    args = ()
    if inventory_id is not None:
        sql += " WHERE r.inventory_id=?"
        args = (inventory_id,)
    sql += " ORDER BY r.report_no"
    return [dict(r) for r in conn.execute(sql, args).fetchall()]


def verify_report(report_path):
    """
    独立校验报告文件：重算内容哈希与输入绑定，不访问仓、不用匹配函数。
    报告可任意搬迁（内部无绝对路径）。
    """
    report_path = os.path.abspath(report_path)
    errors, checks = [], []
    if os.path.isdir(report_path):
        cand = os.path.join(report_path, "report.json")
        report_path = cand
    if not os.path.isfile(report_path):
        return {
            "ok": False,
            "errors": ["report file missing: %s" % os.path.basename(report_path)],
            "checks": [],
        }
    with open(report_path, "rb") as f:
        raw = f.read()
    try:
        doc = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        return {"ok": False, "errors": ["invalid report JSON: %s" % exc],
                "checks": []}

    for field in ("report_id", "content_sha256", "profile", "inputs",
                  "summary", "assignments", "unsatisfied_obligations",
                  "ambiguous_obligations", "ambiguous_edges",
                  "extra_representations"):
        if field not in doc:
            errors.append("missing required field %r" % field)
    if "generated_at" not in doc:
        errors.append("missing required field 'generated_at'")

    if not errors:
        recomputed = report_content_sha256(doc)
        checks.append("recomputed report content SHA-256")
        if recomputed != doc.get("content_sha256"):
            errors.append(
                "content_sha256 mismatch: stored=%s recomputed=%s"
                % (doc.get("content_sha256"), recomputed)
            )
        if recomputed != doc.get("report_id"):
            errors.append(
                "report_id is not the content address: stored=%s recomputed=%s"
                % (doc.get("report_id"), recomputed)
            )

        inv = doc["inputs"].get("inventory", {})
        sealed = doc["inputs"].get("sealed", {})
        for field in ("inventory_id", "format_version", "source_sha256"):
            if field not in inv:
                errors.append("inventory input binding missing %r" % field)
        if "package_set" not in sealed or "package_set_sha256" not in sealed:
            errors.append("sealed package set binding missing")
        else:
            ps = sealed["package_set"]
            ps_sha = _sha(_canon(ps))
            if ps_sha != sealed["package_set_sha256"]:
                errors.append(
                    "sealed package set SHA-256 mismatch: stored=%s recomputed=%s"
                    % (sealed["package_set_sha256"], ps_sha)
                )
            if ps != sorted(ps):
                errors.append("sealed package set is not sorted")
        checks.append("inventory SHA-256 and sealed package set binding verified")

        # 汇总自洽
        s = doc["summary"]
        if s.get("satisfied", 0) + s.get("unsatisfied", 0) != s.get(
            "obligation_total", -1
        ):
            errors.append(
                "summary inconsistent: satisfied+unsatisfied != obligation_total"
            )
        if s.get("extra") != len(doc.get("extra_representations", [])):
            errors.append("summary.extra != len(extra_representations)")
        if s.get("ambiguous") != len(doc.get("ambiguous_obligations", [])):
            errors.append("summary.ambiguous != len(ambiguous_obligations)")
        if s.get("ambiguous_edges") != len(doc.get("ambiguous_edges", [])):
            errors.append("summary.ambiguous_edges != len(ambiguous_edges)")
        if s.get("satisfied") != len(doc.get("assignments", [])):
            errors.append("summary.satisfied != len(assignments)")
        if s.get("identity_conflicts") != len(doc.get("identity_conflicts", [])):
            errors.append("summary.identity_conflicts != len(identity_conflicts)")
        checks.append("summary counts cross-checked against item lists")

        # 质量标签不得被对账提升：只允许既有四标签
        allowed_labels = {
            "verified", "incomplete", "invalid", "unproven"
        }
        for a in doc.get("assignments", []):
            label = a.get("quality", {}).get("label")
            if label not in allowed_labels:
                errors.append(
                    "assignment %r has unknown quality label %r"
                    % (a.get("obligation_id"), label)
                )
        checks.append("assignment quality labels limited to existing vocabulary")

        # 报告内不得出现文件系统绝对路径（身份值本身可能是 URI/路径形态，
        # 属于业务事实，不在此限制；其余字段一律不得携带绝对路径）。
        identity_keys = {"identifierValue", "identifierType", "inventory_id",
                         "obligation_id", "item_id", "package_id",
                         "taken_by_obligation_id"}
        bad_paths = []

        def _walk(node):
            if isinstance(node, dict):
                for k, v in node.items():
                    if (isinstance(v, str) and v.startswith("/")
                            and k not in identity_keys):
                        bad_paths.append((k, v))
                    elif isinstance(v, list) and k == "package_set":
                        pass
                    else:
                        _walk(v)
            elif isinstance(node, list):
                for x in node:
                    _walk(x)

        _walk(doc)
        if bad_paths:
            errors.append(
                "report contains absolute filesystem path(s) in non-identity "
                "fields: %r" % (bad_paths[:4],)
            )
        checks.append("report contains no workflow-dependent absolute paths")

    return {
        "ok": not errors,
        "report_id": doc.get("report_id"),
        "content_sha256": doc.get("content_sha256"),
        "inventory_id": doc.get("inputs", {}).get("inventory", {}).get(
            "inventory_id"
        ),
        "sealed_package_set": doc.get("inputs", {}).get("sealed", {}).get(
            "package_set"
        ),
        "summary": doc.get("summary"),
        "checks": checks,
        "errors": errors,
    }
