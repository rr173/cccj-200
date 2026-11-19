# -*- coding: utf-8 -*-
"""
谱系诊断（只读 sealed 物化事实）。

- explain_object：以 AND/OR 依赖树说明一个 bitstream 为何 proven / 未 proven，
  每条缺失证据逐项给出原因，绝不把多种原因合成一个“失败”。
- evaluate_representation：按题目四标签判定，并列出逐项原因。
- 结构节点只引用表示，同一 bitstream 被多处展示不会重复计数（成员按身份去重）。
"""
from __future__ import annotations

from . import evaluate as ev
from .util import (
    REP_INCOMPLETE,
    REP_INVALID,
    REP_UNPROVEN,
    REP_VERIFIED,
    ST_BYTES_CORRUPT,
    ST_BYTES_MISSING,
    ST_BYTES_OK,
    ST_IDENTITY_CONFLICT,
    ST_NOT_RECEIVED,
)


def explain_object(conn, id_type, id_value, _stack=None):
    """
    返回依赖解释 dict：
      {identity, state, proven, chosen_event, candidate_events:[...], reasons:[...]}
    环按“支路路径”判定：同一对象可能经一条有限路径可证，而在另一条候选支路中
    成环（如 C<-G<-D<-F<-C）。_stack 沿当前候选支路传递，循环支路标记
    cycle=true 且不能自证，但不否决其他独立好路径。
    """
    if _stack is None:
        _stack = set()
    key = (id_type, id_value)
    if key in _stack:
        return {
            "id_type": id_type,
            "id_value": id_value,
            "state": "cycle",
            "proven": False,
            "cycle": True,
            "reasons": ["cyclic dependency branch cannot self-prove"],
        }

    state, proven = ev.object_state(conn, id_type, id_value)
    node = {
        "id_type": id_type,
        "id_value": id_value,
        "state": state,
        "proven": proven,
        "candidate_events": [],
        "chosen_event": None,
        "reasons": [],
    }
    _stack.add(key)
    try:
        if state == ST_IDENTITY_CONFLICT:
            node["reasons"].append("object identity occupied by different actual bytes")
        elif state in (ST_BYTES_MISSING, ST_NOT_RECEIVED):
            node["reasons"].append("bytes_missing: no received copy passed integrity check")
        elif state == ST_BYTES_CORRUPT:
            node["reasons"].append("bytes_corrupt: SHA-256 does not match manifest")

        candidates = ev.valid_events_producing(conn, id_type, id_value)
        good_branch = None
        for e in candidates:
            branch = _explain_event_branch(conn, e, _stack)
            node["candidate_events"].append(branch)
            # 好支路 = 全部输入可证 且 支路内无循环自证
            if (branch["all_inputs_proven"] and not branch["contains_cycle"]
                    and good_branch is None):
                good_branch = branch
        if good_branch is not None:
            node["chosen_event"] = good_branch["event_id"]
        elif state == ST_BYTES_OK and not candidates:
            node["reasons"].append(
                "no valid event produces this object; no path to a trusted ingest root"
            )
        elif state == ST_BYTES_OK and candidates:
            node["reasons"].append(
                "all producing events have unproven/failed/cyclic inputs; see candidate details"
            )
    finally:
        _stack.discard(key)
    return node


def _explain_event_branch(conn, event_row, stack):
    eid = event_row["event_id"]
    inputs = ev.event_inputs(conn, eid)
    input_nodes = []
    all_in = True
    for it, iv in inputs:
        # 沿当前候选支路继续展开（带上路径栈），这样 C<-G<-D<-F<-C
        # 这种跨多事件的环才能在支路评估中被识别
        child = explain_object(conn, it, iv, stack)
        input_nodes.append(child)
        if not child["proven"]:
            all_in = False
    return {
        "event_id": eid,
        "event_type": event_row,
        "package_id": event_row["package_id"],
        "xml_rel": event_row["xml_rel"],
        "inputs": input_nodes,
        "all_inputs_proven": all_in,
        "contains_cycle": any(_branch_has_cycle(n) for n in input_nodes),
    }


def _branch_has_cycle(node):
    """递归判断一个解释子树内是否出现循环支路。"""
    if node.get("cycle"):
        return True
    for cand in node.get("candidate_events", []):
        if cand.get("contains_cycle"):
            return True
        for sub in cand.get("inputs", []):
            if _branch_has_cycle(sub):
                return True
    return False


def invalid_event_reasons(conn, event_id):
    """对非有效事件逐项列出失效原因（诊断用，独立于求值器的布尔结果）。"""
    reasons = []
    rows = conn.execute(
        "SELECT * FROM events WHERE event_id=?", (event_id,)
    ).fetchall()
    if not rows:
        return ["event not present in any sealed package"]
    conflict = conn.execute(
        "SELECT 1 FROM event_conflicts WHERE event_id=?", (event_id,)
    ).fetchone()
    if conflict:
        reasons.append("event identifier conflict: same id, different canonical content")
    if len({(r["package_id"], r["c14n_sha256"]) for r in rows}) > 1 and not conflict:
        reasons.append("ambiguous event records")
    r = rows[0]
    if r["event_type"] not in ("ingest", "copy", "migration"):
        reasons.append("unsupported event type %r (retained as fact, never evidence)"
                       % r["event_type"])
    if r["outcome"] != "success":
        reasons.append("event outcome is %r, not success" % r["outcome"])
    inputs = ev.event_inputs(conn, event_id)
    outputs = ev.event_outputs(conn, event_id)
    if r["event_type"] == "ingest" and inputs:
        reasons.append("ingest event must have no input objects")
    if r["event_type"] in ("copy", "migration") and not inputs:
        reasons.append("%s event requires at least one explicit input role"
                       % r["event_type"])
    if not outputs:
        reasons.append("event requires at least one explicit output role")
    if r["event_type"] == "ingest":
        trusted = conn.execute(
            "SELECT 1 FROM trusted_ingest t WHERE t.event_id=? AND "
            "t.package_id IN (SELECT package_id FROM packages WHERE state='sealed')",
            (event_id,),
        ).fetchone()
        if not trusted:
            reasons.append("ingest event id is not on caller-provided trust list")
    for it, iv in inputs + outputs:
        state, _ = ev.object_state(conn, it, iv)
        if state == ST_NOT_RECEIVED:
            reasons.append("linked object %s/%s not received" % (it, iv))
        elif state == ST_IDENTITY_CONFLICT:
            reasons.append("linked object %s/%s has identity conflict" % (it, iv))
    for it, iv in outputs:
        state, _ = ev.object_state(conn, it, iv)
        if state in (ST_BYTES_MISSING, ST_NOT_RECEIVED):
            reasons.append("output %s/%s bytes_missing" % (it, iv))
        elif state == ST_BYTES_CORRUPT:
            reasons.append("output %s/%s bytes_corrupt" % (it, iv))
    return reasons


def evaluate_representation(conn, rep_id_type, rep_id_value):
    """
    返回 representation 评估：
      label ∈ verified|incomplete|invalid|unproven
      members: 去重后的成员身份及各自状态；reasons: 逐项原因；
      explanations: 每成员的 AND/OR 解释树。
    """
    rows = conn.execute(
        """
        SELECT DISTINCT member_type, member_value
        FROM rep_members
        WHERE rep_id_type=? AND rep_id_value=?
          AND package_id IN (SELECT package_id FROM packages WHERE state='sealed')
        ORDER BY member_type, member_value
        """,
        (rep_id_type, rep_id_value),
    ).fetchall()
    if not rows:
        return {
            "id_type": rep_id_type,
            "id_value": rep_id_value,
            "label": REP_INCOMPLETE,
            "reasons": ["representation not present in any sealed package"],
            "members": [],
        }

    members, reasons, explanations = [], [], []
    has_invalid = has_incomplete = has_unproven = False
    for r in rows:
        mt, mv = r["member_type"], r["member_value"]
        state, proven = ev.object_state(conn, mt, mv)
        expl = explain_object(conn, mt, mv)
        explanations.append(expl)
        members.append(
            {"id_type": mt, "id_value": mv, "state": state, "origin_proven": proven}
        )
        if state == ST_IDENTITY_CONFLICT:
            has_invalid = True
            reasons.append("member %s/%s identity_conflict" % (mt, mv))
        elif state == ST_BYTES_CORRUPT:
            has_invalid = True
            reasons.append("member %s/%s bytes_corrupt" % (mt, mv))
        elif state in (ST_BYTES_MISSING, ST_NOT_RECEIVED):
            has_incomplete = True
            reasons.append("member %s/%s %s" % (mt, mv, state))
        elif state == ST_BYTES_OK and not proven:
            has_unproven = True
            reasons.append(
                "member %s/%s bytes_ok but no complete provenance path" % (mt, mv)
            )
            for cr in expl["reasons"]:
                reasons.append("  └ %s/%s: %s" % (mt, mv, cr))

    # 标签优先级：invalid > incomplete > unproven > verified；原因全部保留
    if has_invalid:
        label = REP_INVALID
    elif has_incomplete:
        label = REP_INCOMPLETE
    elif has_unproven:
        label = REP_UNPROVEN
    else:
        label = REP_VERIFIED
    return {
        "id_type": rep_id_type,
        "id_value": rep_id_value,
        "label": label,
        "reasons": reasons,
        "members": members,
        "explanations": explanations,
    }


def list_representations(conn):
    rows = conn.execute(
        """
        SELECT DISTINCT id_type, id_value FROM objects
        WHERE category='representation'
          AND package_id IN (SELECT package_id FROM packages WHERE state='sealed')
        ORDER BY id_type, id_value
        """
    ).fetchall()
    return [dict(r) for r in rows]


def get_struct_node(conn, node_id):
    return conn.execute(
        "SELECT * FROM struct_nodes WHERE node_id=? AND "
        "package_id IN (SELECT package_id FROM packages WHERE state='sealed')",
        (node_id,),
    ).fetchall()
