# -*- coding: utf-8 -*-
"""
离线发布的馆内计划构建（只读取 sealed 事实视图；staging 完全不可见）。

核心语义（见 profile.md §15）：

1. **一致事实视图**：一次计划读取当时的 sealed 包集合，包集合哈希写入计划
   绑定。用既有 rep_members/object_blobs/obj_status 成员关系展开完整表示，
   合并跨包相同声明；成员集合互相矛盾、成员缺失/字节不可用/身份冲突时，
   整份表示暂缓并逐项给出原因。

2. **按内容统一落实规则**：相同字节的不同对象是不同身份，因此对计划涉及的
   每个内容摘要，纳入本次 sealed 视图中**所有**关联该摘要的 bytes_ok
   bitstream 身份（含未选表示中的别名）。任一身份缺规则或明确 hold，
   该内容整体暂缓；否则取全部 redact 区间并集；全部 release 才放行原字节。

3. **错误分层**：缺规则是**业务暂缓**（计划照常生成、逐项记录）；
   规则语法错误在 release_rules 阶段整体拒绝（计划失败）；
   遮盖规则无法成立（摘要不符、非 UTF-8、端点不对齐等）记为 blocked，
   计划保留可审计记录，但阻止产生可发布结果。

4. **可重现**：计划内嵌请求与规则的完整解析内容、来源哈希与 sealed 包集合，
   plan_id 为业务内容寻址；相同输入 + 相同包集合得到相同 plan_id。
"""
from __future__ import annotations

import datetime
import hashlib
import hmac
import json
import os

from . import redaction as red
from .db import sealed_filter
from .release_rules import (
    ACTION_HOLD,
    ACTION_REDACT,
    ACTION_RELEASE,
    parse_request_and_rules,
    merge_ranges,
    ReleaseInputError,
)
from .util import (
    ST_BYTES_CORRUPT,
    ST_BYTES_MISSING,
    ST_IDENTITY_CONFLICT,
    ST_NOT_RECEIVED,
)

PLAN_PROFILE = "offline-evidence-repo/release-plan/v1"
PLAN_ENGINE = "release-plan/v1"

# 表示级决定
REP_DELIVER = "deliverable"
REP_HOLD = "held"
# 内容级决定
CONTENT_RELEASE = "release"
CONTENT_REDACT = "redact"
CONTENT_HOLD = "held"
CONTENT_BLOCKED = "blocked"

# 原因码（逐项、稳定，供馆内定位）
R_REP_NOT_SEALED = "representation_not_in_sealed_view"
R_REP_CATEGORY_MISMATCH = "representation_category_mismatch"
R_REP_MEMBER_SET_CONFLICT = "representation_member_set_conflict"
R_MEMBER_IDENTITY_CONFLICT = "member_identity_conflict"
R_MEMBER_BYTES_CORRUPT = "member_bytes_corrupt"
R_MEMBER_BYTES_MISSING = "member_bytes_missing"
R_MEMBER_NOT_RECEIVED = "member_not_received"
R_MEMBER_NOT_BITSTREAM = "member_not_a_bitstream"
R_CONTENT_NO_RULE = "alias_bitstream_without_rule"
R_CONTENT_HOLD_RULE = "alias_bitstream_explicit_hold"
R_CONTENT_BOUND_DIGEST_MISMATCH = "redaction_bound_digest_mismatch"
R_CONTENT_NOT_UTF8 = "redaction_content_not_valid_utf8"
R_CONTENT_RANGE_INVALID = "redaction_range_not_establishable"


class PlanError(Exception):
    pass


def _now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def _canon(obj):
    return json.dumps(
        obj, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def sealed_package_set(conn):
    return sorted(
        r[0]
        for r in conn.execute(
            "SELECT package_id FROM packages WHERE state='sealed' ORDER BY package_id"
        ).fetchall()
    )


# ---------------------------------------------------------------------------
# 表示事实展开（合并跨包声明；显式识别矛盾，绝不静默择一）
# ---------------------------------------------------------------------------

def _representation_facts(conn, id_type, id_value):
    """
    返回 (facts, reasons)。facts:
      {"packages":[...], "member_sets": {pkg: [[t,v]...]},
       "members": [(t,v)...] 合并去重排序, "category_ok": bool}
    """
    rows = conn.execute(
        "SELECT DISTINCT package_id, category FROM objects "
        "WHERE id_type=? AND id_value=? AND " + sealed_filter("objects") +
        " ORDER BY package_id",
        (id_type, id_value),
    ).fetchall()
    facts = {
        "packages": [r["package_id"] for r in rows],
        "member_sets": {},
        "members": [],
        "category_ok": all(r["category"] == "representation" for r in rows)
        and len(rows) > 0,
    }
    if not rows:
        return facts, [R_REP_NOT_SEALED]
    if not facts["category_ok"]:
        return facts, [R_REP_CATEGORY_MISMATCH]
    mrows = conn.execute(
        "SELECT package_id, member_type, member_value FROM rep_members "
        "WHERE rep_id_type=? AND rep_id_value=? AND "
        + sealed_filter("rep_members")
        + " ORDER BY package_id, ord",
        (id_type, id_value),
    ).fetchall()
    union = set()
    for r in mrows:
        facts["member_sets"].setdefault(r["package_id"], []).append(
            [r["member_type"], r["member_value"]]
        )
        union.add((r["member_type"], r["member_value"]))
    signatures = {
        frozenset(tuple(x) for x in members)
        for members in facts["member_sets"].values()
    }
    facts["members"] = sorted(union)
    reasons = []
    if len(signatures) > 1:
        reasons.append(R_REP_MEMBER_SET_CONFLICT)
    if not facts["members"]:
        # sealed 中有 representation 对象但没有任何成员声明：视为不完整
        reasons.append(R_REP_NOT_SEALED)
    return facts, reasons


def _member_state_row(conn, key):
    return conn.execute(
        "SELECT state, proven FROM obj_status WHERE id_type=? AND id_value=?",
        key,
    ).fetchone()


def _member_categories(conn, key):
    return {
        r["category"]
        for r in conn.execute(
            "SELECT DISTINCT category FROM objects WHERE id_type=? AND id_value=? "
            "AND " + sealed_filter("objects"),
            key,
        ).fetchall()
    }


# ---------------------------------------------------------------------------
# 内容（字节摘要）反查：单次查询覆盖全部相关摘要，避免逐表示全仓扫描
# ---------------------------------------------------------------------------

def _bytes_ok_blobs_for_digests(conn, digests):
    """
    一次查询返回关联给定摘要集合的全部 sealed bytes_ok 身份与存储记录。
    返回 {digest: [ {identity, package_id, blob_rel, stored_path, size}, ... ]}
    游标流式取用，调用方只保留与本次计划相关的有界行集。
    """
    out = {d: [] for d in digests}
    if not digests:
        return out
    # 用 TEMP 表做有界连接，避免 IN 列表过长
    conn.execute("DROP TABLE IF EXISTS tmp_rel_digests")
    conn.execute(
        "CREATE TEMP TABLE tmp_rel_digests(digest TEXT PRIMARY KEY) WITHOUT ROWID"
    )
    conn.executemany(
        "INSERT INTO tmp_rel_digests(digest) VALUES(?)",
        [(d,) for d in digests],
    )
    try:
        cur = conn.execute(
            """
            SELECT ob.id_type AS id_type, ob.id_value AS id_value,
                   b.actual_sha AS digest, b.package_id AS package_id,
                   b.rel_path AS blob_rel, b.stored_path AS stored_path,
                   b.size_actual AS size
            FROM object_blobs ob
            JOIN blobs b
              ON b.package_id = ob.package_id AND b.rel_path = ob.blob_rel
            JOIN tmp_rel_digests d ON d.digest = b.actual_sha
            WHERE b.state = 'bytes_ok' AND """
            + sealed_filter("b")
            + """
            ORDER BY b.actual_sha, ob.id_type, ob.id_value, b.package_id, b.rel_path
            """
        )
        for r in cur:
            out[r["digest"]].append(dict(r))
    finally:
        conn.execute("DROP TABLE IF EXISTS tmp_rel_digests")
    return out


def _digests_of_members(conn, member_keys):
    """成员身份 -> 一份 bytes_ok 摘要（bytes_ok 身份取稳定第一条）。"""
    result = {}
    for key in member_keys:
        row = conn.execute(
            """
            SELECT b.actual_sha AS digest, b.size_actual AS size,
                   b.stored_path AS stored_path, b.package_id AS package_id,
                   b.rel_path AS blob_rel
            FROM object_blobs ob
            JOIN blobs b ON b.package_id=ob.package_id AND b.rel_path=ob.blob_rel
            WHERE ob.id_type=? AND ob.id_value=? AND b.state='bytes_ok' AND """
            + sealed_filter("b")
            + """
            ORDER BY b.package_id, b.rel_path LIMIT 1
            """,
            key,
        ).fetchone()
        if row is not None:
            result[key] = dict(row)
    return result


# ---------------------------------------------------------------------------
# 计划构建
# ---------------------------------------------------------------------------

def build_plan(conn, repo_root, request_path, rules_path):
    """
    解析输入（语法错误直接抛 ReleaseInputError，不落任何计划），
    读取 sealed 视图，产出馆内计划 dict 并落盘、登记表。
    相同业务输入复用同一 plan_id（只增不改）。
    """
    request, rules_doc = parse_request_and_rules(request_path, rules_path)
    rules = rules_doc["rules"]

    pkg_set = sealed_package_set(conn)
    pkg_set_sha = _sha(_canon(pkg_set))

    # ---- 第一步：逐表示做成员检查，收集 bytes_ok 成员的摘要 ---------------
    rep_records = []
    member_keys_all = set()
    for sel in request["selections"]:
        key = (sel["id_type"], sel["id_value"])
        facts, fact_reasons = _representation_facts(conn, *key)
        rep_rec = {
            "identity": {"identifierType": key[0], "identifierValue": key[1]},
            "external_code": sel["external_code"],
            "request_line": sel["source_line"],
            "decision": REP_DELIVER,
            "sealed_packages": facts["packages"],
            "member_set_conflict":
                R_REP_MEMBER_SET_CONFLICT in fact_reasons,
            "reasons": list(fact_reasons),
            "member_checks": [],
            "content_digests": [],
        }
        for mk in facts["members"]:
            member_keys_all.add(mk)
            check = {
                "identity": {"identifierType": mk[0], "identifierValue": mk[1]},
                "state": None,
                "origin_proven": None,
                "reasons": [],
            }
            cats = _member_categories(conn, mk)
            if cats and "bitstream" not in cats:
                check["reasons"].append(R_MEMBER_NOT_BITSTREAM)
            row = _member_state_row(conn, mk)
            if row is None:
                check["state"] = ST_NOT_RECEIVED
                check["reasons"].append(R_MEMBER_NOT_RECEIVED)
            else:
                check["state"] = row["state"]
                check["origin_proven"] = bool(row["proven"])
                if row["state"] == ST_IDENTITY_CONFLICT:
                    check["reasons"].append(R_MEMBER_IDENTITY_CONFLICT)
                elif row["state"] == ST_BYTES_CORRUPT:
                    check["reasons"].append(R_MEMBER_BYTES_CORRUPT)
                elif row["state"] == ST_BYTES_MISSING:
                    check["reasons"].append(R_MEMBER_BYTES_MISSING)
                elif row["state"] == ST_NOT_RECEIVED:
                    check["reasons"].append(R_MEMBER_NOT_RECEIVED)
            rep_rec["member_checks"].append(check)
        if rep_rec["reasons"] or any(
            c["reasons"] for c in rep_rec["member_checks"]
        ):
            rep_rec["decision"] = REP_HOLD
        rep_records.append(rep_rec)

    # ---- 第二步：成员摘要 -> 全 sealed 视图别名反查（一次查询）------------
    member_blob = _digests_of_members(conn, sorted(member_keys_all))
    relevant_digests = sorted({v["digest"] for v in member_blob.values()})
    alias_index = _bytes_ok_blobs_for_digests(conn, relevant_digests)

    # 表示 -> 内容摘要（只挂该表示 bytes_ok 成员实际承载的摘要）
    for rep_rec in rep_records:
        digests = []
        for check in rep_rec["member_checks"]:
            mk = (check["identity"]["identifierType"],
                  check["identity"]["identifierValue"])
            if mk in member_blob:
                digests.append(member_blob[mk]["digest"])
        rep_rec["content_digests"] = sorted(set(digests))

    # ---- 第三步：逐内容合并全部别名身份上的规则 ---------------------------
    content_records = {}
    for digest in relevant_digests:
        aliases = alias_index.get(digest, [])
        rec = {
            "content_sha256": digest,
            "length": aliases[0]["size"] if aliases else None,
            "decision": None,
            "aliases": [
                {
                    "identifierType": a["id_type"],
                    "identifierValue": a["id_value"],
                    "package_id": a["package_id"],
                }
                for a in aliases
            ],
            "alias_rule_actions": {},   # 身份 -> 动作（含来源行）
            "merged_redaction_ranges": [],
            "bound_digests": [],
            "reasons": [],
            "blocked": False,
        }
        actions, all_ranges, bound = [], [], []
        for a in aliases:
            akey = (a["id_type"], a["id_value"])
            rule = rules.get(akey)
            if rule is None:
                rec["reasons"].append(
                    "%s: %s/%s" % (R_CONTENT_NO_RULE, akey[0], akey[1])
                )
                rec["alias_rule_actions"][
                    "%s\x1f%s" % akey
                ] = {"action": None, "source_line": None}
                continue
            rec["alias_rule_actions"]["%s\x1f%s" % akey] = {
                "action": rule["action"],
                "source_line": rule["source_line"],
            }
            actions.append(rule["action"])
            if rule["action"] == ACTION_HOLD:
                rec["reasons"].append(
                    "%s: %s/%s (rule line %d)"
                    % (R_CONTENT_HOLD_RULE, akey[0], akey[1],
                       rule["source_line"])
                )
            elif rule["action"] == ACTION_REDACT:
                bound.append(rule["content_sha256"])
                all_ranges.extend(rule["ranges"])
        # 决定优先级：blocked 检查在下方；先判业务暂缓
        has_hold = any(
            v["action"] in (None, ACTION_HOLD)
            for v in rec["alias_rule_actions"].values()
        )
        if has_hold:
            rec["decision"] = CONTENT_HOLD
        elif ACTION_REDACT in actions:
            rec["decision"] = CONTENT_REDACT
        elif actions and all(x == ACTION_RELEASE for x in actions):
            rec["decision"] = CONTENT_RELEASE
        else:
            # 没有别名（理论不可达）或无任何动作：按暂缓处理
            rec["decision"] = CONTENT_HOLD
            rec["reasons"].append(R_CONTENT_NO_RULE)

        # ---- 第四步：遮盖可成立性预检（只对 redact 内容）-----------------
        if rec["decision"] == CONTENT_REDACT:
            rec["merged_redaction_ranges"] = merge_ranges(all_ranges)
            rec["bound_digests"] = sorted(set(bound))
            # 规则绑定摘要必须与本次 sealed 视图中的实际摘要一致
            if any(b != digest for b in rec["bound_digests"]):
                rec["blocked"] = True
                rec["reasons"].append(
                    "%s: content=%s bound=%s"
                    % (R_CONTENT_BOUND_DIGEST_MISMATCH, digest,
                       ",".join(rec["bound_digests"]))
                )
            else:
                # 取一份稳定的 bytes_ok 封存文件做 UTF-8/边界/越界预检
                src = aliases[0]
                src_path = os.path.join(repo_root, src["stored_path"])
                ident = (src["id_type"], src["id_value"])
                try:
                    red.scan_utf8_and_boundaries(
                        src_path, all_ranges, digest, src["size"],
                        identity=ident,
                    )
                except red.RedactionError as exc:
                    rec["blocked"] = True
                    rec["reasons"].append(
                        "%s: %s/%s: %s: %s"
                        % (R_CONTENT_RANGE_INVALID, ident[0], ident[1],
                           exc.code, exc.message)
                    )
        content_records[digest] = rec

    # ---- 第五步：表示可交付判定 ------------------------------------------
    # 只有通过全部成员检查、且其全部内容决定可发布（release/redact）的表示
    # 才能对外列出。
    deliverable_reps, held_reps = [], []
    for rep_rec in rep_records:
        if rep_rec["decision"] == REP_HOLD:
            held_reps.append(rep_rec)
            continue
        bad_contents = []
        for d in rep_rec["content_digests"]:
            c = content_records[d]
            if c["decision"] in (CONTENT_HOLD, CONTENT_BLOCKED) or c["blocked"]:
                bad_contents.append((d, c["decision"], c["reasons"]))
        if bad_contents:
            rep_rec["decision"] = REP_HOLD
            for d, _dec, why in bad_contents:
                rep_rec["reasons"].append(
                    "content %s not publishable: %s" % (d, "; ".join(why))
                )
            held_reps.append(rep_rec)
        else:
            deliverable_reps.append(rep_rec)

    # ---- 第六步：装配计划文档并内容寻址 ----------------------------------
    blocked_contents = [d for d, c in content_records.items() if c["blocked"]]
    plan_body = {
        "profile": PLAN_PROFILE,
        "engine": PLAN_ENGINE,
        "audience": request["audience"],
        "inputs": {
            "request": {
                "request_id": request["request_id"],
                "format_version": "release-request/v1",
                "source_sha256": request["source_sha256"],
                "source_bytes": request["source_bytes"],
                "source_lines": request["source_lines"],
                "selections": [
                    {
                        "identifierType": s["id_type"],
                        "identifierValue": s["id_value"],
                        "external_code": s["external_code"],
                        "source_line": s["source_line"],
                    }
                    for s in request["selections"]
                ],
            },
            "rules": {
                "rules_id": rules_doc["rules_id"],
                "format_version": "release-rules/v1",
                "source_sha256": rules_doc["source_sha256"],
                "source_bytes": rules_doc["source_bytes"],
                "source_lines": rules_doc["source_lines"],
                "rules": [
                    {
                        "bitstream": {
                            "identifierType": k[0],
                            "identifierValue": k[1],
                        },
                        "action": v["action"],
                        "content_sha256": v["content_sha256"],
                        "ranges": v["ranges"],
                        "source_line": v["source_line"],
                    }
                    for k, v in sorted(rules.items())
                ],
            },
            "sealed": {
                "package_set": pkg_set,
                "package_set_sha256": pkg_set_sha,
            },
        },
        "representations": rep_records,
        "contents": [content_records[d] for d in sorted(content_records)],
        "summary": {
            "representation_total": len(rep_records),
            "deliverable": len(deliverable_reps),
            "held": len(held_reps),
            "content_total": len(content_records),
            "content_release": sum(
                1 for c in content_records.values()
                if c["decision"] == CONTENT_RELEASE and not c["blocked"]
            ),
            "content_redact": sum(
                1 for c in content_records.values()
                if c["decision"] == CONTENT_REDACT and not c["blocked"]
            ),
            "content_held": sum(
                1 for c in content_records.values()
                if c["decision"] == CONTENT_HOLD
            ),
            "content_blocked": len(blocked_contents),
        },
    }
    plan_id = _sha(_canon(plan_body))
    plan_doc = dict(plan_body)
    plan_doc["plan_id"] = plan_id
    plan_doc["created_at"] = _now()

    existing = conn.execute(
        "SELECT plan_id, plan_path FROM release_plans WHERE plan_id=?",
        (plan_id,),
    ).fetchone()
    if existing is not None:
        return _load_plan_doc(conn, repo_root, plan_id), True

    _persist_plan(conn, repo_root, plan_doc, request, rules_doc, request_path,
                  rules_path)
    return plan_doc, False


def _persist_plan(conn, repo_root, plan_doc, request, rules_doc,
                  request_path, rules_path):
    rel_plan = "release/plans/%s.json" % plan_doc["plan_id"]
    abs_plan = os.path.join(repo_root, rel_plan)
    os.makedirs(os.path.dirname(abs_plan), exist_ok=True)
    # 原始输入副本（审计/争议定位；与计划同在仓内、外发目录之外）。
    # 用完整来源摘要命名，避免截断碰撞；同内容输入自然复用同一副本。
    stored = {}
    for kind, src, doc in (
        ("requests", request_path, request),
        ("rules", rules_path, rules_doc),
    ):
        digest = doc["source_sha256"]
        rel = "release/%s/%s.jsonl" % (kind, digest)
        dst = os.path.join(repo_root, rel)
        if not os.path.exists(dst):
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            tmp = dst + ".tmp-%d" % os.getpid()
            with open(src, "rb") as fi, open(tmp, "wb") as fo:
                while True:
                    chunk = fi.read(1 << 20)
                    if not chunk:
                        break
                    fo.write(chunk)
                fo.flush()
                os.fsync(fo.fileno())
            os.replace(tmp, dst)
        stored[kind] = rel
    tmp = abs_plan + ".tmp-%d" % os.getpid()
    with open(tmp, "wb") as f:
        f.write(json.dumps(
            plan_doc, ensure_ascii=False, sort_keys=True, indent=2
        ).encode("utf-8") + b"\n")
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, abs_plan)

    s = plan_doc["summary"]
    conn.execute(
        "INSERT INTO release_plans(plan_id,request_id,audience,created_at,"
        "sealed_package_set,package_set_sha256,request_sha256,rules_sha256,"
        "request_bytes,rules_bytes,plan_path,deliverable_count,held_count,"
        "blocked_count) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (
            plan_doc["plan_id"],
            plan_doc["inputs"]["request"]["request_id"],
            plan_doc["audience"],
            plan_doc["created_at"],
            json.dumps(plan_doc["inputs"]["sealed"]["package_set"]),
            plan_doc["inputs"]["sealed"]["package_set_sha256"],
            plan_doc["inputs"]["request"]["source_sha256"],
            plan_doc["inputs"]["rules"]["source_sha256"],
            plan_doc["inputs"]["request"]["source_bytes"],
            plan_doc["inputs"]["rules"]["source_bytes"],
            rel_plan,
            s["deliverable"],
            s["held"],
            s["content_blocked"],
        ),
    )
    conn.commit()


def _load_plan_doc(conn, repo_root, plan_id):
    row = conn.execute(
        "SELECT plan_path FROM release_plans WHERE plan_id=?", (plan_id,)
    ).fetchone()
    if row is None:
        raise PlanError("unknown plan_id %r" % plan_id)
    with open(os.path.join(repo_root, row["plan_path"]), "rb") as f:
        return json.load(f)


def list_plans(conn):
    return [
        dict(r)
        for r in conn.execute(
            "SELECT plan_id,request_id,audience,created_at,"
            "package_set_sha256,deliverable_count,held_count,blocked_count,"
            "plan_path FROM release_plans ORDER BY created_at, plan_id"
        ).fetchall()
    ]


def get_plan(conn, repo_root, plan_id):
    return _load_plan_doc(conn, repo_root, plan_id)


# ---------------------------------------------------------------------------
# 交付文件名（受控、确定性；不得取自馆内身份/路径/原件摘要）
# ---------------------------------------------------------------------------

def delivery_filename(plan_id, delivered_sha256):
    """
    以 plan_id 为键、交付字节摘要为消息的 HMAC 全名（64 hex）。
    plan_id 与原件摘要均不出现在外发目录；同名内容在同一计划内稳定共享一个
    输出文件，跨计划自然更换文件名。HMAC 截断只用于展示，落盘用完整摘要，
    杜绝碰撞空间。
    """
    mac = hmac.new(
        plan_id.encode("ascii"),
        delivered_sha256.encode("ascii"),
        hashlib.sha256,
    ).hexdigest()
    return "f-%s.bin" % mac
