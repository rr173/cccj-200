# -*- coding: utf-8 -*-
"""
命令行入口：
  init        初始化证据仓
  receive     接收交接包到 staging（可 --resume 补迟到字节）
  finish      结束包/封包（staging -> sealed，重算全库证明）
  packages    列包及字节状态
  object      逐对象查询（状态 + AND/OR 依赖解释）
  rep         逐表示查询（四标签 + 逐项原因）
  reps        列出全部表示
  node        按结构节点查询
  export      按结构节点/表示导出证明子包
  verify      独立验证导出子包（仅用标准库重算，不依赖求值器）
  proofs      列历史证明（证明号与当时包集合绑定，不可变）
  check-store 整仓移动后重算全部 sealed 字节与原始 XML 哈希
  inventory-import  导入预期馆藏清单（整份校验，失败不留半份）
  inventories       列出已导入清单
  inventory-show    查看某份清单的义务与候选
  reconcile         按 inventory_id 对账，生成新的不可变报告
  reports           列出对账报告（按清单过滤）
  report            查看报告全文及其输入绑定
  verify-report     独立校验报告文件（内容哈希 + 输入绑定，可搬迁）
  release-plan      按请求+受众规则生成馆内离线发布计划（内容寻址、只增不改）
  release-plans     列出馆内发布计划
  release-show      查看馆内计划全文（逐项决定、原因与输入绑定）
  release-publish   按确认的 plan_id 发布到全新目标目录（陈旧计划拒绝）
  release-verify    离线校验外发目录（仅依据公开格式与清单，可搬离仓库）
  release-deliveries 列出发布登记
"""
from __future__ import annotations

import argparse
import json
import os
import sys

from . import db as dbmod
from . import diagnostics, export as exportmod, ingest, verify_export
from . import inventory as invmod
from . import reconcile as reconc
from . import release_plan, release_publish, release_rules, verify_release
from .util import safe_relpath, sha256_file


def _print(obj):
    print(json.dumps(obj, ensure_ascii=False, indent=2, sort_keys=False))


def _open(repo):
    if not os.path.isdir(os.path.join(repo, "db")):
        raise SystemExit("not an evidence repository: %s" % repo)
    return dbmod.connect(repo)


def cmd_init(args):
    os.makedirs(os.path.join(args.repo, "db"), exist_ok=True)
    os.makedirs(os.path.join(args.repo, "store"), exist_ok=True)
    os.makedirs(os.path.join(args.repo, "exports"), exist_ok=True)
    conn = dbmod.connect(args.repo)
    conn.close()
    _print({"initialized": args.repo})


def cmd_receive(args):
    conn = _open(args.repo)
    try:
        _print(ingest.receive(conn, args.repo, args.src, resume=args.resume))
    finally:
        conn.close()


def cmd_finish(args):
    conn = _open(args.repo)
    try:
        _print(ingest.finish(conn, args.repo, args.package_id))
    finally:
        conn.close()


def cmd_packages(args):
    conn = _open(args.repo)
    try:
        _print(ingest.status_overview(conn))
    finally:
        conn.close()


def cmd_object(args):
    conn = _open(args.repo)
    try:
        _print(diagnostics.explain_object(conn, args.id_type, args.id_value))
    finally:
        conn.close()


def cmd_rep(args):
    conn = _open(args.repo)
    try:
        _print(
            diagnostics.evaluate_representation(conn, args.id_type, args.id_value)
        )
    finally:
        conn.close()


def cmd_reps(args):
    conn = _open(args.repo)
    try:
        _print(diagnostics.list_representations(conn))
    finally:
        conn.close()


def cmd_node(args):
    conn = _open(args.repo)
    rows = diagnostics.get_struct_node(conn, args.node_id)
    if not rows:
        raise SystemExit("struct node not found in sealed packages: %s" % args.node_id)
    out = []
    for r in rows:
        assessment = diagnostics.evaluate_representation(
            conn, r["rep_id_type"], r["rep_id_value"]
        )
        out.append(
            {
                "node_id": r["node_id"],
                "label": r["label"],
                "package_id": r["package_id"],
                "representation": {
                    "id_type": r["rep_id_type"],
                    "id_value": r["rep_id_value"],
                },
                "assessment": assessment,
            }
        )
    _print(out)


def cmd_export(args):
    conn = _open(args.repo)
    try:
        node_id = None
        if args.node_id:
            rows = diagnostics.get_struct_node(conn, args.node_id)
            if not rows:
                raise SystemExit("unknown struct node: %s" % args.node_id)
            r = rows[0]
            id_type, id_value = r["rep_id_type"], r["rep_id_value"]
            node_id = r["node_id"]
        else:
            id_type, id_value = args.id_type, args.id_value
        res = exportmod.export_proof(
            conn,
            args.repo,
            os.path.join(args.repo, "exports")
            if not args.out
            else args.out,
            id_type,
            id_value,
            node_id=node_id,
        )
        _print(res)
    finally:
        conn.close()


def cmd_verify(args):
    result = verify_export.verify_export(args.export_dir)
    _print(result)
    if not result["ok"]:
        sys.exit(1)


def cmd_proofs(args):
    conn = _open(args.repo)
    rows = conn.execute(
        "SELECT proof_no,proof_id,created_at,rep_id_type,rep_id_value,export_dir,"
        "package_set FROM proofs ORDER BY proof_no"
    ).fetchall()
    _print([dict(r, package_set=json.loads(r["package_set"])) for r in rows])


def cmd_check_store(args):
    """整仓移动后：用仓内相对路径重算所有 sealed 字节和 XML 哈希。"""
    conn = _open(args.repo)
    problems = []
    n_blob = n_xml = 0
    for b in conn.execute(
        "SELECT * FROM blobs WHERE state='bytes_ok' AND "
        "package_id IN (SELECT package_id FROM packages WHERE state='sealed')"
    ):
        n_blob += 1
        p = safe_relpath(b["stored_path"], args.repo)
        digest = sha256_file(p)
        if digest != b["actual_sha"]:
            problems.append(
                {"kind": "blob", "package_id": b["package_id"],
                 "rel_path": b["rel_path"], "expected": b["actual_sha"],
                 "actual": digest}
            )
    for x in conn.execute(
        "SELECT * FROM xml_docs WHERE package_id IN "
        "(SELECT package_id FROM packages WHERE state='sealed')"
    ):
        n_xml += 1
        p = safe_relpath(x["stored_path"], args.repo)
        # 仓内保存的就是 C14N 规范化字节：直接哈希存储字节，不再二次规范化
        digest = sha256_file(p)
        if digest != x["c14n_sha256"]:
            problems.append(
                {"kind": "xml", "package_id": x["package_id"],
                 "rel_path": x["rel_path"], "expected": x["c14n_sha256"],
                 "actual": digest}
            )
    _print({"ok": not problems, "checked_blobs": n_blob,
            "checked_xml_docs": n_xml, "problems": problems})


# ---------------------------------------------------------------------------
# 预期馆藏对账（与证明/谱系命令完全分离）
# ---------------------------------------------------------------------------

def cmd_inventory_import(args):
    conn = _open(args.repo)
    try:
        _print(invmod.import_inventory(conn, args.repo, args.path))
    except invmod.InventoryError as exc:
        _print(exc.as_dict())
        sys.exit(1)
    finally:
        conn.close()


def cmd_inventories(args):
    conn = _open(args.repo)
    try:
        _print(invmod.list_inventories(conn))
    finally:
        conn.close()


def cmd_inventory_show(args):
    conn = _open(args.repo)
    try:
        _print(invmod.get_inventory(conn, args.inventory_id))
    except invmod.InventoryError as exc:
        _print(exc.as_dict())
        sys.exit(1)
    finally:
        conn.close()


def cmd_reconcile(args):
    conn = _open(args.repo)
    try:
        _print(
            reconc.reconcile_and_store(conn, args.repo, args.inventory_id)
        )
    except (invmod.InventoryError, reconc.ReconciliationError) as exc:
        _print({"error": type(exc).__name__, "message": str(exc)})
        sys.exit(1)
    finally:
        conn.close()


def cmd_reports(args):
    conn = _open(args.repo)
    try:
        _print(reconc.list_reports(conn, args.inventory_id))
    finally:
        conn.close()


def cmd_report(args):
    conn = _open(args.repo)
    try:
        _print(reconc.load_report(conn, args.repo, args.report_id))
    except reconc.ReconciliationError as exc:
        _print({"error": "unknown_report", "message": str(exc)})
        sys.exit(1)
    finally:
        conn.close()


def cmd_verify_report(args):
    result = reconc.verify_report(args.path)
    _print(result)
    if not result["ok"]:
        sys.exit(1)


# ---------------------------------------------------------------------------
# 离线发布（馆内计划 -> 确认后发布 -> 外发目录离线校验）
# ---------------------------------------------------------------------------

def cmd_release_plan(args):
    conn = _open(args.repo)
    try:
        try:
            doc, reused = release_plan.build_plan(
                conn, args.repo, args.request, args.rules
            )
        except release_rules.ReleaseInputError as exc:
            # 语法/约束错误：计划失败（区别于业务暂缓）
            _print(exc.as_dict())
            sys.exit(2)
        except release_publish.PublishError as exc:
            _print(exc.as_dict())
            sys.exit(1)
        _print({
            "plan_id": doc["plan_id"],
            "reused": reused,
            "audience": doc["audience"],
            "summary": doc["summary"],
            "plan_path": conn.execute(
                "SELECT plan_path FROM release_plans WHERE plan_id=?",
                (doc["plan_id"],),
            ).fetchone()["plan_path"],
        })
    finally:
        conn.close()


def cmd_release_plans(args):
    conn = _open(args.repo)
    try:
        _print(release_plan.list_plans(conn))
    finally:
        conn.close()


def cmd_release_show(args):
    conn = _open(args.repo)
    try:
        _print(release_plan.get_plan(conn, args.repo, args.plan_id))
    except release_plan.PlanError as exc:
        _print({"error": "unknown_plan", "message": str(exc)})
        sys.exit(1)
    finally:
        conn.close()


def cmd_release_publish(args):
    conn = _open(args.repo)
    try:
        try:
            res = release_publish.publish(
                conn, args.repo, args.plan_id, args.target
            )
        except release_publish.PublishError as exc:
            _print(exc.as_dict())
            sys.exit(1)
        _print(res)
    finally:
        conn.close()


def cmd_release_verify(args):
    result = verify_release.verify_release(args.release_dir)
    _print(result)
    if not result["ok"]:
        sys.exit(1)


def cmd_release_deliveries(args):
    conn = _open(args.repo)
    try:
        rows = conn.execute(
            "SELECT delivery_no,plan_id,delivered_at,target_dir,manifest_name,"
            "file_count,manifest_sha256,package_set_sha256 "
            "FROM release_deliveries ORDER BY delivery_no"
        ).fetchall()
        _print([dict(r) for r in rows])
    finally:
        conn.close()


def build_parser():
    p = argparse.ArgumentParser(prog="evidrepo", description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("init"); sp.add_argument("repo"); sp.set_defaults(fn=cmd_init)
    sp = sub.add_parser("receive")
    sp.add_argument("repo"); sp.add_argument("src"); sp.add_argument("--resume", action="store_true")
    sp.set_defaults(fn=cmd_receive)
    sp = sub.add_parser("finish"); sp.add_argument("repo"); sp.add_argument("package_id")
    sp.set_defaults(fn=cmd_finish)
    sp = sub.add_parser("packages"); sp.add_argument("repo"); sp.set_defaults(fn=cmd_packages)
    sp = sub.add_parser("object")
    sp.add_argument("repo"); sp.add_argument("id_type"); sp.add_argument("id_value")
    sp.set_defaults(fn=cmd_object)
    sp = sub.add_parser("rep")
    sp.add_argument("repo"); sp.add_argument("id_type"); sp.add_argument("id_value")
    sp.set_defaults(fn=cmd_rep)
    sp = sub.add_parser("reps"); sp.add_argument("repo"); sp.set_defaults(fn=cmd_reps)
    sp = sub.add_parser("node"); sp.add_argument("repo"); sp.add_argument("node_id")
    sp.set_defaults(fn=cmd_node)
    sp = sub.add_parser("export")
    sp.add_argument("repo")
    sp.add_argument("--node", dest="node_id")
    sp.add_argument("--id-type", dest="id_type")
    sp.add_argument("--id-value", dest="id_value")
    sp.add_argument("--out")
    sp.set_defaults(fn=cmd_export)
    sp = sub.add_parser("verify"); sp.add_argument("export_dir")
    sp.set_defaults(fn=cmd_verify)
    sp = sub.add_parser("proofs"); sp.add_argument("repo"); sp.set_defaults(fn=cmd_proofs)
    sp = sub.add_parser("check-store"); sp.add_argument("repo"); sp.set_defaults(fn=cmd_check_store)

    sp = sub.add_parser("inventory-import")
    sp.add_argument("repo"); sp.add_argument("path")
    sp.set_defaults(fn=cmd_inventory_import)
    sp = sub.add_parser("inventories"); sp.add_argument("repo")
    sp.set_defaults(fn=cmd_inventories)
    sp = sub.add_parser("inventory-show")
    sp.add_argument("repo"); sp.add_argument("inventory_id")
    sp.set_defaults(fn=cmd_inventory_show)
    sp = sub.add_parser("reconcile")
    sp.add_argument("repo"); sp.add_argument("inventory_id")
    sp.set_defaults(fn=cmd_reconcile)
    sp = sub.add_parser("reports")
    sp.add_argument("repo"); sp.add_argument("--inventory", dest="inventory_id")
    sp.set_defaults(fn=cmd_reports)
    sp = sub.add_parser("report")
    sp.add_argument("repo"); sp.add_argument("report_id")
    sp.set_defaults(fn=cmd_report)
    sp = sub.add_parser("verify-report"); sp.add_argument("path")
    sp.set_defaults(fn=cmd_verify_report)

    # 离线发布
    sp = sub.add_parser("release-plan")
    sp.add_argument("repo"); sp.add_argument("request"); sp.add_argument("rules")
    sp.set_defaults(fn=cmd_release_plan)
    sp = sub.add_parser("release-plans"); sp.add_argument("repo")
    sp.set_defaults(fn=cmd_release_plans)
    sp = sub.add_parser("release-show"); sp.add_argument("repo"); sp.add_argument("plan_id")
    sp.set_defaults(fn=cmd_release_show)
    sp = sub.add_parser("release-publish")
    sp.add_argument("repo"); sp.add_argument("plan_id"); sp.add_argument("target")
    sp.set_defaults(fn=cmd_release_publish)
    sp = sub.add_parser("release-verify"); sp.add_argument("release_dir")
    sp.set_defaults(fn=cmd_release_verify)
    sp = sub.add_parser("release-deliveries"); sp.add_argument("repo")
    sp.set_defaults(fn=cmd_release_deliveries)
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    args.fn(args)


if __name__ == "__main__":
    main()
