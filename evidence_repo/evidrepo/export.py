# -*- coding: utf-8 -*-
"""
按结构节点/表示导出证明子包。

规则：
- 只导出选中表示的全部成员 + “一条”完整证明所需原件、事件与原始 XML 出处；
  可任选一条有效路径（不追求最小证明），选择稳定（事件按 ID 字典序取第一条
  全输入已证明的支路）且可独立验证。
- 共享证据（同一原件/事件/XML）在子包内只保留一次；不枚举全部来源路径；
  不顺带导出任何无关表示。
- 证明号与证明 ID 固定绑定导出当时的 sealed 包集合；迟到原件只能让“新查询”
  变 verified，不能改写旧证明（proofs 表只增不改，导出目录内容寻址）。
- 全部路径相对仓根/导出根，移动整个仓与导出目录后仍可校验。
"""
from __future__ import annotations

import datetime
import hashlib
import json
import os
import shutil

from . import evaluate as ev
from .util import CHUNK_SIZE


class ExportError(Exception):
    pass


def _now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def select_proof_path(conn, id_type, id_value, _stack=None):
    """
    稳定选择一条有限无环证明（只走已 proven 的事实）。
    返回 {"object":(t,v), "root":True, "via":event_id, "inputs":[...]} 或 None。
    不做跨支路结果缓存：某条支路中的环只能让该支路失败，不能污染其他
    独立好路径（与求值器的 OR 语义一致）。事件按 ID 字典序选择，结果稳定。
    """
    if _stack is None:
        _stack = set()
    key = (id_type, id_value)
    if key in _stack:
        return None  # 环：该支路不能自证
    state, proven = ev.object_state(conn, id_type, id_value)
    if not proven or state != "bytes_ok":
        return None
    _stack.add(key)
    try:
        chosen = None
        for e in ev.valid_events_producing(conn, id_type, id_value):
            if e["event_type"] == "ingest":
                chosen = {"object": key, "root": True, "via": e["event_id"],
                          "inputs": []}
                break
            input_paths = []
            ok = True
            for it, iv in ev.event_inputs(conn, e["event_id"]):
                sub = select_proof_path(conn, it, iv, set(_stack))
                if sub is None:
                    ok = False
                    break
                input_paths.append(sub)
            if ok:
                chosen = {
                    "object": key,
                    "root": False,
                    "via": e["event_id"],
                    "inputs": input_paths,
                }
                break
    finally:
        _stack.discard(key)
    return chosen


def _flatten(path_node, events_out, objects_out, order):
    obj = path_node["object"]
    if obj in objects_out:
        # 共享对象只处理一次；但根 ingest 事件仍需确保入集（下方处理）
        if path_node["root"]:
            events_out.add(path_node["via"])
        return
    objects_out.add(obj)
    order.append(obj)
    # 根对象的受信 ingest 事件同样是证明组成部分，必须随包导出
    events_out.add(path_node["via"])
    if not path_node["root"]:
        for sub in path_node["inputs"]:
            _flatten(sub, events_out, objects_out, order)


def _find_blob(conn, id_type, id_value):
    """取该身份一份 bytes_ok 的字节（按 package_id,rel_path 稳定选择）。"""
    return conn.execute(
        """
        SELECT ob.package_id, ob.blob_rel, b.actual_sha, b.size_actual, b.stored_path
        FROM object_blobs ob
        JOIN blobs b ON b.package_id=ob.package_id AND b.rel_path=ob.blob_rel
        WHERE ob.id_type=? AND ob.id_value=? AND b.state='bytes_ok'
        ORDER BY ob.package_id, ob.blob_rel LIMIT 1
        """,
        (id_type, id_value),
    ).fetchone()


def export_proof(conn, repo_root, export_root, rep_id_type, rep_id_value,
                 node_id=None):
    from .diagnostics import evaluate_representation

    assessment = evaluate_representation(conn, rep_id_type, rep_id_value)
    if assessment["label"] != "verified":
        raise ExportError(
            "representation %s/%s is %s, no verified proof can be exported: %s"
            % (rep_id_type, rep_id_value, assessment["label"],
               "; ".join(assessment["reasons"]))
        )

    paths, events, objects, obj_order = [], set(), set(), []
    for m in assessment["members"]:
        p = select_proof_path(conn, m["id_type"], m["id_value"])
        if p is None:  # 理论不可达：verified 已保证
            raise ExportError("internal: proven member without selectable path")
        paths.append(p)
        _flatten(p, events, objects, obj_order)

    package_set = sorted(
        r[0]
        for r in conn.execute(
            "SELECT DISTINCT package_id FROM packages WHERE state='sealed'"
        ).fetchall()
    )

    out = os.path.abspath(export_root)
    staging = out + ".tmp-%d" % os.getpid()
    if os.path.exists(staging):
        shutil.rmtree(staging)
    os.makedirs(os.path.join(staging, "blobs"))
    os.makedirs(os.path.join(staging, "xml"))

    blob_records, xml_records = [], []
    copied_blobs, copied_xml = set(), set()
    for id_type, id_value in sorted(objects):
        b = _find_blob(conn, id_type, id_value)
        if b is None:
            raise ExportError("internal: proven object without bytes_ok blob: %s/%s"
                              % (id_type, id_value))
        store_src = os.path.join(repo_root, b["stored_path"])
        content_name = "%s%s" % (b["actual_sha"], os.path.splitext(b["blob_rel"])[1])
        dst_rel = os.path.join("blobs", b["package_id"], content_name)
        if b["actual_sha"] not in copied_blobs:
            _copy_chunked(store_src, os.path.join(staging, dst_rel))
            copied_blobs.add(b["actual_sha"])
        blob_records.append(
            {
                "id_type": id_type,
                "id_value": id_value,
                "package_id": b["package_id"],
                "source_rel": b["blob_rel"],
                "export_rel": dst_rel,
                "size": b["size_actual"],
                "sha256": b["actual_sha"],
            }
        )

    event_records = []
    for eid in sorted(events):
        er = conn.execute(
            "SELECT * FROM events WHERE event_id=? AND "
            "package_id IN (SELECT package_id FROM packages WHERE state='sealed')",
            (eid,),
        ).fetchone()
        xkey = (er["package_id"], er["xml_rel"])
        dst_rel = os.path.join("xml", er["package_id"],
                               er["xml_rel"].replace(os.sep, "__"))
        if xkey not in copied_xml:
            src = os.path.join(
                repo_root,
                conn.execute(
                    "SELECT stored_path FROM xml_docs WHERE package_id=? AND rel_path=?",
                    xkey,
                ).fetchone()["stored_path"],
            )
            _copy_chunked(src, os.path.join(staging, dst_rel))
            copied_xml.add(xkey)
        links = conn.execute(
            "SELECT role,obj_id_type,obj_id_value,ord FROM event_links "
            "WHERE event_id=? ORDER BY ord",
            (eid,),
        ).fetchall()
        event_records.append(
            {
                "event_id": eid,
                "event_type": er["event_type"],
                "event_date_time": er["event_dt"],
                "outcome": er["outcome"],
                "package_id": er["package_id"],
                "xml_rel": dst_rel,
                "links": [dict(r) for r in links],
            }
        )

    # 成员所在包的 manifest（信任名单出处）也随包保存
    manifests = []
    for pid in sorted({b["package_id"] for b in blob_records} |
                      {e["package_id"] for e in event_records}):
        mrow = conn.execute(
            "SELECT manifest FROM packages WHERE package_id=?", (pid,)
        ).fetchone()
        dst_rel = os.path.join("xml", pid, "manifest.json")
        _copy_chunked(
            os.path.join(repo_root, mrow["manifest"]),
            os.path.join(staging, dst_rel),
        )
        manifests.append({"package_id": pid, "export_rel": dst_rel})

    proof_doc = {
        "profile": "offline-evidence-repo/v1",
        "generated_at": _now(),
        "sealed_package_set": package_set,
        "representation": {
            "id_type": rep_id_type,
            "id_value": rep_id_value,
            "struct_node": node_id,
        },
        "members": [
            {"id_type": m["id_type"], "id_value": m["id_value"]}
            for m in assessment["members"]
        ],
        "selected_paths": paths,
        "events": event_records,
        "blobs": blob_records,
        "manifests": manifests,
        "notes": (
            "Only ONE valid provenance path per object is included. "
            "Shared evidence stored once. Event time is source metadata only."
        ),
    }
    # proof_id 只绑定“证据内容”：选中路径、事件、字节、成员、出处。
    # 生成时间与当时 sealed 包集合快照不参与内容寻址（包集合另存列），
    # 这样同一证据内容的重复导出稳定复用同一证明号；包集合变化时
    # 证据内容若变化自然得到新号，旧证明行只增不改。
    content_doc = {
        "profile": proof_doc["profile"],
        "representation": proof_doc["representation"],
        "members": proof_doc["members"],
        "selected_paths": proof_doc["selected_paths"],
        "events": [
            {k: e[k] for k in ("event_id", "event_type", "event_date_time",
                               "outcome", "links")}
            for e in proof_doc["events"]
        ],
        "blobs": [
            {k: b[k] for k in ("id_type", "id_value", "sha256", "size",
                               "package_id", "source_rel")}
            for b in proof_doc["blobs"]
        ],
    }
    proof_id = hashlib.sha256(
        json.dumps(content_doc, ensure_ascii=False, indent=2,
                   sort_keys=True).encode("utf-8")
    ).hexdigest()
    proof_doc["proof_id"] = proof_id
    with open(os.path.join(staging, "proof.json"), "wb") as f:
        f.write(
            json.dumps(proof_doc, ensure_ascii=False, indent=2, sort_keys=True).encode(
                "utf-8"
            )
        )

    from .synthetic_xml import write_synthetic

    write_synthetic(staging, proof_doc)

    # 旧证明不可变：同一内容证明已存在则复用编号；新内容拿新号
    existing = conn.execute(
        "SELECT proof_no, export_dir FROM proofs WHERE proof_id=?", (proof_id,)
    ).fetchone()
    if existing:
        shutil.rmtree(staging)
        return {
            "proof_id": proof_id,
            "proof_no": existing["proof_no"],
            "export_dir": existing["export_dir"],
            "reused": True,
        }
    final_dir = os.path.join(out, "proof-%s" % proof_id[:12])
    os.makedirs(out, exist_ok=True)
    os.rename(staging, final_dir)
    cur = conn.execute(
        "INSERT INTO proofs(proof_id,created_at,rep_id_type,rep_id_value,"
        "export_dir,package_set) VALUES(?,?,?,?,?,?)",
        (
            proof_id,
            _now(),
            rep_id_type,
            rep_id_value,
            os.path.relpath(final_dir, repo_root)
            if os.path.commonpath([os.path.abspath(repo_root), final_dir])
            == os.path.abspath(repo_root)
            else final_dir,
            json.dumps(package_set),
        ),
    )
    conn.commit()
    return {
        "proof_id": proof_id,
        "proof_no": cur.lastrowid,
        "export_dir": final_dir,
        "reused": False,
    }


def _copy_chunked(src, dst):
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    with open(src, "rb") as fi, open(dst, "wb") as fo:
        while True:
            chunk = fi.read(CHUNK_SIZE)
            if not chunk:
                break
            fo.write(chunk)
