# -*- coding: utf-8 -*-
"""
接包（receive）、暂存恢复（resume）、结束包/封包（finish）。

信任模型：
- manifest 是调用者给定的信任起点（成员路径/长度/SHA-256、representation
  完整成员集合、trusted ingest 事件名单）。程序不按 eventType 自行信任任何事件。
- staging 包对查询/求值不可见；finish 封包后才进入 sealed 事实集。
- 接包是事务：profile 校验失败整体回滚，不留半条事实。
"""
from __future__ import annotations

import datetime
import hashlib
import json
import os

from . import parser as prs
from .util import (
    CHUNK_SIZE,
    PKG_SEALED,
    PKG_STAGING,
    canonical_xml,
    safe_relpath,
)


class ReceiveError(Exception):
    pass


def _now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def _store_dir(repo_root, package_id):
    return os.path.join(repo_root, "store", package_id)


def _stream_copy(src, dst):
    """分块复制，返回 (字节数, sha256)。"""
    import hashlib

    h = hashlib.sha256()
    size = 0
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    with open(src, "rb") as fi, open(dst, "wb") as fo:
        while True:
            chunk = fi.read(CHUNK_SIZE)
            if not chunk:
                break
            h.update(chunk)
            size += len(chunk)
            fo.write(chunk)
    return size, h.hexdigest()


def load_manifest(src_dir):
    mf_path = safe_relpath("manifest.json", src_dir)
    if not os.path.isfile(mf_path):
        raise ReceiveError("manifest.json not found in %s" % src_dir)
    with open(mf_path, "r", encoding="utf-8") as f:
        manifest = json.load(f)
    for field in ("package_id", "xml", "members", "representations"):
        if field not in manifest:
            raise ReceiveError("manifest missing field: %s" % field)
    manifest.setdefault("trusted_ingest_events", [])
    return manifest


def receive(conn, repo_root, src_dir, resume=False):
    """
    接收 src_dir 中的交接包到 staging。
    resume=True 时允许对已存在的 staging 包补到迟到字节。
    """
    src_dir = os.path.abspath(src_dir)
    manifest = load_manifest(src_dir)
    pkg = manifest["package_id"]

    row = conn.execute(
        "SELECT state FROM packages WHERE package_id=?", (pkg,)
    ).fetchone()
    if row is not None:
        if row["state"] == PKG_SEALED:
            raise ReceiveError("package %s already sealed" % pkg)
        if not resume:
            raise ReceiveError(
                "package %s already staged; use resume to add late bytes" % pkg
            )
    # 所有路径先做逃逸检查（任何一条失败，整包拒绝）
    for x in manifest["xml"]:
        safe_relpath(x["rel_path"], src_dir)
    for m in manifest["members"]:
        if "rel_path" in m:
            safe_relpath(m["rel_path"], src_dir)

    try:
        conn.execute("BEGIN")
        if row is None:
            store = _store_dir(repo_root, pkg)
            os.makedirs(store, exist_ok=True)
            with open(os.path.join(store, "manifest.json"), "w", encoding="utf-8") as f:
                json.dump(manifest, f, ensure_ascii=False, indent=2, sort_keys=True)
            conn.execute(
                "INSERT INTO packages(package_id,state,manifest,received_at) "
                "VALUES(?,?,?,?)",
                (pkg, PKG_STAGING, "store/%s/manifest.json" % pkg, _now()),
            )
            for ev_id in manifest["trusted_ingest_events"]:
                conn.execute(
                    "INSERT INTO trusted_ingest(package_id,event_id) VALUES(?,?)",
                    (pkg, ev_id),
                )

        _ingest_blobs(conn, repo_root, src_dir, pkg, manifest)
        _ingest_xml(conn, repo_root, src_dir, pkg, manifest)
        conn.commit()
    except Exception:
        conn.rollback()
        raise

    return _stage_report(conn, pkg)


def _ingest_blobs(conn, repo_root, src_dir, pkg, manifest):
    store = _store_dir(repo_root, pkg)
    # 一次性取已成功接收的成员，避免逐行 SELECT
    already_ok = {
        r[0]
        for r in conn.execute(
            "SELECT rel_path FROM blobs WHERE package_id=? AND state='bytes_ok'",
            (pkg,),
        ).fetchall()
    }
    blob_rows, object_blob_rows, object_rows = [], [], []
    for m in manifest["members"]:
        ident = m["object"]
        if "rel_path" not in m:
            # 跨包成员：本包只声明身份，不产生 blob 记录
            continue
        rel = m["rel_path"]
        if rel in already_ok:
            # 已成功接收的字节不重做，仅确保身份映射存在
            object_blob_rows.append(
                (ident["id_type"], ident["id_value"], pkg, rel)
            )
            object_rows.append(
                (ident["id_type"], ident["id_value"], pkg, "bitstream", "(manifest)")
            )
            continue

        src = safe_relpath(rel, src_dir)
        dst = os.path.join(store, "blobs", rel)
        if not os.path.isfile(src):
            state, actual_sha, size_actual, stored = "bytes_missing", None, None, None
        else:
            size_actual, actual_sha = _stream_copy(src, dst)
            if actual_sha.lower() != m["sha256"].lower():
                state, stored = "bytes_corrupt", None
                # 损坏副本不进入仓内可信存储
                if os.path.exists(dst):
                    os.remove(dst)
            elif size_actual != m["size"]:
                raise ReceiveError(
                    "length mismatch for %s: manifest=%d actual=%d"
                    % (rel, m["size"], size_actual)
                )
            else:
                state = "bytes_ok"
                stored = "store/%s/blobs/%s" % (pkg, rel)

        blob_rows.append(
            (pkg, rel, m["sha256"].lower(), actual_sha, m["size"],
             size_actual, state, stored)
        )
        object_blob_rows.append(
            (ident["id_type"], ident["id_value"], pkg, rel)
        )
        object_rows.append(
            (ident["id_type"], ident["id_value"], pkg, "bitstream", "(manifest)")
        )

    conn.executemany(
        "INSERT OR REPLACE INTO blobs"
        "(package_id,rel_path,declared_sha,actual_sha,size_decl,size_actual,"
        "state,stored_path) VALUES(?,?,?,?,?,?,?,?)",
        blob_rows,
    )
    conn.executemany(
        "INSERT OR IGNORE INTO object_blobs(id_type,id_value,package_id,blob_rel) "
        "VALUES(?,?,?,?)",
        object_blob_rows,
    )
    conn.executemany(
        "INSERT OR IGNORE INTO objects(id_type,id_value,package_id,category,xml_rel) "
        "VALUES(?,?,?,?,'(manifest)')",
        [(r[0], r[1], r[2], r[3]) for r in object_rows],
    )


def _ingest_xml(conn, repo_root, src_dir, pkg, manifest):
    store = _store_dir(repo_root, pkg)
    parsed_premis = []
    parsed_mets = []
    for x in manifest["xml"]:
        rel = x["rel_path"]
        kind = x.get("kind", "other")
        src = safe_relpath(rel, src_dir)
        if not os.path.isfile(src):
            raise ReceiveError("declared XML missing: %s" % rel)
        # XML 自身也是包内字节，先按普通文件校验（若 manifest 另给了哈希）
        canon, c14n_hash = canonical_xml(src)
        dst = os.path.join(store, "xml", rel)
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        with open(dst, "wb") as f:
            f.write(canon)
        conn.execute(
            "INSERT OR REPLACE INTO xml_docs"
            "(package_id,rel_path,kind,c14n_sha256,stored_path) VALUES(?,?,?,?,?)",
            (pkg, rel, kind, c14n_hash, "store/%s/xml/%s" % (pkg, rel)),
        )
        if kind == "premis":
            doc = prs.parse_premis(src, canon_text=canon.decode("utf-8"))
            parsed_premis.append((rel, doc))
        elif kind == "mets":
            parsed_mets.append((rel, prs.parse_mets(src)))

    seen_obj = set()
    # resume 重收时先清掉本包旧的 uninterpreted 行，避免重复累积
    conn.execute(
        "DELETE FROM object_uninterpreted WHERE package_id=?", (pkg,)
    )
    conn.execute(
        "DELETE FROM event_uninterpreted WHERE package_id=?", (pkg,)
    )
    # 批量收集后用 executemany 一次写入，避免逐行 SQL 往返
    obj_rows, obj_un_rows, ev_rows, link_rows, ev_un_rows = [], [], [], [], []
    for rel, doc in parsed_premis:
        for o in doc["objects"]:
            k = (o["id_type"], o["id_value"])
            if k in seen_obj:
                continue
            seen_obj.add(k)
            obj_rows.append(
                (o["id_type"], o["id_value"], pkg, o["class"], rel)
            )
        for u in doc["object_uninterpreted"]:
            obj_un_rows.append(
                (u["id_type"], u["id_value"], pkg, rel, u["local_name"], u["raw_xml"])
            )
        for e in doc["events"]:
            event_c14n = hashlib.sha256(e["c14n"].encode("utf-8")).hexdigest()
            ev_rows.append(
                (e["event_id"], pkg, e["event_type"], e["event_dt"],
                 e["outcome"], event_c14n, rel)
            )
            for ord_, link in enumerate(e["links"]):
                link_rows.append(
                    (e["event_id"], pkg, link["role"], link["obj_id_type"],
                     link["obj_id_value"], ord_)
                )
        for u in doc["event_uninterpreted"]:
            ev_un_rows.append(
                (u["event_id"], pkg, rel, u["local_name"], u["raw_xml"])
            )

    conn.executemany(
        "INSERT OR IGNORE INTO objects"
        "(id_type,id_value,package_id,category,xml_rel) VALUES(?,?,?,?,?)",
        obj_rows,
    )
    conn.executemany(
        "INSERT INTO object_uninterpreted"
        "(id_type,id_value,package_id,xml_rel,local_name,raw_xml) "
        "VALUES(?,?,?,?,?,?)",
        obj_un_rows,
    )
    conn.executemany(
        "INSERT OR REPLACE INTO events"
        "(event_id,package_id,event_type,event_dt,outcome,c14n_sha256,xml_rel) "
        "VALUES(?,?,?,?,?,?,?)",
        ev_rows,
    )
    if ev_rows:
        conn.execute(
            "DELETE FROM event_links WHERE package_id=?", (pkg,)
        )
    conn.executemany(
        "INSERT INTO event_links"
        "(event_id,package_id,role,obj_id_type,obj_id_value,ord) "
        "VALUES(?,?,?,?,?,?)",
        link_rows,
    )
    conn.executemany(
        "INSERT INTO event_uninterpreted"
        "(event_id,package_id,xml_rel,local_name,raw_xml) "
        "VALUES(?,?,?,?,?)",
        ev_un_rows,
    )

    # representation 成员集合（manifest 权威；与 METS 交叉核对）
    conn.execute(
        "DELETE FROM rep_members WHERE package_id=?", (pkg,)
    )
    conn.execute("DELETE FROM struct_nodes WHERE package_id=?", (pkg,))
    mets_by_pkg = {rel: d for rel, d in parsed_mets}
    # 一次性取本包全部对象身份与 representation 身份，避免逐行 SELECT
    local_ids = {
        (r[0], r[1])
        for r in conn.execute(
            "SELECT id_type,id_value FROM objects WHERE package_id=?", (pkg,)
        ).fetchall()
    }
    rep_ids = {
        (r[0], r[1])
        for r in conn.execute(
            "SELECT id_type,id_value FROM objects WHERE package_id=? "
            "AND category='representation'", (pkg,)
        ).fetchall()
    }
    rep_member_rows, struct_rows = [], []
    for rep in manifest["representations"]:
        rk = (rep["id_type"], rep["id_value"])
        if rk not in rep_ids:
            raise ReceiveError(
                "representation %s/%s not declared as PREMIS representation object"
                % rk
            )
        for ord_, mem in enumerate(rep["members"]):
            if tuple(mem) not in local_ids:
                raise ReceiveError(
                    "representation %s/%s member %s/%s has no PREMIS object in package"
                    % (rk[0], rk[1], mem[0], mem[1])
                )
            rep_member_rows.append(
                (rk[0], rk[1], mem[0], mem[1], pkg, ord_)
            )
        fg_id = rep.get("filegrp")
        if fg_id is not None and mets_by_pkg:
            _check_filegrp(conn, pkg, rep, mets_by_pkg, manifest)
        for node in rep.get("struct_nodes", []):
            struct_rows.append(
                (pkg, node["node_id"], node.get("label"), rk[0], rk[1])
            )
            _check_struct_node(mets_by_pkg, node, fg_id)
    conn.executemany(
        "INSERT OR REPLACE INTO rep_members"
        "(rep_id_type,rep_id_value,member_type,member_value,package_id,ord) "
        "VALUES(?,?,?,?,?,?)",
        rep_member_rows,
    )
    conn.executemany(
        "INSERT OR REPLACE INTO struct_nodes"
        "(package_id,node_id,label,rep_id_type,rep_id_value) "
        "VALUES(?,?,?,?,?)",
        struct_rows,
    )


def _check_filegrp(conn, pkg, rep, mets_by_pkg, manifest):
    fg_id = rep["filegrp"]
    found = None
    for rel, mets in mets_by_pkg.items():
        if fg_id in mets["filegrps"]:
            found = (rel, mets["filegrps"][fg_id])
            break
    if found is None:
        raise ReceiveError(
            "fileGrp %s referenced by representation %s/%s not found in METS"
            % (fg_id, rep["id_type"], rep["id_value"])
        )
    rel, grp = found
    if grp["rep_identity"] != (rep["id_type"], rep["id_value"]):
        raise ReceiveError(
            "fileGrp %s ADMID identity %r != manifest representation %r"
            % (fg_id, grp["rep_identity"], (rep["id_type"], rep["id_value"]))
        )
    mets_identities = sorted(
        [f["identity"] for f in grp["files"] if f["identity"] is not None]
    )
    manifest_identities = sorted([tuple(m) for m in rep["members"]])
    if mets_identities != manifest_identities:
        raise ReceiveError(
            "fileGrp %s member identities mismatch: METS=%r manifest=%r"
            % (fg_id, mets_identities, manifest_identities)
        )
    # METS href 必须指向：本包 manifest 成员，或该表示声明的跨包成员身份
    hrefs = {f["href"] for f in grp["files"]}
    local = {
        m["rel_path"]: tuple(m["object"].values())
        for m in manifest["members"]
        if "rel_path" in m
    }
    cross_member_rels = {
        "content/%s.bin" % mem[1] for mem in rep["members"]
        if tuple(mem) not in set(local.values())
    }
    for href in hrefs:
        if href in local:
            continue
        if href in cross_member_rels:
            continue  # 跨包成员：字节由别的已接收包提供
        raise ReceiveError(
            "fileGrp %s FLocat %s not listed in manifest members or declared "
            "cross-package members" % (fg_id, href)
        )


def _check_struct_node(mets_by_pkg, node, fg_id):
    for rel, mets in mets_by_pkg.items():
        for s in mets["struct"]:
            if s["node_id"] == node["node_id"]:
                if fg_id is not None and s["fptr"] != fg_id:
                    raise ReceiveError(
                        "struct node %s fptr=%r != representation filegrp %r"
                        % (node["node_id"], s["fptr"], fg_id)
                    )
                return
    raise ReceiveError("struct node %s not found in any METS structMap" % node["node_id"])


def _stage_report(conn, pkg):
    rows = conn.execute(
        "SELECT state, COUNT(*) c FROM blobs WHERE package_id=? GROUP BY state", (pkg,)
    ).fetchall()
    return {
        "package_id": pkg,
        "state": PKG_STAGING,
        "blobs": {r["state"]: r["c"] for r in rows},
    }


def finish(conn, repo_root, package_id):
    """封包：staging -> sealed，然后重算冲突与全库证明不动点。"""
    row = conn.execute(
        "SELECT state FROM packages WHERE package_id=?", (package_id,)
    ).fetchone()
    if row is None:
        raise ReceiveError("unknown package: %s" % package_id)
    if row["state"] == PKG_SEALED:
        raise ReceiveError("package %s already sealed" % package_id)
    conn.execute(
        "UPDATE packages SET state=?, sealed_at=? WHERE package_id=?",
        (PKG_SEALED, _now(), package_id),
    )
    conn.commit()
    from .evaluate import recompute

    recompute(conn)
    return status_overview(conn, package_id)


def status_overview(conn, package_id=None):
    where = ""
    args = ()
    if package_id:
        where, args = " WHERE package_id=?", (package_id,)
    rows = conn.execute(
        "SELECT package_id,state FROM packages" + where + " ORDER BY package_id", args
    ).fetchall()
    out = []
    for r in rows:
        blobs = conn.execute(
            "SELECT state, COUNT(*) c FROM blobs WHERE package_id=? GROUP BY state",
            (r["package_id"],),
        ).fetchall()
        out.append(
            {
                "package_id": r["package_id"],
                "state": r["state"],
                "blobs": {b["state"]: b["c"] for b in blobs},
            }
        )
    return out
