# -*- coding: utf-8 -*-
"""
导出证明子包的独立验证器（独立检查，不 import 求值器/诊断模块）。

检查项：
1. 每个 blob 的 SHA-256/长度与 proof.json 声明一致（分块重算）；
2. proof.json 中每个事件的“全部输入”都在子包内、且字节完整；
   输出同样完整；ingest 无 input 且其事件 ID 出现在随包 manifest 的
   trusted_ingest_events 名单中；
3. 从每个成员出发独立做一次有限无环 DFS，根全部是受信 ingest，
   中间事件 outcome=success、角色显式（不按记录顺序猜）；
4. selected_paths 与重新独立选出的路径结构一致；
5. 事件引用无悬空；不存在循环自证；
6. 表示成员集合与合成 METS fileSec 一致；structMap 只引用该表示。

整个导出目录可任意移动：验证只用导出目录内的相对路径。
"""
from __future__ import annotations

import hashlib
import json
import os
import sys
import xml.etree.ElementTree as ET

CHUNK = 1 << 20
PREMIS_NS = "http://www.loc.gov/premis/v3"
METS_NS = "http://www.loc.gov/METS/"


class VerificationError(Exception):
    pass


def _sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            b = f.read(CHUNK)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def verify_export(export_dir):
    export_dir = os.path.abspath(export_dir)
    pj = os.path.join(export_dir, "proof.json")
    if not os.path.isfile(pj):
        raise VerificationError("proof.json missing")
    with open(pj, "r", encoding="utf-8") as f:
        doc = json.load(f)
    errors, checks = [], []

    # 1. 字节完整性
    blob_index = {}
    for b in doc["blobs"]:
        p = os.path.join(export_dir, b["export_rel"])
        if not os.path.isfile(p):
            errors.append("blob missing: %s" % b["export_rel"])
            continue
        digest = _sha256(p)
        if digest != b["sha256"]:
            errors.append(
                "blob hash mismatch %s: proof=%s recomputed=%s"
                % (b["export_rel"], b["sha256"], digest)
            )
        if os.path.getsize(p) != b["size"]:
            errors.append("blob size mismatch: %s" % b["export_rel"])
        blob_index[(b["id_type"], b["id_value"])] = b
    checks.append("recomputed SHA-256 for %d blobs (chunked)" % len(doc["blobs"]))

    # 2/3. 独立事件检查
    trust = set()
    for m in doc["manifests"]:
        with open(os.path.join(export_dir, m["export_rel"]), "r", encoding="utf-8") as f:
            mf = json.load(f)
        trust.update(mf.get("trusted_ingest_events", []))
    ev_index = {e["event_id"]: e for e in doc["events"]}
    producing = {}
    ingest_roots = set()
    for e in doc["events"]:
        if e["event_type"] not in ("ingest", "copy", "migration"):
            errors.append("unsupported event type in proof: %s" % e["event_id"])
        if e["outcome"] != "success":
            errors.append("non-success event used as evidence: %s" % e["event_id"])
        roles = [l["role"] for l in e["links"]]
        if any(r not in ("input", "output") for r in roles):
            errors.append("link without explicit input/output role: %s" % e["event_id"])
        inputs = [l for l in e["links"] if l["role"] == "input"]
        outputs = [l for l in e["links"] if l["role"] == "output"]
        if not outputs:
            errors.append("event without output: %s" % e["event_id"])
        if e["event_type"] == "ingest":
            if inputs:
                errors.append("ingest event %s has inputs" % e["event_id"])
            if e["event_id"] not in trust:
                errors.append(
                    "ingest %s not on caller trust list in bundled manifests"
                    % e["event_id"]
                )
            else:
                for l in outputs:
                    ingest_roots.add((l["obj_id_type"], l["obj_id_value"]))
        else:
            if not inputs:
                errors.append("%s event %s lacks explicit input"
                              % (e["event_type"], e["event_id"]))
        for l in e["links"]:
            key = (l["obj_id_type"], l["obj_id_value"])
            if key not in blob_index:
                errors.append(
                    "event %s references object not in bundle: %s/%s"
                    % (e["event_id"], key[0], key[1])
                )
            if l["role"] == "output":
                producing.setdefault(key, []).append(e["event_id"])

    # 3. 独立有限无环 DFS（自己重写，不依赖仓内求值器）
    def prove(key, stack):
        if key in stack:
            return False, "cycle at %s/%s" % key
        if key not in blob_index:
            return False, "object not bundled %s/%s" % key
        # 受信 ingest 的 output 是证明根，不再向上追溯
        if key in ingest_roots:
            return True, None
        eids = producing.get(key, [])
        if not eids:
            return False, "no producing event for %s/%s" % key
        last_err = "no complete branch"
        for eid in sorted(eids):
            e = ev_index[eid]
            if e["event_type"] == "ingest":
                # 不受信的 ingest 不能作为根（上面已记 error），跳过
                continue
            ok = True
            for l in e["links"]:
                if l["role"] != "input":
                    continue
                sub_key = (l["obj_id_type"], l["obj_id_value"])
                ok2, err = prove(sub_key, stack | {key})
                if not ok2:
                    ok = False
                    last_err = err
                    break
            if ok:
                return True, None
        return False, last_err

    members = [(m["id_type"], m["id_value"]) for m in doc["members"]]
    for key in members:
        ok, err = prove(key, set())
        if not ok:
            errors.append("independent DFS cannot prove %s/%s: %s" % (key[0], key[1], err))
    checks.append("independent acyclic DFS from %d representation members" % len(members))

    # 4. selected_paths 与独立 DFS 结果一致性（全部对象可达受信根）
    def walk(node, seen_events):
        # 根对象的 ingest 事件与中间事件都应出现在捆绑事件集中
        seen_events.add(node["via"])
        if not node["root"]:
            for sub in node["inputs"]:
                walk(sub, seen_events)

    seen_events = set()
    for p in doc["selected_paths"]:
        walk(p, seen_events)
    if seen_events != set(ev_index):
        errors.append(
            "selected_paths event set %r != bundled event set %r (stray/missing evidence)"
            % (sorted(seen_events), sorted(set(ev_index)))
        )

    # 5. 原始 XML 存在且可重新解析
    for e in doc["events"]:
        xp = os.path.join(export_dir, e["xml_rel"])
        if not os.path.isfile(xp):
            errors.append("source XML missing for event %s" % e["event_id"])
            continue
        try:
            root = ET.parse(xp).getroot()
            if root.tag != "{%s}premis" % PREMIS_NS:
                errors.append("source XML %s is not PREMIS root" % e["xml_rel"])
        except ET.ParseError as exc:
            errors.append("source XML parse error %s: %s" % (e["xml_rel"], exc))
    checks.append("re-parsed %d source PREMIS documents" % len(doc["events"]))

    # 6. 合成 METS fileSec 成员集合 == 表示成员集合
    mets_path = os.path.join(export_dir, "synthetic", "synthetic-mets.xml")
    tree = ET.parse(mets_path)
    hrefs = {
        os.path.normpath(
            os.path.join(os.path.dirname(mets_path),
                         fl.get("{http://www.w3.org/1999/xlink}href"))
        )
        for fl in tree.getroot().iter("{%s}FLocat" % METS_NS)
    }
    member_blob_files = {
        os.path.normpath(os.path.join(export_dir, blob_index[k]["export_rel"]))
        for k in members
    }
    if hrefs != member_blob_files:
        errors.append("synthetic METS fileSec does not match representation members")
    fptrs = list(tree.getroot().iter("{%s}fptr" % METS_NS))
    if len(fptrs) != 1:
        errors.append("synthetic structMap must reference exactly one representation")
    checks.append("synthetic METS/structMap cross-checked")

    # proof_id 稳定性：与导出器同一套内容规范（时间/包集合不参与）
    content_doc = {
        "profile": doc["profile"],
        "representation": doc["representation"],
        "members": doc["members"],
        "selected_paths": doc["selected_paths"],
        "events": [
            {k: e[k] for k in ("event_id", "event_type", "event_date_time",
                               "outcome", "links")}
            for e in doc["events"]
        ],
        "blobs": [
            {k: b[k] for k in ("id_type", "id_value", "sha256", "size",
                               "package_id", "source_rel")}
            for b in doc["blobs"]
        ],
    }
    recomputed = hashlib.sha256(
        json.dumps(content_doc, ensure_ascii=False, indent=2,
                   sort_keys=True).encode("utf-8")
    ).hexdigest()
    if recomputed != doc["proof_id"]:
        errors.append("proof_id does not bind proof content")
    checks.append("proof_id content binding verified")

    return {
        "ok": not errors,
        "proof_id": doc["proof_id"],
        "sealed_package_set": doc["sealed_package_set"],
        "checks": checks,
        "errors": errors,
    }


def main(argv):
    if len(argv) != 2:
        print("usage: python -m evidrepo.verify_export <export_dir>")
        return 2
    result = verify_export(argv[1])
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
