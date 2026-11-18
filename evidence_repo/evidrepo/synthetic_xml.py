# -*- coding: utf-8 -*-
"""
导出子包内的合成 XML 生成器。

只生成 profile 明确支持的元素（PREMIS 3 objectIdentifier/eventIdentifier/
eventType/eventDateTime/eventOutcomeInformation/带 input|output 角色的
linkingObjectIdentifier；METS fileSec/structMap 引用），并在
element-mapping.json 中逐元素标注其来源原始 XML 出处。
合成文档不发明任何新证据；原包中的扩展仍只存在于原始 XML 副本中（uninterpreted）。
"""
from __future__ import annotations

import json
import os
import xml.etree.ElementTree as ET

from .util import METS_NS, PREMIS_NS, XLINK_NS

ET.register_namespace("premis", PREMIS_NS)
ET.register_namespace("mets", METS_NS)
ET.register_namespace("xlink", XLINK_NS)


def _q(ns, tag):
    return "{%s}%s" % (ns, tag)


def write_synthetic(export_dir, proof_doc):
    syn_dir = os.path.join(export_dir, "synthetic")
    os.makedirs(syn_dir, exist_ok=True)
    mapping = {"profile": "offline-evidence-repo/v1", "elements": []}

    # ---------- 合成 PREMIS（对象 + 事件，仅 profile 元素） ----------
    premis = ET.Element(_q(PREMIS_NS, "premis"), {"version": "3.0"})

    rep_obj = ET.SubElement(premis, _q(PREMIS_NS, "object"))
    roi = ET.SubElement(rep_obj, _q(PREMIS_NS, "objectIdentifier"))
    ET.SubElement(roi, _q(PREMIS_NS, "objectIdentifierType")).text = proof_doc[
        "representation"
    ]["id_type"]
    ET.SubElement(roi, _q(PREMIS_NS, "objectIdentifierValue")).text = proof_doc[
        "representation"
    ]["id_value"]
    ET.SubElement(rep_obj, _q(PREMIS_NS, "objectCategory")).text = "representation"

    for b in proof_doc["blobs"]:
        obj = ET.SubElement(premis, _q(PREMIS_NS, "object"))
        oi = ET.SubElement(obj, _q(PREMIS_NS, "objectIdentifier"))
        t1 = ET.SubElement(oi, _q(PREMIS_NS, "objectIdentifierType"))
        t1.text = b["id_type"]
        v1 = ET.SubElement(oi, _q(PREMIS_NS, "objectIdentifierValue"))
        v1.text = b["id_value"]
        ET.SubElement(obj, _q(PREMIS_NS, "objectCategory")).text = "bitstream"
        mapping["elements"].append(
            {
                "synthetic": "premis:object/objectIdentifier",
                "source": proof_doc["manifests"][0]["export_rel"],
                "object": [b["id_type"], b["id_value"]],
                "category": "bitstream",
            }
        )

    for e in proof_doc["events"]:
        evt = ET.SubElement(premis, _q(PREMIS_NS, "event"))
        ei = ET.SubElement(evt, _q(PREMIS_NS, "eventIdentifier"))
        ET.SubElement(ei, _q(PREMIS_NS, "eventIdentifierType")).text = "local"
        ET.SubElement(ei, _q(PREMIS_NS, "eventIdentifierValue")).text = e["event_id"]
        ET.SubElement(evt, _q(PREMIS_NS, "eventType")).text = e["event_type"]
        if e.get("event_date_time"):
            ET.SubElement(evt, _q(PREMIS_NS, "eventDateTime")).text = e[
                "event_date_time"
            ]
        eoi = ET.SubElement(evt, _q(PREMIS_NS, "eventOutcomeInformation"))
        ET.SubElement(eoi, _q(PREMIS_NS, "eventOutcome")).text = e["outcome"]
        for link in e["links"]:
            loi = ET.SubElement(evt, _q(PREMIS_NS, "linkingObjectIdentifier"))
            ET.SubElement(
                loi, _q(PREMIS_NS, "linkingObjectIdentifierType")
            ).text = link["obj_id_type"]
            ET.SubElement(
                loi, _q(PREMIS_NS, "linkingObjectIdentifierValue")
            ).text = link["obj_id_value"]
            ET.SubElement(loi, _q(PREMIS_NS, "linkingObjectRole")).text = link["role"]
        mapping["elements"].append(
            {
                "synthetic": "premis:event",
                "event_id": e["event_id"],
                "source_xml": e["xml_rel"],
                "mapped": [
                    "eventIdentifier",
                    "eventType",
                    "eventDateTime",
                    "eventOutcomeInformation/eventOutcome",
                    "linkingObjectIdentifier[linkingObjectRole=input|output]",
                ],
                "uninterpreted_note": (
                    "Any other elements in the source PREMIS are preserved only "
                    "in the source XML copy and are not treated as evidence."
                ),
            }
        )
    premis_path = os.path.join(syn_dir, "synthetic-premis.xml")
    ET.ElementTree(premis).write(premis_path, encoding="utf-8", xml_declaration=True)

    # ---------- 合成 METS（fileSec 成员 + structMap 单节点引用表示） ----------
    mets = ET.Element(_q(METS_NS, "mets"))
    fsec = ET.SubElement(mets, _q(METS_NS, "fileSec"))
    grp = ET.SubElement(
        fsec,
        _q(METS_NS, "fileGrp"),
        {"ID": "REP-GRP-1",
         "ADMID": "REP-OBJ"},
    )
    for i, b in enumerate(proof_doc["blobs"]):
        is_member = any(
            b["id_value"] == m["id_value"] and b["id_type"] == m["id_type"]
            for m in proof_doc["members"]
        )
        if not is_member:
            continue  # 原件/中间件不进 fileSec，只在 PREMIS 谱系中出现
        f = ET.SubElement(grp, _q(METS_NS, "file"), {"ID": "F-%d" % i})
        ET.SubElement(
            f,
            _q(METS_NS, "FLocat"),
            {
                _q(XLINK_NS, "href"): os.path.relpath(
                    os.path.join(export_dir, b["export_rel"]), syn_dir
                ),
                "{http://www.w3.org/1999/xlink}type": "simple",
            },
        )
    smap = ET.SubElement(mets, _q(METS_NS, "structMap"))
    div = ET.SubElement(
        smap,
        _q(METS_NS, "div"),
        {"ID": proof_doc["representation"].get("struct_node") or "NODE-1",
         "LABEL": proof_doc["representation"]["id_value"]},
    )
    ET.SubElement(div, _q(METS_NS, "fptr"), {"FILEID": "REP-GRP-1"})
    mets_path = os.path.join(syn_dir, "synthetic-mets.xml")
    ET.ElementTree(mets).write(mets_path, encoding="utf-8", xml_declaration=True)

    mapping["elements"].append(
        {
            "synthetic": "mets:fileSec/fileGrp/file/FLocat",
            "note": "representation members only; source-of-evidence blobs "
            "stay in PREMIS lineage, not duplicated as members",
        }
    )
    mapping["elements"].append(
        {
            "synthetic": "mets:structMap/div/fptr",
            "note": "struct node references exactly one representation; "
            "a bitstream shown at multiple nodes is never counted twice",
        }
    )
    with open(
        os.path.join(syn_dir, "element-mapping.json"), "w", encoding="utf-8"
    ) as f:
        json.dump(mapping, f, ensure_ascii=False, indent=2, sort_keys=True)
    return premis_path, mets_path
