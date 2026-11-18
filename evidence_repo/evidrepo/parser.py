# -*- coding: utf-8 -*-
"""
METS / PREMIS 3 解析器（只映射 profile.md 声明的元素，其余原样保存）。

PREMIS 3 映射：
  object/objectIdentifier/objectIdentifierType  -> id_type
  object/objectIdentifier/objectIdentifierValue -> id_value
  object/objectCategory                         -> bitstream | representation
  event/eventIdentifier/*                       -> event_id
  event/eventType                               -> ingest|copy|migration（其他保留不证明）
  event/eventDateTime                           -> 仅记录来源
  event/eventOutcomeInformation/eventOutcome    -> success|failed|unknown（其他按 unknown）
  event/linkingObjectIdentifier +
      linkingObjectRole = input|output          -> 有角色引用
  （linkingObjectIdentifier 缺角色/角色未知：不猜顺序，整条存 uninterpreted）

METS 映射：
  fileSec/fileGrp@ID + @ADMID                   -> representation（ADMID 指向
                                                   amdSec/mdWrap 内的 PREMIS 对象）
  fileSec/fileGrp/file/FLocat@xlink:href        -> 包内成员路径
  file@ADMID                                    -> 成员 bitstream 的 PREMIS 身份
  structMap/div@ID,@LABEL + div/fptr@FILEID     -> 结构节点 -> representation
"""
from __future__ import annotations

import xml.etree.ElementTree as ET

from .util import (
    PREMIS_NS,
    METS_NS,
    KNOWN_ROLES,
    localname,
    direct_children,
    one_child,
    text_of,
)


class ProfileError(Exception):
    """违反 profile 的结构（不是坏字节，而是映射不成立）。"""


def _raw(el):
    return ET.tostring(el, encoding="unicode")


def _event_c14n_substrings(canon_text):
    """
    在已整体 C14N 的 PREMIS 文本上，按事件元素边界切出每个事件的规范子串。
    C14N 后命名空间前缀统一（premis:），且 event 元素不嵌套同名 event 标签，
    因此可用非贪婪匹配可靠切分，避免对每个事件再跑一次 XMLParser。
    返回 [(event_id_value, 事件规范子串)]。
    """
    import re

    out = []
    for m in re.finditer(
        r"<premis:event>.*?</premis:event>", canon_text, flags=re.DOTALL
    ):
        sub = m.group(0)
        idm = re.search(
            r"<premis:eventIdentifierValue>(.*?)</premis:eventIdentifierValue>",
            sub,
            flags=re.DOTALL,
        )
        if idm:
            out.append((idm.group(1), sub))
    return out


def _findall(el, ns_name):
    return el.findall(ns_name)


def parse_premis(path, canon_text=None):
    if canon_text is not None:
        # 在已整体 C14N 的文档上解析：命名空间已统一，事件子树序列化稳定，
        # 跨包同一事件得到一致哈希，且无需对每个事件再跑一次解析器。
        root = ET.fromstring(canon_text)
        # 一次性切出各事件的规范子串作为身份哈希依据
        c14n_by_id = dict(_event_c14n_substrings(canon_text))
    else:
        root = ET.parse(path).getroot()
        c14n_by_id = {}
    objects = []
    events = []
    object_unint = []
    event_unint = []

    for obj in root.findall("{%s}object" % PREMIS_NS):
        oi = one_child(obj, "objectIdentifier")
        if oi is None:
            raise ProfileError("premis:object without objectIdentifier in %s" % path)
        id_type = text_of(oi, "objectIdentifierType")
        id_value = text_of(oi, "objectIdentifierValue")
        if not id_type or not id_value:
            raise ProfileError("incomplete objectIdentifier in %s" % path)
        category = (text_of(obj, "objectCategory") or "").strip().lower()
        # PREMIS file 与 bitstream 在本 profile 中都作为 bitstream 类成员。
        cls = "representation" if category == "representation" else "bitstream"
        objects.append(
            {
                "id_type": id_type,
                "id_value": id_value,
                "category": category or "(unspecified)",
                "class": cls,
                "xml_rel": None,  # 由调用方填入文档相对路径
            }
        )
        mapped = {"objectIdentifier", "objectCategory"}
        for child in list(obj):
            if localname(child.tag) not in mapped:
                object_unint.append(
                    {
                        "id_type": id_type,
                        "id_value": id_value,
                        "local_name": localname(child.tag),
                        "raw_xml": _raw(child),
                    }
                )

    for evt in root.findall("{%s}event" % PREMIS_NS):
        ei = one_child(evt, "eventIdentifier")
        if ei is None:
            raise ProfileError("premis:event without eventIdentifier in %s" % path)
        ev_type_id = text_of(ei, "eventIdentifierType")
        event_id = text_of(ei, "eventIdentifierValue")
        if not event_id:
            raise ProfileError("incomplete eventIdentifier in %s" % path)

        event_type = (text_of(evt, "eventType") or "").strip().lower()
        event_dt = text_of(evt, "eventDateTime")

        outcome = "unknown"
        eoi = one_child(evt, "eventOutcomeInformation")
        if eoi is not None:
            raw_outcome = (text_of(eoi, "eventOutcome") or "").strip().lower()
            if raw_outcome in ("success", "failed", "unknown"):
                outcome = raw_outcome
            # 非受控词：按 unknown 处理，原值随 detail 一并 uninterpreted
            for child in list(eoi):
                if localname(child.tag) != "eventOutcome":
                    event_unint.append(
                        {
                            "event_id": event_id,
                            "local_name": localname(child.tag),
                            "raw_xml": _raw(child),
                        }
                    )
            if raw_outcome and raw_outcome not in ("success", "failed", "unknown"):
                event_unint.append(
                    {
                        "event_id": event_id,
                        "local_name": "eventOutcome(non-controlled)",
                        "raw_xml": raw_outcome,
                    }
                )

        links = []
        for loi in direct_children(evt, "linkingObjectIdentifier"):
            lot = text_of(loi, "linkingObjectIdentifierType")
            lov = text_of(loi, "linkingObjectIdentifierValue")
            role_el = one_child(loi, "linkingObjectRole")
            role = role_el.text.strip().lower() if role_el is not None and role_el.text else ""
            if role in KNOWN_ROLES and lot and lov:
                links.append(
                    {"role": role, "obj_id_type": lot, "obj_id_value": lov}
                )
            else:
                # 角色缺失/未知或身份不全：绝不按顺序猜，整条保留为 uninterpreted
                event_unint.append(
                    {
                        "event_id": event_id,
                        "local_name": "linkingObjectIdentifier(role=%s)" % role,
                        "raw_xml": _raw(loi),
                    }
                )

        events.append(
            {
                "event_id": event_id,
                "event_id_type": ev_type_id or "(unspecified)",
                "event_type": event_type or "(unspecified)",
                "event_dt": event_dt,
                "outcome": outcome,
                "links": links,
                # 事件身份哈希依据：优先取整文档 C14N 后切出的事件规范子串
                # （零额外解析）；无规范化文本时退回对子树单独 C14N。
                "c14n": c14n_by_id.get(
                    event_id,
                    ET.canonicalize(
                        ET.tostring(evt), strip_text=False, with_comments=True
                    ),
                ),
            }
        )

        mapped = {
            "eventIdentifier",
            "eventType",
            "eventDateTime",
            "eventOutcomeInformation",
            "linkingObjectIdentifier",
        }
        for child in list(evt):
            if localname(child.tag) not in mapped:
                event_unint.append(
                    {
                        "event_id": event_id,
                        "local_name": localname(child.tag),
                        "raw_xml": _raw(child),
                    }
                )

    # 非 object/event 的顶层元素（如 agent、rights）整体 uninterpreted
    for child in list(root):
        if localname(child.tag) not in ("object", "event"):
            object_unint.append(
                {
                    "id_type": "",
                    "id_value": "",
                    "local_name": "premis:%s" % localname(child.tag),
                    "raw_xml": _raw(child),
                }
            )

    return {
        "objects": objects,
        "events": events,
        "object_uninterpreted": object_unint,
        "event_uninterpreted": event_unint,
    }


def parse_mets(path):
    tree = ET.parse(path)
    root = tree.getroot()

    def q(tag):
        return "{%s}%s" % (METS_NS, tag)

    # amdSec/mdWrap 注册表：ADMID -> 内嵌 PREMIS 对象身份（若有）
    admid_objects = {}
    for mdwrap in root.iter(q("mdWrap")):
        wrap_id = mdwrap.get("ID")
        xmldata = one_child(mdwrap, "xmlData")
        if xmldata is None:
            continue
        pobj = xmldata.find("{%s}object" % PREMIS_NS)
        if pobj is not None:
            oi = one_child(pobj, "objectIdentifier")
            if oi is not None:
                admid_objects[wrap_id] = (
                    text_of(oi, "objectIdentifierType"),
                    text_of(oi, "objectIdentifierValue"),
                )

    filegrps = {}
    file_sec = one_child(root, "fileSec")
    if file_sec is not None:
        for fg in direct_children(file_sec, "fileGrp"):
            fg_id = fg.get("ID")
            if not fg_id:
                raise ProfileError("mets:fileGrp without ID in %s" % path)
            fg_admids = (fg.get("ADMID") or "").split()
            rep_identity = None
            for aid in fg_admids:
                if aid in admid_objects:
                    rep_identity = admid_objects[aid]
            files = []
            for f in fg.iter(q("file")):
                f_id = f.get("ID")
                flocat = one_child(f, "FLocat")
                href = flocat.get("{http://www.w3.org/1999/xlink}href") if flocat is not None else None
                if not f_id or not href:
                    raise ProfileError(
                        "mets:file missing ID/FLocat in fileGrp %s (%s)" % (fg_id, path)
                    )
                f_admids = (f.get("ADMID") or "").split()
                obj_identity = None
                for aid in f_admids:
                    if aid in admid_objects:
                        obj_identity = admid_objects[aid]
                files.append(
                    {
                        "file_id": f_id,
                        "href": href,
                        "admids": f_admids,
                        "identity": obj_identity,
                    }
                )
            filegrps[fg_id] = {
                "admids": fg_admids,
                "rep_identity": rep_identity,
                "files": files,
            }

    struct = []
    for sm in root.findall(".//" + q("structMap")):
        for div in sm.iter(q("div")):
            node_id = div.get("ID")
            if not node_id:
                continue
            fptrs = direct_children(div, "fptr")
            if len(fptrs) > 1:
                raise ProfileError(
                    "struct node %s has multiple fptr; profile allows one representation"
                    % node_id
                )
            target = fptrs[0].get("FILEID") if fptrs else None
            if target is not None and target not in filegrps:
                raise ProfileError(
                    "struct node %s fptr@FILEID=%r is not a fileGrp representation"
                    % (node_id, target)
                )
            struct.append(
                {"node_id": node_id, "label": div.get("LABEL"), "fptr": target}
            )

    return {"filegrps": filegrps, "struct": struct, "admid_objects": admid_objects}
