# -*- coding: utf-8 -*-
"""
合成交接包构造器（测试/演练用；这些包是“不受信输入数据”，放在独立目录）。

生成的每个包：
  manifest.json                信任起点声明（调用者给定）
  metadata/premis.xml          PREMIS 3 对象与事件
  metadata/mets.xml            METS fileSec/structMap
  content/<file>               二进制成员
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil

PREMIS_NS = "http://www.loc.gov/premis/v3"
METS_NS = "http://www.loc.gov/METS/"
XLINK_NS = "http://www.w3.org/1999/xlink"


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


class PackageBuilder:
    def __init__(self, root, package_id, trusted_ingest=()):
        self.root = os.path.join(root, package_id)
        self.package_id = package_id
        self.trusted = list(trusted_ingest)
        if os.path.exists(self.root):
            shutil.rmtree(self.root)
        os.makedirs(os.path.join(self.root, "content"))
        os.makedirs(os.path.join(self.root, "metadata"))
        # id -> (type, value, category, bytes|None)
        self.objects = {}
        # event_id -> dict
        self.events = {}
        # rep value -> {"members":[ident...], "nodes":[...], "filegrp": str}
        self.reps = {}
        self.missing_files = set()
        self.corrupt_files = set()
        self.extensions = []

    # ---- 内容 -------------------------------------------------------------
    def add_bitstream(self, value, data, id_type="local"):
        self.objects[value] = (id_type, value, "bitstream", data)
        return (id_type, value)

    def add_ref_only(self, value, id_type="local", category="bitstream"):
        """仅声明 PREMIS 对象身份，本包不承载其字节（跨包引用）。"""
        self.objects[value] = (id_type, value, category, None)
        return (id_type, value)

    def add_representation(self, value, members, nodes=(), id_type="local",
                           filegrp=None):
        self.objects[value] = (id_type, value, "representation", None)
        self.reps[value] = {
            "members": list(members),
            "nodes": list(nodes),
            "filegrp": filegrp or ("GRP-" + value),
        }
        return (id_type, value)

    def add_event(self, event_id, etype, inputs=(), outputs=(), outcome="success",
                  dt="2026-01-01T00:00:00Z", untrusted_role_links=(),
                  extra_extension=None):
        self.events[event_id] = {
            "type": etype,
            "inputs": list(inputs),
            "outputs": list(outputs),
            "outcome": outcome,
            "dt": dt,
            "untrusted_role_links": list(untrusted_role_links),
            "extra_extension": extra_extension,
        }

    def mark_missing(self, obj_value):
        self.missing_files.add(obj_value)

    def mark_corrupt(self, obj_value):
        self.corrupt_files.add(obj_value)

    def add_foreign_extension(self, raw_xml_snippet):
        self.extensions.append(raw_xml_snippet)

    # ---- 写出 -------------------------------------------------------------
    def build(self, omit_file_for=()):
        omit = set(omit_file_for) | self.missing_files
        manifest_members, file_meta = [], {}
        for value, (id_type, _v, cat, data) in self.objects.items():
            if cat != "bitstream":
                continue
            if data is None:
                continue  # 仅引用身份：不产生本包成员条目
            rel = "content/%s.bin" % value
            if value in omit:
                # 仍声明长度/哈希（模拟未到齐），但不落文件
                manifest_members.append(
                    {"rel_path": rel, "size": len(data),
                     "sha256": sha256_bytes(data),
                     "object": {"id_type": id_type, "id_value": value}}
                )
                continue
            payload = data
            if value in self.corrupt_files:
                payload = data + b"\x00CORRUPTION"
            with open(os.path.join(self.root, rel), "wb") as f:
                f.write(payload)
            actual_disk = payload
            file_meta[value] = (rel, len(actual_disk), sha256_bytes(actual_disk))
            # manifest 始终声明“应然”哈希；损坏文件实算哈希会不同
            manifest_members.append(
                {"rel_path": rel, "size": len(data),
                 "sha256": sha256_bytes(data),
                 "object": {"id_type": id_type, "id_value": value}}
            )

        premis_rel = self._write_premis()
        mets_rel = self._write_mets()

        rep_decls = []
        for value, spec in self.reps.items():
            id_type = self.objects[value][0]
            rep_decls.append(
                {
                    "id_type": id_type,
                    "id_value": value,
                    "filegrp": spec["filegrp"],
                    "members": [list(self._ident_of(m)) for m in spec["members"]],
                    "struct_nodes": [
                        {"node_id": n, "label": n} for n in spec["nodes"]
                    ],
                }
            )
        manifest = {
            "package_id": self.package_id,
            "xml": [
                {"rel_path": premis_rel, "kind": "premis"},
                {"rel_path": mets_rel, "kind": "mets"},
            ],
            "members": manifest_members,
            "representations": rep_decls,
            "trusted_ingest_events": self.trusted,
        }
        with open(os.path.join(self.root, "manifest.json"), "w",
                  encoding="utf-8") as f:
            json.dump(manifest, f, ensure_ascii=False, indent=2, sort_keys=True)
        return self.root

    def _ident_of(self, value):
        t, v, _c, _d = self.objects[value]
        return (t, v)

    def _write_premis(self):
        lines = ['<?xml version="1.0" encoding="UTF-8"?>',
                 '<premis:premis xmlns:premis="%s" version="3.0">' % PREMIS_NS]
        for value, (id_type, _v, cat, data) in self.objects.items():
            lines.append("  <premis:object>")
            lines.append("    <premis:objectIdentifier>")
            lines.append("      <premis:objectIdentifierType>%s</premis:objectIdentifierType>"
                         % id_type)
            lines.append("      <premis:objectIdentifierValue>%s</premis:objectIdentifierValue>"
                         % value)
            lines.append("    </premis:objectIdentifier>")
            lines.append("      <premis:objectCategory>%s</premis:objectCategory>" % cat)
            lines.append("  </premis:object>")
        for eid, e in self.events.items():
            lines.append("  <premis:event>")
            lines.append("    <premis:eventIdentifier>")
            lines.append("      <premis:eventIdentifierType>local</premis:eventIdentifierType>")
            lines.append("      <premis:eventIdentifierValue>%s</premis:eventIdentifierValue>"
                         % eid)
            lines.append("    </premis:eventIdentifier>")
            lines.append("    <premis:eventType>%s</premis:eventType>" % e["type"])
            lines.append("    <premis:eventDateTime>%s</premis:eventDateTime>" % e["dt"])
            lines.append("    <premis:eventOutcomeInformation>")
            lines.append("      <premis:eventOutcome>%s</premis:eventOutcome>" % e["outcome"])
            lines.append("    </premis:eventOutcomeInformation>")
            for role, objs in (("input", e["inputs"]), ("output", e["outputs"])):
                for ov in objs:
                    ot, ova = self._ident_of(ov)
                    lines.append("    <premis:linkingObjectIdentifier>")
                    lines.append("      <premis:linkingObjectIdentifierType>%s</premis:linkingObjectIdentifierType>"
                                 % ot)
                    lines.append("      <premis:linkingObjectIdentifierValue>%s</premis:linkingObjectIdentifierValue>"
                                 % ova)
                    lines.append("      <premis:linkingObjectRole>%s</premis:linkingObjectRole>"
                                 % role)
                    lines.append("    </premis:linkingObjectIdentifier>")
            for ov in e["untrusted_role_links"]:
                ot, ova = self._ident_of(ov) if isinstance(ov, str) else ov
                lines.append("    <premis:linkingObjectIdentifier>")
                lines.append("      <premis:linkingObjectIdentifierType>%s</premis:linkingObjectIdentifierType>"
                             % ot)
                lines.append("      <premis:linkingObjectIdentifierValue>%s</premis:linkingObjectIdentifierValue>"
                             % ova)
                lines.append("      <premis:linkingObjectRole>witness</premis:linkingObjectRole>")
                lines.append("    </premis:linkingObjectIdentifier>")
            if e["extra_extension"]:
                lines.append("    " + e["extra_extension"])
            lines.append("  </premis:event>")
        for ext in self.extensions:
            lines.append("  " + ext)
        lines.append("</premis:premis>")
        rel = "metadata/premis.xml"
        with open(os.path.join(self.root, rel), "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
        return rel

    def _write_mets(self):
        lines = ['<?xml version="1.0" encoding="UTF-8"?>',
                 '<mets:mets xmlns:mets="%s" xmlns:xlink="%s" '
                 'xmlns:premis="%s">' % (METS_NS, XLINK_NS, PREMIS_NS),
                 "  <mets:amdSec>"]
        admid_map = {}
        for value, (id_type, _v, cat, data) in self.objects.items():
            if cat != "representation":
                continue
            adm = "ADM-%s" % value
            admid_map[value] = adm
            lines.append('    <mets:mdWrap ID="%s" MDTYPE="PREMIS">' % adm)
            lines.append("      <mets:xmlData>")
            lines.append("        <premis:object>")
            lines.append("          <premis:objectIdentifier>")
            lines.append("            <premis:objectIdentifierType>%s</premis:objectIdentifierType>"
                         % id_type)
            lines.append("            <premis:objectIdentifierValue>%s</premis:objectIdentifierValue>"
                         % value)
            lines.append("          </premis:objectIdentifier>")
            lines.append("          <premis:objectCategory>representation</premis:objectCategory>")
            lines.append("        </premis:object>")
            lines.append("      </mets:xmlData>")
            lines.append("    </mets:mdWrap>")
        # bitstream ADMID
        for value, (id_type, _v, cat, data) in self.objects.items():
            if cat != "bitstream":
                continue
            adm = "ADM-%s" % value
            lines.append('    <mets:mdWrap ID="%s" MDTYPE="PREMIS">' % adm)
            lines.append("      <mets:xmlData>")
            lines.append("        <premis:object>")
            lines.append("          <premis:objectIdentifier>")
            lines.append("            <premis:objectIdentifierType>%s</premis:objectIdentifierType>"
                         % id_type)
            lines.append("            <premis:objectIdentifierValue>%s</premis:objectIdentifierValue>"
                         % value)
            lines.append("          </premis:objectIdentifier>")
            lines.append("          <premis:objectCategory>bitstream</premis:objectCategory>")
            lines.append("        </premis:object>")
            lines.append("      </mets:xmlData>")
            lines.append("    </mets:mdWrap>")
        lines.append("  </mets:amdSec>")
        lines.append("  <mets:fileSec>")
        for value, spec in self.reps.items():
            lines.append('    <mets:fileGrp ID="%s" ADMID="%s">'
                         % (spec["filegrp"], admid_map[value]))
            for i, mv in enumerate(spec["members"]):
                mt, mva = self._ident_of(mv)
                lines.append('      <mets:file ID="F-%s-%d" ADMID="ADM-%s">'
                             % (value, i, mv))
                lines.append('        <mets:FLocat LOCTYPE="URL" '
                             'xlink:type="simple" xlink:href="content/%s.bin"/>' % mv)
                lines.append("      </mets:file>")
            lines.append("    </mets:fileGrp>")
        lines.append("  </mets:fileSec>")
        lines.append('  <mets:structMap TYPE="physical">')
        emitted = set()
        for value, spec in self.reps.items():
            for n in spec["nodes"]:
                if n in emitted:
                    continue
                emitted.add(n)
                lines.append('    <mets:div ID="%s" LABEL="%s">' % (n, n))
                lines.append('      <mets:fptr FILEID="%s"/>' % spec["filegrp"])
                lines.append("    </mets:div>")
        lines.append("  </mets:structMap>")
        lines.append("</mets:mets>")
        rel = "metadata/mets.xml"
        with open(os.path.join(self.root, rel), "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
        return rel
