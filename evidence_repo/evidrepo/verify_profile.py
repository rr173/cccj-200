# -*- coding: utf-8 -*-
"""
画像结果离线自校验器（独立模块：不 import 仓内任何模块，可在仓库外运行）。

画像结果文件可复制到仓库外校验。校验器**只**检查文件自身的一致性与
绑定信息，**绝不重新运行格式匹配**来伪造原始运行：

1. 内容寻址：重算业务内容（剔除 generated_at / content_sha256 /
   profile_id 后的规范化 JSON）的 SHA-256，必须等于 content_sha256
   且等于 profile_id；
2. 输入绑定：封存包集合有序且其清单摘要一致；目录绑定字段齐全、
   摘要形态合法；每个对象记录的目录绑定与头部一致；
3. 汇总自洽：objects_total 与各状态/结果计数、逐对象记录、各格式
   对象数全部交叉一致；
4. 证据结构：命中签名的每条必需片段有命中数、偏移与匹配字节；
   匹配字节与片段模式在掩码下自洽（这只核对证据内部一致性，
   不访问任何载荷、不重做搜索）；禁止片段命中数必须为 0；
5. 结果语义：identified/ambiguous/unidentified 与命中签名集合一致；
   非 bytes_ok 对象不得携带命中、格式或内容摘要（损坏/缺失/冲突
   不得被签名命中掩盖）；
6. 文件内不得出现工作流相关的绝对路径（身份值等业务事实除外）。

仅使用 Python 标准库。
"""
from __future__ import annotations

import hashlib
import json
import os
import re

PROFILE_PROFILE = "offline-evidence-repo/format-profile/v1"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
HEX_RE = re.compile(r"^[0-9a-f]*$")

RESULTS = ("identified", "ambiguous", "unidentified")
BYTE_STATES = ("bytes_ok", "bytes_missing", "bytes_corrupt",
               "not_received", "identity_conflict")
INVALID_STATES = ("bytes_missing", "bytes_corrupt", "not_received")
MAX_EVIDENCE_OFFSETS = 8


def _canon(obj):
    return json.dumps(
        obj, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def _content_for_hash(doc):
    return {
        k: v
        for k, v in doc.items()
        if k not in ("generated_at", "profile_id", "content_sha256")
    }


def _check_fragment_shape(frag, errors, where):
    if not isinstance(frag, dict):
        errors.append("%s: fragment is not an object" % where)
        return None
    if not set(frag.keys()) <= {"bytes", "mask", "offset", "window"}:
        errors.append("%s: fragment has unknown keys %r"
                      % (where, sorted(frag.keys())))
        return None
    pat_hex = frag.get("bytes")
    if not isinstance(pat_hex, str) or not pat_hex or \
            len(pat_hex) % 2 or not HEX_RE.match(pat_hex):
        errors.append("%s: fragment bytes is not even-length hex" % where)
        return None
    pat = bytes.fromhex(pat_hex)
    mask = None
    if "mask" in frag:
        m = frag["mask"]
        if not isinstance(m, str) or len(m) != len(pat_hex) or \
                not HEX_RE.match(m):
            errors.append("%s: fragment mask malformed" % where)
            return None
        mask = bytes.fromhex(m)
    has_off = "offset" in frag
    has_win = "window" in frag
    if has_off == has_win:
        errors.append("%s: fragment needs exactly one of offset/window"
                      % where)
        return None
    if has_off and (not isinstance(frag["offset"], int)
                    or isinstance(frag["offset"], bool)
                    or frag["offset"] < 0):
        errors.append("%s: bad fragment offset" % where)
        return None
    if has_win:
        w = frag["window"]
        if not (isinstance(w, list) and len(w) == 2
                and all(isinstance(x, int) and not isinstance(x, bool)
                        and x >= 0 for x in w) and w[0] <= w[1]):
            errors.append("%s: bad fragment window" % where)
            return None
    return pat, mask


def _check_hit(hit, errors, where):
    fmt = hit.get("format_id")
    if not isinstance(hit.get("signature_id"), str) or \
            not isinstance(fmt, str):
        errors.append("%s: hit missing signature_id/format_id" % where)
        return None
    req = hit.get("required")
    forb = hit.get("forbidden")
    if not isinstance(req, list) or not req:
        errors.append("%s: hit required evidence must be a non-empty list"
                      % where)
        return None
    if not isinstance(forb, list):
        errors.append("%s: hit forbidden evidence must be a list" % where)
        return None
    for i, ev in enumerate(req):
        w = "%s required[%d]" % (where, i)
        parsed = _check_fragment_shape(ev.get("fragment"), errors, w)
        mc = ev.get("match_count")
        offs = ev.get("offsets")
        if not isinstance(mc, int) or isinstance(mc, bool) or mc < 1:
            errors.append("%s: required fragment match_count must be >= 1"
                          % w)
        if not isinstance(offs, list) or not offs or \
                len(offs) > MAX_EVIDENCE_OFFSETS or \
                not all(isinstance(o, int) and not isinstance(o, bool)
                        and o >= 0 for o in offs) or \
                offs != sorted(offs):
            errors.append("%s: required fragment offsets malformed" % w)
        elif mc < len(offs):
            errors.append("%s: match_count < len(offsets)" % w)
        mb = ev.get("matched_bytes")
        if parsed is not None:
            pat, mask = parsed
            if not isinstance(mb, str) or len(mb) != 2 * len(pat) or \
                    not HEX_RE.match(mb):
                errors.append("%s: matched_bytes missing or wrong length"
                              % w)
            else:
                actual = bytes.fromhex(mb)
                if mask is not None:
                    for k in range(len(pat)):
                        if (actual[k] & mask[k]) != (pat[k] & mask[k]):
                            errors.append(
                                "%s: matched_bytes inconsistent with "
                                "masked pattern" % w)
                            break
                elif actual != pat:
                    errors.append(
                        "%s: matched_bytes inconsistent with pattern" % w)
    for i, ev in enumerate(forb):
        w = "%s forbidden[%d]" % (where, i)
        _check_fragment_shape(ev.get("fragment"), errors, w)
        if ev.get("match_count") != 0 or ev.get("offsets") != []:
            errors.append("%s: forbidden fragment recorded as present" % w)
    return fmt


def verify_profile(profile_path):
    """校验画像结果文件；返回 {ok, checks, errors, ...}。可任意搬迁。"""
    profile_path = os.path.abspath(profile_path)
    errors, checks = [], []
    if os.path.isdir(profile_path):
        profile_path = os.path.join(profile_path, "profile.json")
    if not os.path.isfile(profile_path):
        return {
            "ok": False,
            "errors": ["profile file missing: %s"
                       % os.path.basename(profile_path)],
            "checks": [],
        }
    with open(profile_path, "rb") as f:
        raw = f.read()
    try:
        doc = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        return {"ok": False, "errors": ["invalid profile JSON: %s" % exc],
                "checks": []}
    if not isinstance(doc, dict):
        return {"ok": False, "errors": ["profile is not a JSON object"],
                "checks": []}

    for field in ("profile", "engine", "generated_at", "inputs", "summary",
                  "objects", "content_sha256", "profile_id"):
        if field not in doc:
            errors.append("missing required field %r" % field)
    if errors:
        return {"ok": False, "errors": errors, "checks": checks}

    if doc["profile"] != PROFILE_PROFILE:
        errors.append("unexpected profile marker %r" % doc["profile"])

    # 1) 内容寻址
    recomputed = _sha(_canon(_content_for_hash(doc)))
    checks.append("recomputed profile content SHA-256")
    if doc["content_sha256"] != recomputed:
        errors.append("content_sha256 mismatch: stored=%s recomputed=%s"
                      % (doc["content_sha256"], recomputed))
    if doc["profile_id"] != recomputed:
        errors.append("profile_id is not the content address: stored=%s "
                      "recomputed=%s" % (doc["profile_id"], recomputed))

    # 2) 输入绑定
    inputs = doc["inputs"]
    cat = inputs.get("catalog", {})
    for field in ("catalog_id", "catalog_version", "catalog_sha256",
                  "format_count", "signature_count"):
        if field not in cat:
            errors.append("catalog binding missing %r" % field)
    if not isinstance(cat.get("catalog_sha256"), str) or \
            not SHA256_RE.match(cat.get("catalog_sha256", "")):
        errors.append("catalog_sha256 is not 64-hex")
    pkgs = inputs.get("packages", {})
    pkg_set = pkgs.get("package_set")
    if not isinstance(pkg_set, list) or \
            not all(isinstance(p, str) for p in pkg_set):
        errors.append("package_set binding malformed")
        pkg_set = None
    else:
        if pkg_set != sorted(pkg_set):
            errors.append("package_set is not sorted")
        if _sha(_canon(pkg_set)) != pkgs.get("package_set_sha256"):
            errors.append("package_set_sha256 mismatch")
    checks.append("catalog and sealed package set binding verified")

    # 3) 逐对象记录与汇总自洽
    objects = doc["objects"]
    if not isinstance(objects, list):
        errors.append("objects is not a list")
        objects = []
    head_cat = (cat.get("catalog_id"), cat.get("catalog_version"),
                cat.get("catalog_sha256"))
    counts = {r: 0 for r in RESULTS}
    states = {s: 0 for s in BYTE_STATES}
    fmt_hist = {}
    seen_identities = set()
    for i, obj in enumerate(objects):
        where = "objects[%d]" % i
        ident = (obj.get("identifierType"), obj.get("identifierValue"))
        if not all(isinstance(x, str) for x in ident):
            errors.append("%s: identity malformed" % where)
            continue
        if ident in seen_identities:
            errors.append("%s: duplicate object identity %r" % (where, ident))
        seen_identities.add(ident)
        oc = obj.get("catalog", {})
        if (oc.get("catalog_id"), oc.get("catalog_version"),
                oc.get("catalog_sha256")) != head_cat:
            errors.append("%s: per-object catalog binding differs from "
                          "inputs" % where)
        state = obj.get("byte_state")
        if state not in BYTE_STATES:
            errors.append("%s: unknown byte_state %r" % (where, state))
            continue
        states[state] += 1
        result = obj.get("result")
        hits = obj.get("hits")
        formats = obj.get("formats")
        if state == "bytes_ok":
            if result not in RESULTS:
                errors.append("%s: bytes_ok object has bad result %r"
                              % (where, result))
                continue
            counts[result] += 1
            if not isinstance(obj.get("content_sha256"), str) or \
                    not SHA256_RE.match(obj.get("content_sha256", "")):
                errors.append("%s: bytes_ok object missing content digest"
                              % where)
            if not isinstance(obj.get("content_length"), int) or \
                    obj.get("content_length", -1) < 0:
                errors.append("%s: bytes_ok object missing content length"
                              % where)
            if not isinstance(obj.get("byte_source"), dict):
                errors.append("%s: bytes_ok object missing byte_source"
                              % where)
            if not isinstance(hits, list) or not isinstance(formats, list):
                errors.append("%s: bytes_ok object hits/formats malformed"
                              % where)
                continue
            hit_formats = []
            for j, hit in enumerate(hits):
                fmt = _check_hit(hit, errors, "%s hits[%d]" % (where, j))
                if fmt is not None:
                    hit_formats.append(fmt)
            if sorted(set(hit_formats)) != sorted(formats):
                errors.append("%s: formats != distinct hit formats" % where)
            expect = ("unidentified" if not hits
                      else "identified" if len(set(hit_formats)) == 1
                      else "ambiguous")
            if result != expect:
                errors.append("%s: result %r inconsistent with hits (%r)"
                              % (where, result, expect))
            if result == "identified" and formats:
                fmt_hist[formats[0]] = fmt_hist.get(formats[0], 0) + 1
        else:
            # 非 bytes_ok：不得被签名命中掩盖
            for field in ("result", "hits", "formats", "content_sha256",
                          "content_length", "byte_source"):
                if obj.get(field) is not None:
                    errors.append("%s: %s object must not carry %s"
                                  % (where, state, field))
        if not isinstance(obj.get("package_ids"), list) or \
                not obj["package_ids"]:
            errors.append("%s: package_ids missing" % where)
        if not isinstance(obj.get("copies"), list):
            errors.append("%s: copies missing" % where)
    checks.append("per-object records cross-checked (identity, catalog "
                  "binding, evidence structure, result semantics)")

    s = doc["summary"]
    n_ok = states["bytes_ok"]
    expect = {
        "objects_total": len(objects),
        "identified": counts["identified"],
        "ambiguous": counts["ambiguous"],
        "unidentified": counts["unidentified"],
        "bytes_invalid": sum(states[x] for x in INVALID_STATES),
        "identity_conflict": states["identity_conflict"],
    }
    for key, want in expect.items():
        if s.get(key) != want:
            errors.append("summary.%s=%r != recomputed %r"
                          % (key, s.get(key), want))
    if counts["identified"] + counts["ambiguous"] + counts["unidentified"] \
            != n_ok:
        errors.append("result counts do not add up to bytes_ok objects")
    if s.get("formats", {}) != fmt_hist:
        errors.append("summary.formats histogram inconsistent with "
                      "identified objects")
    by_state = s.get("by_byte_state", {})
    for st in BYTE_STATES:
        if by_state.get(st) != states[st]:
            errors.append("summary.by_byte_state.%s inconsistent" % st)
    checks.append("summary counts cross-checked against per-object records")

    # 4) 绝对路径检查（身份/标识类业务字段除外）
    identity_keys = {"identifierValue", "identifierType", "catalog_id",
                     "catalog_version", "package_id", "rel_path",
                     "signature_id", "format_id"}
    bad_paths = []

    def _walk(node):
        if isinstance(node, dict):
            for k, v in node.items():
                if isinstance(v, str) and v.startswith("/") \
                        and k not in identity_keys:
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
        errors.append("profile contains absolute filesystem path(s) in "
                      "non-identity fields: %r" % (bad_paths[:4],))
    checks.append("profile contains no workflow-dependent absolute paths")

    return {
        "ok": not errors,
        "profile_id": doc.get("profile_id"),
        "content_sha256": doc.get("content_sha256"),
        "catalog": {
            "catalog_id": cat.get("catalog_id"),
            "catalog_version": cat.get("catalog_version"),
            "catalog_sha256": cat.get("catalog_sha256"),
        },
        "bound_package_set": pkg_set,
        "summary": doc.get("summary"),
        "checks": checks,
        "errors": errors,
    }
