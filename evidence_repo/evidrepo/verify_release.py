# -*- coding: utf-8 -*-
"""
外发目录离线自校验器（独立模块：不 import 仓内计划/规则/求值代码）。

目录搬离仓库后，校验器**只根据公开格式与公开清单**检查：
1. 目录布局受控：根目录仅允许 release-manifest.json 与 payloads/ 目录，
   payloads/ 下仅允许 f-<16hex>.bin；拒绝多余文件、缺文件、路径逃逸、
   符号链接（任何层级）；
2. 成员引用：清单中每个表示的每个成员都引用一个存在的受控文件，
   文件集合与引用集合完全一致（无孤儿、无缺失）；
3. 实际字节：分块重算每个文件的 SHA-256 与长度，与清单声明一致；
4. 清单字段受控：只允许 profile/audience/files/representations 等公开字段，
   不接受任何馆内身份、原件摘要、路径、规则、原因、计划号等泄漏字段。

它只检验“目录自身一致性”；规则是否确实落实由馆内独立验收判断（见 §15）。
仅使用 Python 标准库。
"""
from __future__ import annotations

import hashlib
import json
import os
import re

CHUNK = 1 << 20
MANIFEST_NAME = "release-manifest.json"
PAYLOAD_DIR = "payloads"
MANIFEST_PROFILE = "offline-evidence-repo/release-manifest/v1"
FILENAME_RE = re.compile(r"^f-[0-9a-f]{64}\.bin$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")

ALLOWED_TOP = {MANIFEST_NAME, PAYLOAD_DIR}
ALLOWED_MANIFEST_FIELDS = {"profile", "audience", "files", "representations"}
ALLOWED_FILE_FIELDS = {"file", "size", "sha256"}
ALLOWED_REP_FIELDS = {"external_code", "members"}
ALLOWED_MEMBER_FIELDS = {"file", "size", "sha256"}
EXTERNAL_CODE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


class OfflineVerifyError(Exception):
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


def _walk_no_symlinks(root):
    """产出 (abs_path, is_dir)；遇到符号链接即拒绝（根自身也不许是链接）。"""
    if os.path.islink(root):
        raise OfflineVerifyError("directory root is a symlink")
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        for name in dirnames:
            full = os.path.join(dirpath, name)
            if os.path.islink(full):
                raise OfflineVerifyError("symlink not allowed: %s" % name)
            yield full, True
        for name in filenames:
            full = os.path.join(dirpath, name)
            if os.path.islink(full):
                raise OfflineVerifyError("symlink not allowed: %s" % name)
            yield full, False


def verify_release(release_dir):
    release_dir = os.path.abspath(release_dir)
    errors, checks = [], []
    if not os.path.isdir(release_dir) or os.path.islink(release_dir):
        return {
            "ok": False,
            "errors": ["release directory missing or is a symlink: %s"
                       % release_dir],
            "checks": [],
        }

    # 1. 目录树受控（含路径逃逸/符号链接/多余文件）
    try:
        entries = list(_walk_no_symlinks(release_dir))
    except OfflineVerifyError as exc:
        return {"ok": False, "errors": [str(exc)], "checks": []}
    # 目录只做符号链接与顶层受控检查；文件名规则只施加在普通文件上
    dir_rels = sorted(
        os.path.relpath(p, release_dir) for p, is_dir in entries if is_dir
    )
    for rel in dir_rels:
        parts = rel.split(os.sep)
        if parts[0] not in ALLOWED_TOP or len(parts) > 1:
            errors.append("unexpected directory entry: %s" % rel)
    rels = sorted(
        os.path.relpath(p, release_dir) for p, is_dir in entries if not is_dir
    )
    top = sorted({r.split(os.sep)[0] for r in rels})
    if set(top) - ALLOWED_TOP:
        errors.append(
            "unexpected top-level entries: %s"
            % sorted(set(top) - ALLOWED_TOP)
        )
    payload_files = set()
    for rel in rels:
        parts = rel.split(os.sep)
        if parts[0] == PAYLOAD_DIR:
            if len(parts) != 2:
                errors.append("nested/escaped entry under payloads: %s" % rel)
            elif not FILENAME_RE.match(parts[1]):
                errors.append("payload file name not controlled: %s" % rel)
            else:
                payload_files.add(parts[1])
        elif parts[0] != MANIFEST_NAME:
            errors.append("unexpected entry: %s" % rel)
    checks.append("directory layout and controlled file names checked")

    manifest_path = os.path.join(release_dir, MANIFEST_NAME)
    if not os.path.isfile(manifest_path):
        errors.append("missing manifest: %s" % MANIFEST_NAME)
        return {"ok": False, "errors": errors, "checks": checks}
    try:
        with open(manifest_path, "rb") as f:
            raw = f.read()
        doc = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        errors.append("manifest is not valid UTF-8 JSON: %s" % exc)
        return {"ok": False, "errors": errors, "checks": checks}

    # 2. 清单字段受控（拒绝任何馆内泄漏字段）
    if not isinstance(doc, dict):
        errors.append("manifest root must be an object")
        return {"ok": False, "errors": errors, "checks": checks}
    if set(doc.keys()) - ALLOWED_MANIFEST_FIELDS:
        errors.append(
            "manifest contains undeclared fields: %s"
            % sorted(set(doc.keys()) - ALLOWED_MANIFEST_FIELDS)
        )
    if doc.get("profile") != MANIFEST_PROFILE:
        errors.append("manifest profile mismatch: %r" % doc.get("profile"))
    audience = doc.get("audience")
    if not isinstance(audience, str) or not audience:
        errors.append("manifest audience must be a non-empty string")
    files = doc.get("files")
    reps = doc.get("representations")
    if not isinstance(files, list) or not isinstance(reps, list) or not reps:
        errors.append("manifest requires non-empty files[] and representations[]")
        return {"ok": False, "errors": errors, "checks": checks}

    named_files, seen_names = {}, set()
    for entry in files:
        if set(entry.keys()) - ALLOWED_FILE_FIELDS:
            errors.append("file entry has undeclared fields: %r" % entry)
        name = entry.get("file")
        if not isinstance(name, str) or not FILENAME_RE.match(name):
            errors.append("bad controlled file name: %r" % name)
            continue
        if name in seen_names:
            errors.append("duplicate file entry: %s" % name)
        seen_names.add(name)
        if not isinstance(entry.get("size"), int) or isinstance(
            entry.get("size"), bool
        ) or entry["size"] < 0:
            errors.append("file %s has bad size" % name)
        sha = entry.get("sha256")
        if not isinstance(sha, str) or not SHA256_RE.match(sha):
            errors.append("file %s has bad sha256" % name)
        named_files[name] = entry

    referenced = set()
    ext_codes = set()
    for rep in reps:
        if set(rep.keys()) - ALLOWED_REP_FIELDS:
            errors.append("representation entry has undeclared fields: %r" % rep)
        code = rep.get("external_code")
        if not isinstance(code, str) or not EXTERNAL_CODE_RE.match(code):
            errors.append("bad external_code: %r" % code)
        elif code in ext_codes:
            errors.append("duplicate external_code: %s" % code)
        else:
            ext_codes.add(code)
        members = rep.get("members")
        if not isinstance(members, list) or not members:
            errors.append("representation %r must have members" % code)
            continue
        for m in members:
            if set(m.keys()) - ALLOWED_MEMBER_FIELDS:
                errors.append("member entry has undeclared fields: %r" % m)
            name = m.get("file")
            if name not in named_files:
                errors.append(
                    "member references file not declared in files[]: %s" % name
                )
                continue
            referenced.add(name)
            if m.get("size") != named_files[name].get("size") or \
                    m.get("sha256") != named_files[name].get("sha256"):
                errors.append(
                    "member record disagrees with files[] for %s" % name
                )
    checks.append("manifest fields, external codes and member references checked")

    # 3. 文件集合 == 引用集合 == 磁盘集合
    if named_files and referenced != set(named_files):
        orphan = set(named_files) - referenced
        missing_ref = referenced - set(named_files)
        if orphan:
            errors.append("files not referenced by any representation: %s"
                          % sorted(orphan))
        if missing_ref:
            errors.append("referenced files absent from files[]: %s"
                          % sorted(missing_ref))
    on_disk = payload_files
    if set(named_files) != on_disk:
        errors.append(
            "on-disk payload set differs from manifest: missing=%s extra=%s"
            % (sorted(set(named_files) - on_disk),
               sorted(on_disk - set(named_files)))
        )
    checks.append("file set equality (manifest vs references vs disk) checked")

    # 4. 实际字节哈希/长度（分块重算）
    for name, entry in sorted(named_files.items()):
        p = os.path.join(release_dir, PAYLOAD_DIR, name)
        if not os.path.isfile(p) or os.path.islink(p):
            errors.append("payload missing or symlink: %s" % name)
            continue
        digest = _sha256(p)
        size = os.path.getsize(p)
        if digest != entry["sha256"]:
            errors.append(
                "sha256 mismatch for %s: manifest=%s recomputed=%s"
                % (name, entry["sha256"], digest)
            )
        if size != entry["size"]:
            errors.append(
                "size mismatch for %s: manifest=%d actual=%d"
                % (name, entry["size"], size)
            )
    checks.append("recomputed SHA-256 and length for %d payloads (chunked)"
                  % len(named_files))

    return {
        "ok": not errors,
        "manifest": MANIFEST_NAME,
        "audience": audience,
        "file_count": len(named_files),
        "representation_count": len(reps),
        "checks": checks,
        "errors": errors,
    }
