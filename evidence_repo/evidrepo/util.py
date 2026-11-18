# -*- coding: utf-8 -*-
"""
证据仓基础工具：分块哈希、安全相对路径、XML 规范化、对象身份键。

设计约束（见 profile.md）：
- 所有大文件一律分块读（CHUNK_SIZE），内存不随成员大小增长。
- 仓内只保存相对路径，根目录整体移动后仍可定位与校验。
- 哈希只用于字节完整性，绝不用于对象身份合并（身份 = type+value）。
"""
from __future__ import annotations

import hashlib
import os
import xml.etree.ElementTree as ET

CHUNK_SIZE = 1 << 20  # 1 MiB

# 本仓 profile 支持的命名空间。其他命名空间下的扩展一律按 uninterpreted 保存。
PREMIS_NS = "http://www.loc.gov/premis/v3"
METS_NS = "http://www.loc.gov/METS/"
XLINK_NS = "http://www.w3.org/1999/xlink"

NS = {"premis": PREMIS_NS, "mets": METS_NS, "xlink": XLINK_NS}

# 带角色的 linkingObjectIdentifier 中，本 profile 认可的事件引用角色。
ROLE_INPUT = "input"
ROLE_OUTPUT = "output"
KNOWN_ROLES = (ROLE_INPUT, ROLE_OUTPUT)

# 本 profile 支持的事件类型（其他事件保留事实，不参与证明）。
EVT_INGEST = "ingest"
EVT_COPY = "copy"
EVT_MIGRATION = "migration"
SUPPORTED_EVENT_TYPES = (EVT_INGEST, EVT_COPY, EVT_MIGRATION)

OUTCOME_SUCCESS = "success"

# bitstream 字节/身份状态（题目规定的四态，外加未接收诊断）。
ST_BYTES_OK = "bytes_ok"
ST_BYTES_MISSING = "bytes_missing"
ST_BYTES_CORRUPT = "bytes_corrupt"
ST_IDENTITY_CONFLICT = "identity_conflict"
ST_NOT_RECEIVED = "not_received"

# representation 汇总标签。
REP_VERIFIED = "verified"
REP_INCOMPLETE = "incomplete"
REP_INVALID = "invalid"
REP_UNPROVEN = "unproven"

# 包状态。
PKG_STAGING = "staging"
PKG_SEALED = "sealed"


def sha256_file(path, expected=None):
    """分块计算文件 SHA-256；文件不存在返回 None。"""
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            while True:
                chunk = f.read(CHUNK_SIZE)
                if not chunk:
                    break
                h.update(chunk)
    except FileNotFoundError:
        return None
    digest = h.hexdigest()
    if expected is not None and digest.lower() != str(expected).lower():
        raise HashMismatch(path, expected, digest)
    return digest


class HashMismatch(Exception):
    def __init__(self, path, expected, actual):
        super().__init__(
            "SHA-256 mismatch for %s: expected=%s actual=%s"
            % (path, expected, actual)
        )
        self.path = path
        self.expected = expected
        self.actual = actual


def safe_relpath(rel, root):
    """
    把声明为相对路径的 rel 拼到 root 下，并拒绝路径逃逸（含绝对路径、
    符号链接跳出等）。返回规范化后的绝对路径；逃逸抛 PathEscape。
    """
    if os.path.isabs(rel) or "\x00" in rel:
        raise PathEscape(rel)
    norm = os.path.normpath(rel)
    if norm == ".." or norm.startswith(".." + os.sep) or os.path.isabs(norm):
        raise PathEscape(rel)
    root_abs = os.path.abspath(root)
    target = os.path.abspath(os.path.join(root_abs, norm))
    if target != root_abs and not target.startswith(root_abs + os.sep):
        raise PathEscape(rel)
    return target


class PathEscape(Exception):
    def __init__(self, rel):
        super().__init__("path escapes package root: %r" % rel)
        self.rel = rel


def object_key(id_type, id_value):
    """对象身份键：identifierType + '\\x1f' + identifierValue。"""
    return "%s\x1f%s" % (id_type, id_value)


def split_key(key):
    t, v = key.split("\x1f", 1)
    return t, v


def canonical_xml(path):
    """
    对 XML 文档做 C14N 2.0 规范化（含注释），返回 (canon_bytes, sha256hex)。
    同一逻辑文档在不同包里字节可能有空白差异；按规范化结果判定“同名异内容”。
    """
    tree = ET.parse(path)
    canon = ET.canonicalize(
        ET.tostring(tree.getroot()),
        strip_text=False,
        with_comments=True,
    ).encode("utf-8")
    return canon, hashlib.sha256(canon).hexdigest()


def localname(tag):
    """取 Element 的本地名（去命名空间）。"""
    if tag.startswith("{"):
        return tag.split("}", 1)[1]
    return tag


def direct_children(el, local_name):
    """仅取直接子元素中本地名匹配者（不跨层级，避免误读嵌套扩展）。"""
    return [c for c in list(el) if localname(c.tag) == local_name]


def one_child(el, local_name):
    kids = direct_children(el, local_name)
    return kids[0] if kids else None


def text_of(el, local_name):
    kid = one_child(el, local_name)
    if kid is None or kid.text is None:
        return None
    return kid.text.strip()
