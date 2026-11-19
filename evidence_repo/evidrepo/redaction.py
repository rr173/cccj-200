# -*- coding: utf-8 -*-
"""
按原始 UTF-8 字节坐标执行遮盖（redaction）。

规则（见 profile.md §15）：
- 坐标永远是**原始字节**的半开区间 [start, end)，不是字符序号；
- 对需要遮盖的内容先验证整份原件是合法 UTF-8，并核对规则绑定的 SHA-256；
- 每条原始区间必须非空、未越界、且两端都落在字符边界上。
  即使一条非法区间被有效区间完整覆盖，也必须发现它（先逐条校验、后求并集）；
- 以等量 ASCII ``*``（0x2A）替换并集内字节，其余原始字节原样保留（含换行），
  因此输出长度与原件一致；
- 全流程 1 MiB 分块，正确处理跨块的多字节 UTF-8 字符与跨块遮盖区间；
- 读取发布用封存文件时实际校验长度与 SHA-256，确保被转换/复制的字节就是
  通过校验的字节。

边界判定原理：UTF-8 中字节 b 是字符边界，当且仅当
``b < 0x80``（ASCII 字符单字节）或 ``b >= 0xC0``（前导字节）；
0x80..0xBF 是延续字节，绝不可以作为区间端点。
"""
from __future__ import annotations

import hashlib
import os

from .util import CHUNK_SIZE

STAR = 0x2A


class RedactionError(Exception):
    """遮盖规则无法成立或字节校验失败：阻止产生可发布结果。"""

    def __init__(self, message, code=None, identity=None, detail=None):
        super().__init__(message)
        self.message = message
        self.code = code or "redaction_failed"
        self.identity = identity
        self.detail = detail

    def as_dict(self):
        return {
            "error": self.code,
            "identity": self.identity,
            "detail": self.detail,
            "message": self.message,
        }


def is_character_boundary(byte):
    return byte < 0x80 or byte >= 0xC0


def validate_ranges_against_content(length, ranges, identity=None):
    """
    逐条核对区间：非空（解析阶段已保证）、未越界、两端为字符边界。
    length 是原件字节数；ranges 为原始（未合并）区间列表。
    非法即抛 RedactionError，并指出具体区间——即使它被别的区间覆盖。
    """
    for s, e in ranges:
        if s < 0 or e > length or s >= e:
            raise RedactionError(
                "range [%d,%d) is empty or out of bounds (content length %d)"
                % (s, e, length),
                "range_out_of_bounds",
                identity,
                {"range": [s, e], "length": length},
            )
        # 字符边界需要真实字节；这里只做越界，边界在扫描时逐字节确认。
    return True


def scan_utf8_and_boundaries(path, ranges, expected_sha256, expected_size,
                             identity=None):
    """
    第一遍分块扫描：
      1. 实际重算长度与 SHA-256，与声明核对；
      2. 验证整份文件是合法 UTF-8（增量解码器，跨块字符不丢状态）；
      3. 对每个区间端点定位其字节，确认落在字符边界上。
    只保留有界状态（解码器 + 单块缓冲 + 端点集合），不读入整文件。
    返回排序后的端点集合（用于第二遍的边界复核一致性）。
    """
    endpoints = sorted({p for s, e in ranges for p in (s, e)})
    endpoint_set = set(endpoints)
    boundary_bytes = {}  # offset -> byte value（仅端点位置）
    h = hashlib.sha256()
    decoder = _IncrementalUTF8Validator()
    size = 0
    ep_idx = 0
    try:
        with open(path, "rb") as fp:
            while True:
                chunk = fp.read(CHUNK_SIZE)
                if not chunk:
                    break
                h.update(chunk)
                try:
                    decoder.feed(chunk)
                except _UTF8ValidationError as exc:
                    raise RedactionError(
                        "original content is not valid UTF-8: %s" % exc,
                        "not_valid_utf8", identity)
                base = size
                # 记录本块覆盖到的端点字节（端点 < 本块末尾偏移）
                while ep_idx < len(endpoints) and endpoints[ep_idx] < base + len(chunk):
                    off = endpoints[ep_idx]
                    if off >= base:  # 跳过已在历史块处理的（理论不发生）
                        boundary_bytes[off] = chunk[off - base]
                    ep_idx += 1
                size += len(chunk)
    except OSError as exc:
        raise RedactionError(
            "cannot read sealed file: %s" % exc,
            "io_error", identity)
    try:
        decoder.finish()
    except _UTF8ValidationError as exc:
        raise RedactionError(
            "original content is not valid UTF-8: %s" % exc,
            "not_valid_utf8", identity)

    if size != expected_size:
        raise RedactionError(
            "length mismatch: sealed file %d bytes, expected %d"
            % (size, expected_size),
            "length_mismatch", identity,
            {"actual": size, "expected": expected_size})
    actual = h.hexdigest()
    if actual != expected_sha256.lower():
        raise RedactionError(
            "SHA-256 mismatch: sealed file %s, rule/record expected %s"
            % (actual, expected_sha256),
            "digest_mismatch", identity,
            {"actual": actual, "expected": expected_sha256})

    # 越界逐条检查（含被覆盖的区间；在拿到真实长度后立即判定）
    validate_ranges_against_content(size, ranges, identity)

    # 端点字符边界逐条核对——先于合并，确保被覆盖的非法区间同样被发现。
    # offset == size 的端点是文件末尾：合法 UTF-8 流的 EOF 必在字符边界上。
    bad = []
    for s, e in ranges:
        if s != size and not is_character_boundary(boundary_bytes[s]):
            bad.append({"endpoint": s, "range": [s, e], "side": "start"})
        if e != size and not is_character_boundary(boundary_bytes[e]):
            bad.append({"endpoint": e, "range": [s, e], "side": "end"})
    if bad:
        raise RedactionError(
            "redaction range endpoint(s) do not lie on UTF-8 character boundaries",
            "range_not_character_aligned", identity, {"bad_endpoints": bad})
    return size, actual


def write_redacted(src_path, dst_path, merged_ranges, expected_size,
                   expected_sha256, identity=None):
    """
    第二遍：分块读原件、按合并后的并集替换为 0x2A，写出遮盖副本。
    同时重算输入哈希（再次核对）与输出哈希/长度，返回：
      {"size":out_size,"sha256":out_digest,
       "source_size":...,"source_sha256":...}
    区间跨块时用全局字节偏移正确处理；输出缓冲恒不超过一个块。
    """
    in_h = hashlib.sha256()
    out_h = hashlib.sha256()
    out_size = 0
    pos = 0
    # 区间游标：merged_ranges 已排序且互不相交
    ri = 0
    n_ranges = len(merged_ranges)
    os.makedirs(os.path.dirname(dst_path), exist_ok=True)
    with open(src_path, "rb") as fi, open(dst_path, "wb") as fo:
        while True:
            chunk = bytearray(fi.read(CHUNK_SIZE))
            if not chunk:
                break
            in_h.update(chunk)
            base = pos
            end = base + len(chunk)
            j = ri
            while j < n_ranges and merged_ranges[j][0] < end:
                rs, re_ = merged_ranges[j]
                lo = max(rs, base) - base
                hi = min(re_, end) - base
                if hi > lo:
                    for k in range(lo, hi):
                        chunk[k] = STAR
                if re_ <= end:
                    j += 1
                else:
                    break  # 区间延伸到后续块，游标保持
            ri = j
            fo.write(chunk)
            out_h.update(chunk)
            out_size += len(chunk)
            pos = end
    src_digest = in_h.hexdigest()
    if pos != expected_size:
        raise RedactionError(
            "source length changed during redaction: got %d expected %d"
            % (pos, expected_size),
            "length_mismatch", identity)
    if src_digest != expected_sha256.lower():
        raise RedactionError(
            "source SHA-256 mismatch during redaction: got %s expected %s"
            % (src_digest, expected_sha256),
            "digest_mismatch", identity)
    return {
        "size": out_size,
        "sha256": out_h.hexdigest(),
        "source_size": pos,
        "source_sha256": src_digest,
    }


def copy_verified(src_path, dst_path, expected_size, expected_sha256,
                  identity=None):
    """
    原样放行路径：分块复制，并实际核对长度与 SHA-256。
    返回交付字节的 {"size","sha256"}（放行时自然等于原件）。
    """
    h_in = hashlib.sha256()
    h_out = hashlib.sha256()
    size = 0
    os.makedirs(os.path.dirname(dst_path), exist_ok=True)
    with open(src_path, "rb") as fi, open(dst_path, "wb") as fo:
        while True:
            chunk = fi.read(CHUNK_SIZE)
            if not chunk:
                break
            h_in.update(chunk)
            fo.write(chunk)
            h_out.update(chunk)
            size += len(chunk)
    if size != expected_size:
        raise RedactionError(
            "length mismatch copying sealed file: got %d expected %d"
            % (size, expected_size),
            "length_mismatch", identity)
    digest = h_in.hexdigest()
    if digest != expected_sha256.lower():
        raise RedactionError(
            "SHA-256 mismatch copying sealed file: got %s expected %s"
            % (digest, expected_sha256),
            "digest_mismatch", identity)
    if h_out.hexdigest() != digest:
        raise RedactionError(
            "delivered copy digest differs from verified source",
            "digest_mismatch", identity)
    return {"size": size, "sha256": digest}


# ---------------------------------------------------------------------------
# 增量 UTF-8 校验（标准库 codecs 的增量解码器，严格模式，跨块保留状态）
# ---------------------------------------------------------------------------

class _UTF8ValidationError(Exception):
    pass


class _IncrementalUTF8Validator:
    def __init__(self):
        import codecs
        self._dec = codecs.getincrementaldecoder("utf-8")(errors="strict")

    def feed(self, chunk):
        try:
            self._dec.decode(chunk, final=False)
        except UnicodeDecodeError as exc:
            raise _UTF8ValidationError(str(exc))

    def finish(self):
        try:
            self._dec.decode(b"", final=True)
        except UnicodeDecodeError as exc:
            raise _UTF8ValidationError(str(exc))


def validate_utf8_file(path, identity=None):
    """仅做合法 UTF-8 校验（供计划阶段预检，分块、不读入整文件）。"""
    dec = _IncrementalUTF8Validator()
    try:
        with open(path, "rb") as fp:
            while True:
                chunk = fp.read(CHUNK_SIZE)
                if not chunk:
                    break
                dec.feed(chunk)
        dec.finish()
    except _UTF8ValidationError as exc:
        raise RedactionError(
            "original content is not valid UTF-8: %s" % exc,
            "not_valid_utf8", identity)
    except OSError as exc:
        raise RedactionError(
            "cannot read sealed file: %s" % exc, "io_error", identity)
    return True
