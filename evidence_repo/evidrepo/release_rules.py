# -*- coding: utf-8 -*-
"""
离线发布请求与受众规则的严格校验（版本化 UTF-8 JSONL）。

两类输入，均为**无 BOM 的 UTF-8 JSONL、逐行一个 JSON 对象**：

1. 发布请求 ``release-request/v1``
   第 1 行头记录指定受众；其后每行按精确 (identifierType, identifierValue)
   选择一份表示，并显式给出经人工批准的外部代号 external_code。

   {"record_type":"release_header","format_version":"release-request/v1",
    "request_id":"REQ-1","audience":"reading-room-a"}
   {"record_type":"representation_selection",
    "identifierType":"local","identifierValue":"REP-1",
    "external_code":"EXT-0001"}

2. 受众开放规则 ``release-rules/v1``
   第 1 行头记录指定**同一受众**；其后每行按 bitstream 身份给出一个动作：
   release（放行原字节）/ hold（业务暂缓）/ redact（按原始 UTF-8 字节
   半开区间遮盖）。redact 必须绑定原件内容 SHA-256 并给出非空区间表。

   {"record_type":"rules_header","format_version":"release-rules/v1",
    "rules_id":"RULES-1","audience":"reading-room-a"}
   {"record_type":"rule",
    "bitstream":{"identifierType":"local","identifierValue":"BS-1"},
    "action":"release"}
   {"record_type":"rule",
    "bitstream":{"identifierType":"local","identifierValue":"BS-2"},
    "action":"redact","content_sha256":"<64 hex>",
    "ranges":[[1,4],[4,5]]}

错误分层（题目要求两者可区分）：
- **语法/计划失败**（ReleaseInputError）：编码、JSON、字段、版本、受控词、
  重复或冲突规则、重复外部代号、非法区间结构、受众不一致等。整份输入拒绝，
  不产生馆内计划。
- **业务暂缓**：某 bitstream 身份缺规则等，在计划构建阶段逐项记录为 hold
  原因，计划照常生成（见 release_plan.py）。

内存边界：逐行流式解析，单行上限 MAX_LINE_BYTES，不把整份文件读入内存。
"""
from __future__ import annotations

import hashlib
import io
import json
import re

REQUEST_FORMAT = "release-request/v1"
RULES_FORMAT = "release-rules/v1"

ACTION_RELEASE = "release"
ACTION_HOLD = "hold"
ACTION_REDACT = "redact"
KNOWN_ACTIONS = (ACTION_RELEASE, ACTION_HOLD, ACTION_REDACT)

# 外部代号：严格 ASCII 安全字符；字母数字开头，其余限 . _ -，长度 1..128。
EXTERNAL_CODE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")

MAX_LINE_BYTES = 1 << 20  # 1 MiB：控制元数据单行上限，防止无界内存


class ReleaseInputError(Exception):
    """输入语法/约束错误：计划失败（区别于业务暂缓）。"""

    def __init__(self, message, line=None, code=None, source=None):
        super().__init__(message)
        self.message = message
        self.line = line
        self.code = code or "invalid_release_input"
        self.source = source  # "request" | "rules"

    def as_dict(self):
        return {
            "error": self.code,
            "source": self.source,
            "line": self.line,
            "message": self.message,
        }


# ---------------------------------------------------------------------------
# 物理行读取（与 inventory 同一套严格语义：仅按 \n 切行、拒绝 BOM/裸 CR）
# ---------------------------------------------------------------------------

def _iter_physical_lines(fp, hasher=None):
    lineno = 0
    while True:
        raw = fp.readline(MAX_LINE_BYTES + 2)
        if not raw:
            break
        lineno += 1
        if hasher is not None:
            hasher.update(raw)
        if not raw.endswith(b"\n") and len(raw) > MAX_LINE_BYTES:
            raise ReleaseInputError(
                "line exceeds %d bytes" % MAX_LINE_BYTES, lineno, "line_too_long"
            )
        chunk = raw[:-1] if raw.endswith(b"\n") else raw
        if chunk.endswith(b"\r"):
            chunk = chunk[:-1]
        if b"\r" in chunk:
            raise ReleaseInputError(
                "bare CR in line (use LF or CRLF line endings)",
                lineno,
                "bad_encoding",
            )
        if len(chunk) > MAX_LINE_BYTES:
            raise ReleaseInputError(
                "line exceeds %d bytes" % MAX_LINE_BYTES, lineno, "line_too_long"
            )
        try:
            text = chunk.decode("utf-8", "strict")
        except UnicodeDecodeError as exc:
            raise ReleaseInputError(
                "line is not valid UTF-8: %s" % exc, lineno, "bad_encoding"
            )
        yield lineno, text


def _first_pass_info(path):
    """返回 (sha256, bytes, physical_lines)；拒绝空文件与 BOM。"""
    h = hashlib.sha256()
    size = 0
    first = b""
    n_lines = 0
    with open(path, "rb") as fp:
        while True:
            chunk = fp.read(1 << 20)
            if not chunk:
                break
            if not first:
                first = chunk[:3]
            h.update(chunk)
            size += len(chunk)
            n_lines += chunk.count(b"\n")
            last = chunk[-1:]
    if size == 0:
        raise ReleaseInputError("input file is empty", 1, "empty")
    if first == b"\xef\xbb\xbf":
        raise ReleaseInputError(
            "input must be UTF-8 without BOM", 1, "bad_encoding"
        )
    if last != b"\n":
        n_lines += 1
    return h.hexdigest(), size, n_lines


def _validate_text(value, what, line, allow_empty=False):
    if not isinstance(value, str):
        raise ReleaseInputError(
            "%s must be a JSON string" % what, line, "bad_type"
        )
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in value):
        raise ReleaseInputError(
            "%s contains control characters" % what, line, "bad_text"
        )
    if not allow_empty and value.strip() == "":
        raise ReleaseInputError("%s must not be empty" % what, line, "bad_text")
    return value


def _parse_json_object(text, line_no):
    def _bad_constant(x):
        raise ReleaseInputError(
            "non-finite JSON number %r is not allowed" % x, line_no, "bad_json"
        )

    try:
        obj = json.loads(text, parse_constant=_bad_constant)
    except ReleaseInputError:
        raise
    except (json.JSONDecodeError, ValueError) as exc:
        raise ReleaseInputError("invalid JSON: %s" % exc, line_no, "bad_json")
    if not isinstance(obj, dict):
        raise ReleaseInputError(
            "each line must be a JSON object", line_no, "bad_json"
        )
    return obj


def _identity_from(obj, line_no, what):
    if not isinstance(obj, dict):
        raise ReleaseInputError(
            "%s must be an object with identifierType and identifierValue" % what,
            line_no,
            "bad_type",
        )
    if "identifierType" not in obj or "identifierValue" not in obj:
        raise ReleaseInputError(
            "%s requires identifierType and identifierValue" % what,
            line_no,
            "missing_field",
        )
    t = _validate_text(obj["identifierType"], "identifierType", line_no)
    v = _validate_text(obj["identifierValue"], "identifierValue", line_no)
    return t, v


def _validate_range(raw, line_no):
    """
    区间结构校验（内容相关的越界/字符边界校验在发布执行时按真实字节做）：
    必须是恰好两个非负整数的半开区间 [start, end)，且 start < end。
    布尔值虽为 int 子类，显式拒绝。
    """
    if not isinstance(raw, list) or len(raw) != 2:
        raise ReleaseInputError(
            "each redaction range must be a [start, end) pair",
            line_no,
            "bad_range",
        )
    s, e = raw
    if isinstance(s, bool) or isinstance(e, bool) or \
            not isinstance(s, int) or not isinstance(e, int):
        raise ReleaseInputError(
            "range endpoints must be integers", line_no, "bad_range"
        )
    if s < 0 or e < 0:
        raise ReleaseInputError(
            "range endpoints must be non-negative", line_no, "bad_range"
        )
    if s >= e:
        raise ReleaseInputError(
            "range %r must be non-empty (start < end)" % raw,
            line_no,
            "bad_range",
        )
    return [s, e]


# ---------------------------------------------------------------------------
# 请求解析
# ---------------------------------------------------------------------------

def parse_request(path):
    """
    流式解析并整份校验发布请求。返回 dict：
      request_id / audience / selections[(id_type,id_value,external_code,line)]
      source_sha256 / source_bytes / source_lines
    任何语法/约束错误抛 ReleaseInputError(source='request')，不留半份结果。
    """
    digest, size, phys_lines = _first_pass_info(path)
    out = {
        "request_id": None,
        "audience": None,
        "selections": [],
        "source_sha256": digest,
        "source_bytes": size,
        "source_lines": phys_lines,
    }
    seen_identities, seen_codes = set(), set()
    first = True
    n = 0
    rehash = hashlib.sha256()
    with open(path, "rb") as fp:
        for line_no, text in _iter_physical_lines(fp, rehash):
            n += 1
            if text.strip() == "":
                raise ReleaseInputError(
                    "blank line in request", line_no, "blank_line", "request"
                )
            rec = _parse_json_object(text, line_no)
            if first:
                first = False
                if rec.get("record_type") not in (None, "release_header"):
                    raise ReleaseInputError(
                        "first line must be the release header",
                        line_no,
                        "bad_header",
                        "request",
                    )
                if rec.get("format_version") != REQUEST_FORMAT:
                    raise ReleaseInputError(
                        "unsupported request format_version %r (expected %r)"
                        % (rec.get("format_version"), REQUEST_FORMAT),
                        line_no,
                        "bad_format_version",
                        "request",
                    )
                for field in ("request_id", "audience"):
                    if field not in rec:
                        raise ReleaseInputError(
                            "header requires %r" % field,
                            line_no,
                            "missing_field",
                            "request",
                        )
                out["request_id"] = _validate_text(
                    rec["request_id"], "request_id", line_no
                )
                out["audience"] = _validate_text(
                    rec["audience"], "audience", line_no
                )
                continue
            if rec.get("record_type") != "representation_selection":
                raise ReleaseInputError(
                    "unknown record_type %r" % rec.get("record_type"),
                    line_no,
                    "bad_record",
                    "request",
                )
            ident = _identity_from(rec, line_no, "selection")
            if "external_code" not in rec:
                raise ReleaseInputError(
                    "selection requires human-approved external_code",
                    line_no,
                    "missing_field",
                    "request",
                )
            code = _validate_text(rec["external_code"], "external_code", line_no)
            if not EXTERNAL_CODE_RE.match(code) or any(
                ord(ch) > 127 for ch in code
            ):
                raise ReleaseInputError(
                    "external_code %r is not ASCII-safe "
                    "(allowed: A-Z a-z 0-9 . _ -, must start alphanumeric)"
                    % code,
                    line_no,
                    "bad_external_code",
                    "request",
                )
            if ident in seen_identities:
                raise ReleaseInputError(
                    "duplicate representation selection %r" % (ident,),
                    line_no,
                    "duplicate_selection",
                    "request",
                )
            if code in seen_codes:
                raise ReleaseInputError(
                    "duplicate external_code %r" % code,
                    line_no,
                    "duplicate_external_code",
                    "request",
                )
            seen_identities.add(ident)
            seen_codes.add(code)
            out["selections"].append(
                {
                    "id_type": ident[0],
                    "id_value": ident[1],
                    "external_code": code,
                    "source_line": line_no,
                }
            )
    if first:
        raise ReleaseInputError(
            "request has no header", 1, "empty", "request"
        )
    if not out["selections"]:
        raise ReleaseInputError(
            "request contains no representation_selection lines",
            None,
            "empty_selection",
            "request",
        )
    if n != phys_lines or rehash.hexdigest() != digest:
        raise ReleaseInputError(
            "request changed while being parsed", None, "source_changed", "request"
        )
    return out


# ---------------------------------------------------------------------------
# 规则解析
# ---------------------------------------------------------------------------

def parse_rules(path, expected_audience):
    """
    流式解析并整份校验受众规则。expected_audience 来自同一请求，头记录受众
    必须与之精确相等。返回 dict：
      rules_id / audience /
      rules: {(id_type,id_value): {"action":..., "content_sha256":...,
                                    "ranges":[[s,e]...], "source_line":n}}
    每个 bitstream 身份至多一条规则：重复身份即冲突规则，整份拒绝。
    """
    digest, size, phys_lines = _first_pass_info(path)
    out = {
        "rules_id": None,
        "audience": None,
        "rules": {},
        "source_sha256": digest,
        "source_bytes": size,
        "source_lines": phys_lines,
    }
    first = True
    n = 0
    rehash = hashlib.sha256()
    with open(path, "rb") as fp:
        for line_no, text in _iter_physical_lines(fp, rehash):
            n += 1
            if text.strip() == "":
                raise ReleaseInputError(
                    "blank line in rules", line_no, "blank_line", "rules"
                )
            rec = _parse_json_object(text, line_no)
            if first:
                first = False
                if rec.get("record_type") not in (None, "rules_header"):
                    raise ReleaseInputError(
                        "first line must be the rules header",
                        line_no,
                        "bad_header",
                        "rules",
                    )
                if rec.get("format_version") != RULES_FORMAT:
                    raise ReleaseInputError(
                        "unsupported rules format_version %r (expected %r)"
                        % (rec.get("format_version"), RULES_FORMAT),
                        line_no,
                        "bad_format_version",
                        "rules",
                    )
                for field in ("rules_id", "audience"):
                    if field not in rec:
                        raise ReleaseInputError(
                            "header requires %r" % field,
                            line_no,
                            "missing_field",
                            "rules",
                        )
                out["rules_id"] = _validate_text(
                    rec["rules_id"], "rules_id", line_no
                )
                out["audience"] = _validate_text(
                    rec["audience"], "audience", line_no
                )
                if out["audience"] != expected_audience:
                    raise ReleaseInputError(
                        "rules audience %r does not match request audience %r"
                        % (out["audience"], expected_audience),
                        line_no,
                        "audience_mismatch",
                        "rules",
                    )
                continue
            if rec.get("record_type") != "rule":
                raise ReleaseInputError(
                    "unknown record_type %r" % rec.get("record_type"),
                    line_no,
                    "bad_record",
                    "rules",
                )
            if "bitstream" not in rec or "action" not in rec:
                raise ReleaseInputError(
                    "rule requires bitstream identity and action",
                    line_no,
                    "missing_field",
                    "rules",
                )
            ident = _identity_from(rec["bitstream"], line_no, "bitstream")
            action = rec["action"]
            if not isinstance(action, str) or action not in KNOWN_ACTIONS:
                raise ReleaseInputError(
                    "unknown action %r (allowed: release|hold|redact)"
                    % (action,),
                    line_no,
                    "unknown_action",
                    "rules",
                )
            if ident in out["rules"]:
                raise ReleaseInputError(
                    "duplicate/conflicting rule for bitstream %r "
                    "(first seen at line %d)"
                    % (ident, out["rules"][ident]["source_line"]),
                    line_no,
                    "duplicate_rule",
                    "rules",
                )
            entry = {
                "action": action,
                "content_sha256": None,
                "ranges": [],
                "source_line": line_no,
            }
            if action == ACTION_REDACT:
                bound = rec.get("content_sha256")
                if not isinstance(bound, str) or not SHA256_RE.match(
                    bound.lower()
                ):
                    raise ReleaseInputError(
                        "redact rule requires a 64-hex-char content_sha256 "
                        "binding the original bytes",
                        line_no,
                        "bad_bound_digest",
                        "rules",
                    )
                entry["content_sha256"] = bound.lower()
                raw_ranges = rec.get("ranges")
                if not isinstance(raw_ranges, list) or not raw_ranges:
                    raise ReleaseInputError(
                        "redact rule requires a non-empty ranges array",
                        line_no,
                        "bad_range",
                        "rules",
                    )
                ranges = [_validate_range(r, line_no) for r in raw_ranges]
                # 同一规则内的重复区间属于冲突声明
                if len({(s, e) for s, e in ranges}) != len(ranges):
                    raise ReleaseInputError(
                        "duplicate ranges within one redact rule",
                        line_no,
                        "bad_range",
                        "rules",
                    )
                entry["ranges"] = ranges
            else:
                if "ranges" in rec or "content_sha256" in rec:
                    raise ReleaseInputError(
                        "%s rule must not carry redaction bindings" % action,
                        line_no,
                        "bad_rule_fields",
                        "rules",
                    )
            out["rules"][ident] = entry
    if first:
        raise ReleaseInputError("rules have no header", 1, "empty", "rules")
    if not out["rules"]:
        raise ReleaseInputError(
            "rules file contains no rule lines", None, "empty_rules", "rules"
        )
    if n != phys_lines or rehash.hexdigest() != digest:
        raise ReleaseInputError(
            "rules changed while being parsed", None, "source_changed", "rules"
        )
    return out


def parse_request_and_rules(request_path, rules_path):
    """两个文件一起解析并交叉校验受众；纯内存/流式，不写库。"""
    request = parse_request(request_path)
    try:
        rules = parse_rules(rules_path, request["audience"])
    except ReleaseInputError as exc:
        raise
    return request, rules


def merge_ranges(ranges):
    """合并区间为互不相交、按起点排序的并集。"""
    merged = []
    for s, e in sorted(ranges):
        if merged and s <= merged[-1][1]:
            if e > merged[-1][1]:
                merged[-1][1] = e
        else:
            merged.append([s, e])
    return merged


def parse_bytes_for_tests(raw):
    """测试辅助：从字节走同一套严格解析（请求）。"""
    fp = io.BytesIO(raw)
    if raw.startswith(b"\xef\xbb\xbf"):
        raise ReleaseInputError("BOM not allowed", 1, "bad_encoding", "request")
    h = hashlib.sha256(raw)
    lines = list(_iter_physical_lines(fp, h))
    return lines, h.hexdigest()
