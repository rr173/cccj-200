# -*- coding: utf-8 -*-
"""
按经确认的馆内计划执行离线发布。

硬性规则（profile.md §15）：
- **只用确认的计划**：按 plan_id 取计划；重新核对请求/规则来源哈希与
  sealed 包集合。包集合一旦变化（哪怕交付前恰好有新包封存），计划陈旧，
  必须重做——旧计划绝不交付。
- **封存与公开目录先后明确**：全部产物先在目标之外的临时目录构建并校验，
  最后在一个写事务内复核包集合后原子改名；目标正式路径要么不存在，
  要么是一份完整可校验目录，中断后不会出现半成品。
- **目标已存在则保留原内容**；同一路径并发发布最多一个成功（仓内互斥锁 +
  目标存在性复核）。
- 仅交付通过全部成员检查的表示引用的内容；被暂缓表示独有、且未被开放表示
  引用的内容一律留在馆内。
- 公开清单只含外部代号、生成文件名、交付字节的长度与 SHA-256；不含任何
  原件摘要、馆内身份、路径、规则、原因、XML、事件、证明或计划信息。
"""
from __future__ import annotations

import datetime
import hashlib
import json
import os
import re
import shutil

from . import redaction as red
from .release_plan import (
    CONTENT_REDACT,
    CONTENT_RELEASE,
    delivery_filename,
    sealed_package_set,
    _canon,
    _sha,
)
from .release_rules import merge_ranges

MANIFEST_NAME = "release-manifest.json"
MANIFEST_PROFILE = "offline-evidence-repo/release-manifest/v1"
PAYLOAD_DIR = "payloads"
# 受控文件名：payloads/f-<64 hex>.bin + 根目录唯一清单
FILENAME_RE = re.compile(r"^f-[0-9a-f]{64}\.bin$")


class PublishError(Exception):
    def __init__(self, message, code=None):
        super().__init__(message)
        self.message = message
        self.code = code or "publish_failed"

    def as_dict(self):
        return {"error": self.code, "message": self.message}


def _now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def _plan_row(conn, plan_id):
    row = conn.execute(
        "SELECT * FROM release_plans WHERE plan_id=?", (plan_id,)
    ).fetchone()
    if row is None:
        raise PublishError("unknown plan_id %r" % plan_id, "unknown_plan")
    return row


def _check_freshness(conn, row, plan_doc):
    current = sealed_package_set(conn)
    current_sha = _sha(_canon(current))
    if current_sha != row["package_set_sha256"]:
        raise PublishError(
            "plan %s is stale: sealed package set changed since planning "
            "(planned=%s, current=%s); rebuild the plan"
            % (row["plan_id"], row["package_set_sha256"], current_sha),
            "stale_plan",
        )
    bound = plan_doc["inputs"]["sealed"]
    if bound["package_set_sha256"] != current_sha or bound["package_set"] != current:
        raise PublishError(
            "plan document sealed binding does not match the live repository",
            "stale_plan",
        )


def _find_blob(conn, digest):
    """取该摘要一份稳定的 sealed bytes_ok 封存记录。"""
    return conn.execute(
        """
        SELECT ob.id_type AS id_type, ob.id_value AS id_value,
               b.actual_sha AS digest, b.size_actual AS size,
               b.stored_path AS stored_path, b.package_id AS package_id,
               b.rel_path AS blob_rel
        FROM object_blobs ob
        JOIN blobs b ON b.package_id=ob.package_id AND b.rel_path=ob.blob_rel
        WHERE b.actual_sha=? AND b.state='bytes_ok' AND """
        + "b.package_id IN (SELECT package_id FROM packages WHERE state='sealed')"
        + """
        ORDER BY b.package_id, b.rel_path LIMIT 1
        """,
        (digest,),
    ).fetchone()


def publish(conn, repo_root, plan_id, target_dir):
    """
    执行发布。返回登记 dict；失败时清理临时目录、不动任何既有目标。
    """
    row = _plan_row(conn, plan_id)
    plan_path = os.path.join(repo_root, row["plan_path"])
    with open(plan_path, "rb") as f:
        plan_doc = json.load(f)
    if plan_doc.get("plan_id") != plan_id:
        raise PublishError("plan document id does not match registry", "corrupt_plan")

    target_dir = os.path.abspath(target_dir)
    # 目标已存在：保留原内容，拒绝覆盖（并发第二个发布在此失败）
    if os.path.exists(target_dir):
        raise PublishError(
            "target directory already exists; refusing to overwrite: %s"
            % target_dir,
            "target_exists",
        )

    # 仓内互斥锁：序列化所有发布（SQLite 写锁本身也互斥，这里额外保证
    # “检查目标不存在 -> 原子改名”区间内没有第二个发布者）。
    lock_path = os.path.join(repo_root, "release", "publish.lock")
    os.makedirs(os.path.dirname(lock_path), exist_ok=True)
    lock_fd = _acquire_lock(lock_path)
    # 唯一名：pid + 纳秒时间戳，避免同进程重跑/并发时 staging 目录互相覆盖
    staging_dir = "%s.stage-%d-%d" % (
        target_dir, os.getpid(),
        __import__("time").perf_counter_ns())
    try:
        if os.path.exists(target_dir):
            raise PublishError(
                "target directory appeared concurrently: %s" % target_dir,
                "target_exists",
            )
        if os.path.exists(staging_dir):
            shutil.rmtree(staging_dir)
        os.makedirs(os.path.join(staging_dir, PAYLOAD_DIR))

        # 事务开始后直到原子改名前都持有写锁；封存（finish）同样需要写锁，
        # 因此“复核包集合 -> 交付”之间不可能夹入新的封存。
        conn.execute("BEGIN IMMEDIATE")
        try:
            _check_freshness(conn, row, plan_doc)
            manifest = _build_payloads(
                conn, repo_root, plan_doc, staging_dir
            )
            # 交付前最后一次复核：任何新封存都会改变包集合哈希
            _check_freshness(conn, row, plan_doc)

            manifest_path = os.path.join(staging_dir, MANIFEST_NAME)
            body = (json.dumps(manifest, ensure_ascii=False,
                               sort_keys=False, indent=2).encode("utf-8")
                    + b"\n")
            with open(manifest_path, "wb") as f:
                f.write(body)
                f.flush()
                os.fsync(f.fileno())
            manifest_sha = hashlib.sha256(body).hexdigest()

            # 原子交付：rename 使正式路径一次性出现完整目录
            os.rename(staging_dir, target_dir)
            staging_dir = None

            cur = conn.execute(
                "INSERT INTO release_deliveries(plan_id,delivered_at,"
                "target_dir,manifest_name,file_count,manifest_sha256,"
                "package_set_sha256) VALUES(?,?,?,?,?,?,?)",
                (
                    plan_id,
                    _now(),
                    target_dir,
                    MANIFEST_NAME,
                    len(manifest["files"]),
                    manifest_sha,
                    row["package_set_sha256"],
                ),
            )
            conn.commit()
        except Exception:
            conn.rollback()
            raise
    finally:
        _release_lock(lock_fd, lock_path)
        if staging_dir and os.path.exists(staging_dir):
            shutil.rmtree(staging_dir, ignore_errors=True)

    return {
        "plan_id": plan_id,
        "delivery_no": cur.lastrowid,
        "target_dir": target_dir,
        "manifest": MANIFEST_NAME,
        "file_count": len(manifest["files"]),
        "manifest_sha256": manifest_sha,
    }


def _build_payloads(conn, repo_root, plan_doc, staging_dir):
    """
    按计划构建全部有效载荷与公开清单（仅 deliverable 表示参与）。
    多个表示共享同一交付文件（按交付字节摘要去重）。
    """
    contents = {c["content_sha256"]: c for c in plan_doc["contents"]}
    deliverable = [
        r for r in plan_doc["representations"] if r["decision"] == "deliverable"
    ]
    if not deliverable:
        raise PublishError(
            "plan has no deliverable representation; nothing to publish",
            "no_deliverable",
        )

    # 仅收集开放表示实际引用的内容（暂缓表示独有内容不输出）
    wanted = set()
    for rep in deliverable:
        wanted.update(rep["content_digests"])

    produced = {}  # delivered_sha -> {"file":..., "size":..., "sha256":...}
    # 成员引用按表示外部代号、再按稳定成员顺序生成
    rep_entries = []
    for rep in sorted(deliverable, key=lambda r: r["external_code"]):
        member_entries = []
        # 成员顺序：沿用计划 member_checks（已按身份排序），只保留有字节者
        for check in rep["member_checks"]:
            mk = (check["identity"]["identifierType"],
                  check["identity"]["identifierValue"])
            blob = conn.execute(
                """
                SELECT b.actual_sha AS digest FROM object_blobs ob
                JOIN blobs b ON b.package_id=ob.package_id AND b.rel_path=ob.blob_rel
                WHERE ob.id_type=? AND ob.id_value=? AND b.state='bytes_ok' AND """
                + "b.package_id IN (SELECT package_id FROM packages WHERE state='sealed')"
                + " ORDER BY b.package_id, b.rel_path LIMIT 1",
                mk,
            ).fetchone()
            if blob is None:
                # 计划阶段已拦截；走到这里说明事实被改动，属陈旧/损坏
                raise PublishError(
                    "member %s/%s lost its bytes_ok copy after planning"
                    % mk,
                    "fact_changed",
                )
            digest = blob["digest"]
            if digest not in wanted:
                continue  # 防御：不输出未开放内容
            c = contents[digest]
            if c["blocked"] or c["decision"] not in (
                CONTENT_RELEASE, CONTENT_REDACT
            ):
                raise PublishError(
                    "content %s is not publishable under the plan" % digest,
                    "content_not_publishable",
                )
            src_row = _find_blob(conn, digest)
            src_path = os.path.join(repo_root, src_row["stored_path"])

            if c["decision"] == CONTENT_RELEASE:
                delivered_sha = digest
                if delivered_sha not in produced:
                    fname = delivery_filename(plan_doc["plan_id"], delivered_sha)
                    red.copy_verified(
                        src_path,
                        os.path.join(staging_dir, PAYLOAD_DIR, fname),
                        src_row["size"], digest,
                        identity=(src_row["id_type"], src_row["id_value"]),
                    )
                    produced[delivered_sha] = {
                        "file": fname,
                        "size": src_row["size"],
                        "sha256": delivered_sha,
                    }
            else:  # redact
                raw_ranges = []
                for rule in plan_doc["inputs"]["rules"]["rules"]:
                    if rule["action"] != "redact":
                        continue
                    # 与该内容相关的 redact 规则（绑定摘要即本内容）
                    if rule["content_sha256"] == digest:
                        raw_ranges.extend(rule["ranges"])
                merged = merge_ranges(raw_ranges)
                if merged != c["merged_redaction_ranges"]:
                    raise PublishError(
                        "redaction union in plan does not rebuild from rules",
                        "plan_inconsistent",
                    )
                # 发布时再次实际校验：UTF-8、长度、绑定 SHA-256、字符边界
                red.scan_utf8_and_boundaries(
                    src_path, raw_ranges, digest, src_row["size"],
                    identity=(src_row["id_type"], src_row["id_value"]),
                )
                # 先在临时名写出，再按“交付字节摘要”定名，保证文件名绑定交付字节
                tmp_out = os.path.join(
                    staging_dir, PAYLOAD_DIR,
                    ".tmp-%s" % digest[:12],
                )
                res = red.write_redacted(
                    src_path, tmp_out, merged, src_row["size"], digest,
                    identity=(src_row["id_type"], src_row["id_value"]),
                )
                delivered_sha = res["sha256"]
                if delivered_sha not in produced:
                    fname = delivery_filename(plan_doc["plan_id"], delivered_sha)
                    os.replace(
                        tmp_out,
                        os.path.join(staging_dir, PAYLOAD_DIR, fname),
                    )
                    produced[delivered_sha] = {
                        "file": fname,
                        "size": res["size"],
                        "sha256": delivered_sha,
                    }
                else:
                    os.remove(tmp_out)
            member_entries.append(
                {
                    "file": produced[delivered_sha]["file"],
                    "size": produced[delivered_sha]["size"],
                    "sha256": produced[delivered_sha]["sha256"],
                }
            )
        rep_entries.append(
            {
                "external_code": rep["external_code"],
                "members": member_entries,
            }
        )

    files = sorted(produced.values(), key=lambda x: x["file"])
    manifest = {
        "profile": MANIFEST_PROFILE,
        "audience": plan_doc["audience"],
        "files": files,
        "representations": rep_entries,
    }
    # 自洽：清单引用的每个文件都在 files 中，且每个 file 都被至少一个表示引用
    referenced = {m["file"] for r in rep_entries for m in r["members"]}
    named = {f["file"] for f in files}
    if referenced != named:
        raise PublishError(
            "manifest file set inconsistent (referenced=%d named=%d)"
            % (len(referenced), len(named)),
            "manifest_inconsistent",
        )
    return manifest


# ---------------------------------------------------------------------------
# 进程间互斥锁（open O_CREAT|O_EXCL；识别持有者已死的陈旧锁并接管）
# ---------------------------------------------------------------------------

def _pid_alive(pid):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True  # 进程存在但无权发信号
    except OSError:
        return False
    return True


def _acquire_lock(path):
    import time
    fd = None
    for _ in range(200):  # 最多等约 20 秒
        try:
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            os.write(fd, ("%d\n" % os.getpid()).encode("ascii"))
            return fd
        except FileExistsError:
            # 陈旧锁：持有者进程已不存在（崩溃残留），接管
            try:
                with open(path, "r", encoding="ascii") as f:
                    owner = int(f.read().strip())
                if not _pid_alive(owner):
                    os.remove(path)
                    continue
            except (OSError, ValueError):
                # 锁文件不可读/内容损坏：保守等待，不强行接管
                pass
            time.sleep(0.1)
    raise PublishError("could not acquire publish lock: %s" % path,
                       "lock_busy")


def _release_lock(fd, path):
    try:
        if fd is not None:
            os.close(fd)
    finally:
        try:
            os.remove(path)
        except OSError:
            pass
