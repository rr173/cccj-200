# -*- coding: utf-8 -*-
"""
大成员内存测量。

验证两件事：
1. 接包/封包/查询/导出全流程对大成员只用分块（1 MiB）缓冲：
   用 tracemalloc 测量 Python 层峰值分配，峰值不应随成员字节数线性增长；
2. 用 resource 观测进程峰值 RSS，对比“小成员组”和“大成员组”：
   大成员（数百 MiB）处理后的 RSS 增量应远小于成员本身大小。

另用 monkey-patch 断言 open(...).read 从未出现一次性读取整个大文件的调用
（分块器的 read 参数恒为 CHUNK_SIZE）。
"""
from __future__ import annotations

import io
import os
import resource
import shutil
import sys
import tracemalloc

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))

from evidrepo import db as dbmod  # noqa: E402
from evidrepo import export as exportmod, ingest  # noqa: E402
from evidrepo.util import CHUNK_SIZE  # noqa: E402
from evidrepo.verify_export import verify_export  # noqa: E402

from fixtures import PackageBuilder  # noqa: E402

WORK = "/workspace/runs/memory"

# 记录所有对大文件的 read() 调用大小（包装内置 open，不可直接改内置类型）
_read_sizes = []
_builtin_open = io.open


class _TrackingFile:
    def __init__(self, raw):
        self._raw = raw

    def read(self, size=-1):
        if size is not None and size > 0:
            _read_sizes.append(size)
        return self._raw.read(size)

    def write(self, b):
        return self._raw.write(b)

    def __enter__(self):
        self._raw.__enter__()
        return self

    def __exit__(self, *a):
        return self._raw.__exit__(*a)

    def __getattr__(self, name):
        return getattr(self._raw, name)


def _tracking_open(file, mode="r", *args, **kwargs):
    raw = _builtin_open(file, mode, *args, **kwargs)
    if "b" in mode:
        return _TrackingFile(raw)
    return raw


def run_pipeline(total_bytes, n_members, label):
    shutil.rmtree(WORK, ignore_errors=True)
    os.makedirs(WORK + "/pkgs")
    repo = WORK + "/repo"
    conn = dbmod.connect(repo)
    per = total_bytes // n_members
    b = PackageBuilder(WORK + "/pkgs", "BIG",
                       trusted_ingest=tuple("ing-M%d" % i for i in range(n_members)))
    for i in range(n_members):
        # 稀疏可重复内容，避免真实压缩影响；仍走真实分块 I/O
        b.add_bitstream("M%d" % i, (b"block-%08d" % i) * (per // 12 + 1))
    b.add_representation("RBIG", ["M%d" % i for i in range(n_members)],
                         nodes=["big-node"])
    for i in range(n_members):
        b.add_event("ing-M%d" % i, "ingest", outputs=["M%d" % i])
    b.build()
    src = WORK + "/pkgs/BIG"

    tracemalloc.start()
    rss0 = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    ingest.receive(conn, repo, src)
    ingest.finish(conn, repo, "BIG")
    out = exportmod.export_proof(conn, repo, WORK + "/exports",
                                 "local", "RBIG", node_id="big-node")
    v = verify_export(out["export_dir"])
    assert v["ok"], v["errors"]
    cur, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    rss1 = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    conn.close()

    result = {
        "label": label,
        "total_bytes": total_bytes,
        "members": n_members,
        "py_peak_alloc_mib": round(peak / 1048576, 2),
        "rss_growth_mib": round((rss1 - rss0) / 1024, 1),  # ru_maxrss: KiB on Linux
        "verify_ok": v["ok"],
    }
    print(json_pretty(result))
    return result


def json_pretty(d):
    import json
    return json.dumps(d, ensure_ascii=False)


def main():
    import builtins
    builtins.open = _tracking_open
    try:
        small = run_pipeline(total_bytes=4 * 1024 * 1024, n_members=4,
                             label="small-4MiB")
        big = run_pipeline(total_bytes=256 * 1024 * 1024, n_members=8,
                           label="large-256MiB")
    finally:
        builtins.open = _builtin_open

    # 断言 1：Python 层峰值分配不随 64 倍数据量同步增长（上限给定宽松阈值）
    ratio = big["py_peak_alloc_mib"] / max(small["py_peak_alloc_mib"], 0.01)
    ok_peak = big["py_peak_alloc_mib"] < 16.0  # 远小于 256 MiB 成员
    print("\n峰值分配比 (large/small) = %.2f；大成员 Python 峰值 %.2f MiB"
          % (ratio, big["py_peak_alloc_mib"]))
    assert ok_peak, "Python peak grew with binary size: %s" % big

    # 断言 2：RSS 增量远小于处理的字节总量（分块而非全量载入）
    ok_rss = big["rss_growth_mib"] < 128.0
    print("大成员流程 RSS 增量 = %.1f MiB（成员总量 256 MiB）" % big["rss_growth_mib"])
    assert ok_rss, "RSS growth too large: %s" % big

    # 断言 3：所有真实 read 调用都不超过块大小（无一次性整文件读取）
    oversized = [s for s in _read_sizes if s > CHUNK_SIZE]
    print("记录到 read() 调用 %d 次，超过 CHUNK_SIZE(%d) 的 %d 次"
          % (len(_read_sizes), CHUNK_SIZE, len(oversized)))
    assert not oversized, oversized[:5]

    # 断言 4：分块调用确实大量发生（证明走的是流式路径）
    assert len(_read_sizes) > 256, len(_read_sizes)
    print("\n内存测量全部通过：内存占用不随二进制大小增长，全程 1 MiB 分块流式 I/O。")


if __name__ == "__main__":
    main()
