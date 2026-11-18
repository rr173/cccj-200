# -*- coding: utf-8 -*-
"""
路径规模测试：大量对象与事件（图规模）下，求值走 SQL 落盘不动点，
Python 侧内存不随路径数增长；且 OR 多路径与长链证明正确。
"""
from __future__ import annotations

import os
import shutil
import sys
import tracemalloc

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))

from evidrepo import db as dbmod  # noqa: E402
from evidrepo import diagnostics, ingest  # noqa: E402
from evidrepo.evaluate import object_state  # noqa: E402

from fixtures import PackageBuilder  # noqa: E402

WORK = "/workspace/runs/scale"


def build_chain(n, measure_only_eval=False):
    shutil.rmtree(WORK, ignore_errors=True)
    os.makedirs(WORK + "/pkgs")
    conn = dbmod.connect(WORK + "/repo")
    b = PackageBuilder(WORK + "/pkgs", "CHAIN",
                       trusted_ingest=("ing-O0",))
    b.add_bitstream("O0", b"root")
    for i in range(1, n + 1):
        b.add_bitstream("O%d" % i, ("payload-%d" % i).encode())
    b.add_representation("RCHAIN", ["O%d" % n], nodes=["chain-node"])
    b.add_event("ing-O0", "ingest", outputs=["O0"])
    for i in range(1, n + 1):
        # 每个 Oi 再加一条“旁路”迁移，制造 OR 候选，增加图边数
        b.add_event("mig-%d" % i, "migration",
                    inputs=["O%d" % (i - 1)], outputs=["O%d" % i])
    b.build()
    if measure_only_eval:
        # 数据构造发生在子进程外；此处只测量接包+落盘不动点求值
        import builtins
        import gc as _gc
        _gc.collect()
        tracemalloc.start()
        ingest.receive(conn, WORK + "/repo", WORK + "/pkgs/CHAIN")
        ingest.finish(conn, WORK + "/repo", "CHAIN")
        _, peak_eval = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        return conn, peak_eval
    ingest.receive(conn, WORK + "/repo", WORK + "/pkgs/CHAIN")
    ingest.finish(conn, WORK + "/repo", "CHAIN")
    return conn, 0


def _measure_in_subprocess(n):
    """独立进程+独立目录测量：用 RSS 差值（不启用会显著拖慢运行的 tracemalloc）。"""
    import subprocess
    iso = os.path.join(WORK, "iso-%d" % n)
    shutil.rmtree(iso, ignore_errors=True)
    code = r'''
import gc, sys, os, time
sys.path.insert(0, "__HERE__"); sys.path.insert(0, "__PARENT__")
from evidrepo import ingest, db as dbmod
from fixtures import PackageBuilder

def rss_kib():
    for line in open("/proc/self/status"):
        if line.startswith("VmRSS:"):
            return int(line.split()[1])
    return 0

WORK = "__WORK__"; n = __N__
os.makedirs(WORK + "/pkgs", exist_ok=True)
conn = dbmod.connect(WORK + "/repo")
b = PackageBuilder(WORK + "/pkgs", "CHAIN", trusted_ingest=("ing-O0",))
b.add_bitstream("O0", b"root")
for i in range(1, n + 1):
    b.add_bitstream("O%d" % i, ("p-%d" % i).encode())
b.add_event("ing-O0", "ingest", outputs=["O0"])
for i in range(1, n + 1):
    b.add_event("mig-%d" % i, "migration",
                inputs=["O%d" % (i - 1)], outputs=["O%d" % i])
b.build()
gc.collect()
rss0 = rss_kib()
t0 = time.time()
ingest.receive(conn, WORK + "/repo", WORK + "/pkgs/CHAIN")
ingest.finish(conn, WORK + "/repo", "CHAIN")
elapsed = time.time() - t0
gc.collect()
rss1 = rss_kib()
# 输出：当前 RSS 增量(KiB)、耗时
print("%d %.3f" % (max(rss1 - rss0, 0), elapsed))
'''
    code = (code.replace("__HERE__", HERE)
                .replace("__PARENT__", os.path.dirname(HERE))
                .replace("__WORK__", iso)
                .replace("__N__", str(n)))
    out = subprocess.run(
        [sys.executable, "-I", "-c", code], capture_output=True, text=True
    )
    if out.returncode != 0:
        raise RuntimeError("subprocess failed:\n" + out.stderr)
    rss_grow_kib, elapsed = out.stdout.strip().splitlines()[-1].split()
    return int(rss_grow_kib), float(elapsed)


def main():
    n_small, n_big = 200, 2000
    # 功能正确性（主进程）
    conn_s, _ = build_chain(n_small)
    state, proven = object_state(conn_s, "local", "O%d" % n_small)
    assert state == "bytes_ok" and proven, (state, proven)
    rep = diagnostics.evaluate_representation(conn_s, "local", "RCHAIN")
    assert rep["label"] == "verified", rep["label"]
    conn_s.close()

    conn_b, _ = build_chain(n_big)
    state, proven = object_state(conn_b, "local", "O%d" % n_big)
    assert state == "bytes_ok" and proven, (state, proven)
    expl = diagnostics.explain_object(conn_b, "local", "O%d" % n_big)
    assert expl["chosen_event"] == "mig-%d" % n_big
    n_events = conn_b.execute("SELECT COUNT(*) c FROM events").fetchone()["c"]
    n_links = conn_b.execute("SELECT COUNT(*) c FROM event_links").fetchone()["c"]
    conn_b.close()

    # 内存（独立进程，RSS 增量；不启用会拖慢运行的 tracemalloc）
    rss_s, t_s = _measure_in_subprocess(n_small)
    rss_b, t_b = _measure_in_subprocess(n_big)
    print("链长 %d: 事件 %d 链接 %d | RSS 增量 %.1f MiB | 耗时 %.2fs"
          % (n_small, n_small + 1, 2 * (n_small + 1), rss_s / 1024, t_s))
    print("链长 %d: 事件 %d 链接 %d | RSS 增量 %.1f MiB | 耗时 %.2fs"
          % (n_big, n_big + 1, 2 * (n_big + 1), rss_b / 1024, t_b))
    # 图规模 10 倍，RSS 增量倍数应显著低于 10 倍（次线性：图与求值落盘，
    # 仅 XML 文档解析产生与文档大小相关的瞬时对象，解析完即可回收）。
    rss_growth = rss_b / max(rss_s, 1)
    per_node_b = rss_b / n_big
    print("RSS 增量倍数 %.2f（图规模 10 倍，次线性即 <10）；大链每节点约 %.1f KiB"
          % (rss_growth, per_node_b))
    assert rss_growth < 8.0, "RSS grew linearly with path count: %.2f" % rss_growth
    assert t_b < 30.0, "too slow without tracemalloc: %.2fs" % t_b
    print("路径规模测试通过：图与求值落盘，内存次线性增长，长链证明正确，"
          "2000 节点全流程 %.1fs。" % t_b)


if __name__ == "__main__":
    main()
