# -*- coding: utf-8 -*-
"""
对账规模与算法路线一致性测试。

1. 中等规模随机二分图：产品分析 vs 独立 Kuhn 最大匹配（不复用产品函数）；
2. 逐边“强制/排除后重解”的第二条路线 vs 产品交替路径/强连通结构路线，
   两者对“可现边”“强制边”必须给出相同语义；
3. 大清单 + 大量封存表示下的有界内存与耗时（不提交大型生成数据集，
   数据在本脚本运行时生成）。
"""
from __future__ import annotations

import os
import random
import shutil
import sys
import time
import tracemalloc

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))

from evidrepo.reconcile import analyze_matching, _hopcroft_karp  # noqa: E402


def kuhn_size(nL, nR, adj):
    """独立实现（Kuhn 增广路），只用来核对最大匹配基数。"""
    sys.setrecursionlimit(1000000)
    pairV = [-1] * nR

    def try_k(u, vis):
        for v in adj[u]:
            if vis[v]:
                continue
            vis[v] = True
            if pairV[v] == -1 or try_k(pairV[v], vis):
                pairV[v] = u
                return True
        return False

    size = 0
    for u in range(nL):
        if try_k(u, [False] * nR):
            size += 1
    return size


def resized_max(nL, nR, adj, exclude=None, force=None):
    a = [list(x) for x in adj]
    if force is not None:
        fu, fv = force
        for u in range(nL):
            a[u] = [fv] if u == fu else [v for v in a[u] if v != fv]
    if exclude is not None:
        eu, ev = exclude
        a[eu] = [v for v in a[eu] if v != ev]
    pu, _ = _hopcroft_karp(nL, a, nR)
    return sum(1 for x in pu if x != -1)


def route_agreement():
    print("[1/2] 两条歧义语义路线一致性（随机小图，逐边强制/排除重解）")
    random.seed(20261119)
    bad = 0
    total = 0
    for t in range(200):
        nL = random.randint(1, 14)
        nR = random.randint(1, 14)
        adj = [sorted(random.sample(range(nR),
                                    random.randint(1, min(5, nR))))
               for _ in range(nL)]
        edges = {(u, v) for u in range(nL) for v in adj[u]}
        a = analyze_matching(nL, nR, edges, adj)
        k = a["size"]
        assert k == kuhn_size(nL, nR, adj), "matching cardinality mismatch"
        some = set()
        for (u, v) in edges:
            total += 1
            if resized_max(nL, nR, adj, force=(u, v)) == k:
                some.add((u, v))
        forced_alt = {
            (u, v) for (u, v) in some
            if resized_max(nL, nR, adj, exclude=(u, v)) < k
        }
        if a["allowed"] != some or a["forced"] != forced_alt:
            bad += 1
            print("  mismatch at trial", t)
            break
    print("  检查 %d 条边；路线A(交替路径+SCC) vs 路线B(强制/排除重解)：%s"
          % (total, "一致" if bad == 0 else "不一致"))
    assert bad == 0


def scale_case(n_rep, n_obl, label):
    print("[%s] 规模：实际身份 %d、义务 %d" % (label, n_rep, n_obl))
    random.seed(7)
    adj = []
    for _ in range(n_obl):
        adj.append(sorted(random.sample(range(n_rep), min(3, n_rep))))
    edges = {(u, v) for u in range(n_obl) for v in adj[u]}
    tracemalloc.start()
    t0 = time.time()
    a = analyze_matching(n_obl, n_rep, edges, adj)
    elapsed = time.time() - t0
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    assert a["size"] == kuhn_size(n_obl, n_rep, adj)
    print("  最大匹配 %d / %d，耗时 %.2fs，峰值 %.1f MiB"
          % (a["size"], min(n_rep, n_obl), elapsed, peak / 1048576))
    return a["size"], peak, elapsed


def main():
    route_agreement()
    s1, p1, t1 = scale_case(500, 500, "3/4")
    s2, p2, t2 = scale_case(2000, 4000, "4/4")
    # 随机稀疏图不一定存在完美匹配；正确性已由 Kuhn 交叉核对，
    # 这里只要求规模合理且内存/时间有界。
    assert 0 < s1 <= 500 and 0 < s2 <= 2000, (s1, s2)
    assert p2 < 128 * 1024 * 1024, p2
    assert t2 < 60.0, t2
    print("\n规模测试通过：两条歧义路线语义一致；大图有界内存、可接受耗时。")


if __name__ == "__main__":
    main()
