# -*- coding: utf-8 -*-
"""离线保存证据仓（offline preservation evidence repository）。"""
import sys

__version__ = "1.0.0"

# 谱系诊断/选路沿依赖链递归；长迁移链可能远超解释器默认 1000 帧。
# 求值本身在 SQLite 内完成（不受此限），此处仅放宽 Python 侧 DFS 深度。
if sys.getrecursionlimit() < 10000:
    sys.setrecursionlimit(10000)
