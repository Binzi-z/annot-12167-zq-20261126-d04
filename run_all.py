#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""一键离线复核：生成合成数据、跑全部分析与测试。

用法（Windows，原生 Python 3.8+，仅标准库）：
    python run_all.py
或双击/执行 run_all.bat。
"""
from __future__ import annotations

import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from review12167 import pipeline  # noqa: E402


def run_tests() -> bool:
    loader = unittest.TestLoader()
    suite = loader.discover(str(ROOT / "tests"), pattern="test_*.py")
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    return result.wasSuccessful()


def main() -> int:
    print("=" * 72)
    print("第 1 步：端到端生成 + 求解 + 报告")
    print("=" * 72)
    summary = pipeline.run_all()
    for k, v in summary.items():
        print(f"  {k}: {v}")

    print("\n" + "=" * 72)
    print("第 2 步：独立证书复核器（子进程、纯标准库脚本）")
    print("=" * 72)
    cert = ROOT / "reports" / "contradiction_certificate.json"
    keys = ROOT / "artifacts" / "12167" / "empty" / "keys.json"
    proc = subprocess.run(
        [sys.executable, str(ROOT / "review12167" / "verify_certificate.py"),
         str(cert), "--keys", str(keys)],
        cwd=str(ROOT),
    )
    if proc.returncode != 0:
        print("独立证书复核失败")
        return proc.returncode

    print("\n" + "=" * 72)
    print("第 3 步：unittest（含全偏移枚举交叉验证与规模断言）")
    print("=" * 72)
    ok = run_tests()
    if not ok:
        print("TESTS_FAILED")
        return 1
    print("\nALL_OK：报告见 reports/ ，大块数据见 artifacts/12167/")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
