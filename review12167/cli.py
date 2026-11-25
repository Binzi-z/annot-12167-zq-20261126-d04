"""命令行入口：python -m review12167.cli [small|empty|scale|all|verify]."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import pipeline

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
except Exception:
    pass


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="12167 离线取证时间差复核（标准库）")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("small", help="两台终端小例子（回拨/同号异摘要/见证/枚举核对）")
    sub.add_parser("empty", help="空区间矛盾案例与最短证书")
    sub.add_parser("scale", help=">=60000 事件规模验收与增量重算度量")
    sub.add_parser("all", help="依次运行 small+empty+scale")
    vf = sub.add_parser("verify", help="独立复核矛盾证书（转发到 verify_certificate）")
    vf.add_argument("certificate", type=Path)
    vf.add_argument("--keys", type=Path, required=True)
    args = ap.parse_args(argv)

    if args.cmd == "small":
        r = pipeline.run_small()
        print("small updated interval:", r["updated_interval"])
        print("small sealed interval :", r["sealed_interval"])
        print("equivocations        :", len(r["verification_full"]["equivocations"]))
        print("cross-check          :", r["cross_check_updated"]["match"])
    elif args.cmd == "empty":
        r = pipeline.run_empty()
        print("empty feasible combos:", r["oracle"]["feasible_count"])
        print("cert min length      :", r["certificate_review"]["independent_dp_min_length"])
        print(r["certificate_review"]["verdict"])
    elif args.cmd == "scale":
        r = pipeline.run_scale()
        print("events/components    :", r["event_count"], r["component_count"])
        print("recompute            :", r["recomputed_component"],
              "records =", r["component_record_count"])
        print("interval before/after:", r["interval_before"], r["interval_after"])
        print("others unchanged     :", r["all_other_shards_unchanged"])
    elif args.cmd == "all":
        s = pipeline.run_all()
        for k, v in s.items():
            print(f"{k}: {v}")
    elif args.cmd == "verify":
        from .verify_certificate import main as verify_main
        return verify_main([str(args.certificate), "--keys", str(args.keys)])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
