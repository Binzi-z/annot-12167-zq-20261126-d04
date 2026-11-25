"""小例子专用：遍历组件内所有整数偏移组合的暴力 oracle。

与最短路求解完全独立：直接枚举笛卡尔积、逐条检查不等式，
并据此求目标真时差的真实最小/最大值与端点指派。
"""
from __future__ import annotations

import itertools
from typing import Any, Dict, List, Optional

from .constraints import CaseModel
from .solver import prepare_component


def enumerate_all_offsets(
    model: CaseModel, cid: str, target: Optional[Dict[str, str]] = None
) -> Dict[str, Any]:
    gens = list(model.components[cid])
    ranges = [range(model.bounds[g].lo, model.bounds[g].hi + 1) for g in gens]
    total_combos = 1
    for r in ranges:
        total_combos *= len(r)

    pc = prepare_component(model, cid)
    record_edges = [e for e in pc.edges if "__anchor__" not in (e.u, e.v)]

    feasible: List[Dict[str, int]] = []
    checked = 0
    for combo in itertools.product(*ranges):
        checked += 1
        off = dict(zip(gens, combo))
        ok = True
        for e in record_edges:
            if off[e.v] - off[e.u] > e.w:
                ok = False
                break
        if ok:
            feasible.append(off)

    result: Dict[str, Any] = {
        "component": cid,
        "generations": gens,
        "interval_sizes": {g: len(r) for g, r in zip(gens, ranges)},
        "total_offset_combinations": total_combos,
        "enumerated": checked,
        "feasible_count": len(feasible),
        "empty": len(feasible) == 0,
    }

    if target is not None and feasible:
        e1 = model.events[target["event1"]]
        e2 = model.events[target["event2"]]
        s1 = int(e1["payload"]["local_ts"]); s2 = int(e2["payload"]["local_ts"])
        g1 = e1["payload"]["gen"]; g2 = e2["payload"]["gen"]
        c = s2 - s1
        scored = []
        for off in feasible:
            delta = c + off[g1] - off[g2]
            scored.append((delta, off))
        dmin = min(d for d, _ in scored)
        dmax = max(d for d, _ in scored)
        witness_min = next(off for d, off in scored if d == dmin)
        witness_max = next(off for d, off in scored if d == dmax)
        result["target"] = {
            "event1": target["event1"], "event2": target["event2"], "C": c,
            "bruteforce_interval": [dmin, dmax],
            "witness_min": witness_min,
            "witness_max": witness_max,
        }
    return result
