"""确定性合成规模数据：>=60000 个事件，图不全连通（大量互不相连的分片组件）。

每个分片 shard 是两台设备 P#### / Q####，各一个时钟代、K 个事件，
内部一条稀疏事件链加少量跨设备因果边；分片之间没有任何边，
因此整体图是稀疏且断开的（SHARDS 个弱组件，绝非全连通）。
"""
from __future__ import annotations

import random
from pathlib import Path
from typing import Any, Dict, List

from .evidence import build_envelope, write_json, write_jsonl

SHARDS = 300
EVENTS_PER_DEVICE = 105          # 每分片 2*105=210 事件 -> 63000 事件
SHARED_SCALE_KEY = "SYNTH-SCALE-SHARED-KEY-12167-not-a-real-secret"
TARGET_SHARD = 17


def shard_devices(s: int) -> tuple[str, str]:
    return f"P{s:04d}", f"Q{s:04d}"


def build_scale_case(out_dir: Path) -> Dict[str, Any]:
    out_dir.mkdir(parents=True, exist_ok=True)
    rng = random.Random(20261126)
    records: List[Dict[str, Any]] = []
    keys: Dict[str, str] = {}
    initial_bounds: Dict[str, List[int]] = {}
    targets: List[Dict[str, str]] = []

    for s in range(SHARDS):
        pd, qd = shard_devices(s)
        keys[pd] = SHARED_SCALE_KEY
        keys[qd] = SHARED_SCALE_KEY
        pg, qg = f"{pd}-g", f"{qd}-g"
        op = (s % 7) - 3           # 真值偏移（仅用于造数，求解器不可见）
        oq = (s % 5) - 2
        initial_bounds[pg] = [op - 10, op + 10]
        initial_bounds[qg] = [oq - 10, oq + 10]

        p_seqs = 0
        q_seqs = 0

        def sign(dev: str, seq: int, payload: Dict[str, Any], rid: str,
                 recv: int) -> Dict[str, Any]:
            return build_envelope(
                rec_id=rid, device=dev, seq=seq, payload=payload,
                key=SHARED_SCALE_KEY, received_at=recv)

        p_ids: List[str] = []
        q_ids: List[str] = []
        for i in range(EVENTS_PER_DEVICE):
            true_p = 10_000 + i * 10 + s
            lp = true_p + op
            rid_p = f"S{s:04d}-P-E{i:03d}"
            p_seqs += 1
            records.append(sign(pd, p_seqs, {
                "kind": "event", "gen": pg, "local_ts": lp, "i": i,
            }, rid_p, lp + 1))
            p_ids.append(rid_p)

            gap = 3 + (i % 7)      # Q 比 P 真晚 3..9 分
            true_q = true_p + gap
            lq = true_q + oq
            rid_q = f"S{s:04d}-Q-E{i:03d}"
            q_seqs += 1
            records.append(sign(qd, q_seqs, {
                "kind": "event", "gen": qg, "local_ts": lq, "i": i,
            }, rid_q, lq + 1))
            q_ids.append(rid_q)

            if i % 15 == 0:
                # 宽松时延界 [0,60] 覆盖 gap 3..9；刻意不把偏移差夹死，
                # 这样补一个窄校准会经由锚点路径真正收紧目标区间。
                records.append(sign(pd, p_seqs + 1000 + i, {
                    "kind": "causal", "from_event": rid_p, "to_event": rid_q,
                    "latency": [0, 60],
                }, f"S{s:04d}-CA{i:03d}", lq + 2))

        targets.append({"shard": s, "event1": f"S{s:04d}-P-E050",
                        "event2": f"S{s:04d}-Q-E050"})

    event_count = 2 * SHARDS * EVENTS_PER_DEVICE
    write_jsonl(out_dir / "records.jsonl", records)
    write_json(out_dir / "keys.json", keys)
    write_json(out_dir / "bounds.json", initial_bounds)
    write_json(out_dir / "targets.json", {"targets": targets,
                                          "target_shard": TARGET_SHARD})

    # 目标分片要补的“一个校准”（窄区间，包住真值 oq）
    tq = shard_devices(TARGET_SHARD)[1]
    true_oq = (TARGET_SHARD % 5) - 2
    calibration = build_envelope(
        rec_id=f"S{TARGET_SHARD:04d}-CAL-ONE", device=tq, seq=9001,
        payload={"kind": "calibration", "gen": f"{tq}-g",
                 "offset_interval": [true_oq - 1, true_oq + 1],
                 "sync_source": "scale-mtc"},
        key=SHARED_SCALE_KEY, received_at=99_999_999,
    )
    write_json(out_dir / "one_calibration.json", calibration)

    return {
        "case": "scale_disconnected_shards",
        "out_dir": str(out_dir),
        "shards": SHARDS,
        "events_per_device": EVENTS_PER_DEVICE,
        "event_count": event_count,
        "total_records": len(records),
        "target_shard": TARGET_SHARD,
        "target_component_hint": f"C? (build_model 后确定)",
    }
