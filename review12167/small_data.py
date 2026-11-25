"""确定性合成取证记录：两台演练终端的小例子 + 独立空区间矛盾案例。

约定 local_ts = true_time + o_g（o_g 为该时钟代的整数偏移，分钟）。

主案例剧情（全部合成）
----------------------
- A 终端回拨前钟快约 +60（A-g0），巡检回拨约 120 分钟后钟慢约 -60（A-g1），
  信标 A-BEACON-ROLLBACK 记录换代；
- B 终端偏移约 0（B-g0），但其授时站校准包“晚到半班”(240 分钟)，
  封存时只有宽勘验区间 [-20,20]，更新时才用晚到校准相交出 [-1,1]；
- 跨设备已签名因果 A-ANCHOR -> B-ANCHOR，时延 [10,30]；
- 目标对 (A-TGT, B-TGT)：原始读数 165 vs 125，单看本地钟会以为 A 晚 B 早
  （顺序颠倒），真时却是 A=105 早、B=125 晚，Δ=+20；
- (A, seq=9) 同号异摘要：v1 在封存卷内，v2 事后送达且用同一把 A 合成密钥
  合法签名，完整性校验必须点名 EQUIVOCATION。

空区间案例
----------
X、Y 各只有一个时钟代、区间 [0,2]；两份反向已签名因果都要求
“本端->对端时延 >=10”，归约出长度 2、权和 -20 的负环，9 个偏移组合全不可行。
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List

from .evidence import build_envelope, write_json, write_jsonl

SHIFT_HALF_MIN = 240  # 半班 = 4 小时

KEYS: Dict[str, str] = {
    "A": "SYNTH-KEY-A-12167-only-for-offline-drill",
    "B": "SYNTH-KEY-B-12167-only-for-offline-drill",
    "X": "SYNTH-KEY-X-12167-only-for-offline-drill",
    "Y": "SYNTH-KEY-Y-12167-only-for-offline-drill",
}

# 封存时的宽勘验区间
SEALED_BOUNDS: Dict[str, List[int]] = {
    "A-g0": [58, 62],
    "A-g1": [-62, -58],
    "B-g0": [-20, 20],
}
# 更新解释仍以同一初始区间为起点，再与晚到校准相交
UPDATED_INITIAL_BOUNDS: Dict[str, List[int]] = dict(SEALED_BOUNDS)

TARGET = {"event1": "A-TGT", "event2": "B-TGT"}
SEAL_CUTOFF = 430


def build_small_case(out_dir: Path) -> Dict[str, Any]:
    out_dir.mkdir(parents=True, exist_ok=True)
    records: List[Dict[str, Any]] = []
    seq_counter: Dict[str, int] = {"A": 0, "B": 0}

    def nxt_seq(dev: str) -> int:
        seq_counter[dev] += 1
        return seq_counter[dev]

    def add(rec_id: str, dev: str, payload: Dict[str, Any], *,
            received_at: int = 0) -> Dict[str, Any]:
        env = build_envelope(
            rec_id=rec_id, device=dev, seq=nxt_seq(dev), payload=payload,
            key=KEYS[dev], received_at=received_at,
        )
        records.append(env)
        return env

    # ===== A：回拨前 A-g0（o≈+60，钟快），按真时/序号递增 =====
    add("A-EARLY", "A", {"kind": "event", "gen": "A-g0", "local_ts": 140,
                         "true_time_hint": 80, "label": "回拨前-早"},  received_at=81)
    add("A-ANCHOR", "A", {"kind": "event", "gen": "A-g0", "local_ts": 150,
                          "true_time_hint": 90, "label": "因果起点"}, received_at=91)
    add("A-TGT", "A", {"kind": "event", "gen": "A-g0", "local_ts": 165,
                       "true_time_hint": 105, "label": "目标A（钟快代）"}, received_at=106)
    add("A-LASTPRE", "A", {"kind": "event", "gen": "A-g0", "local_ts": 210,
                           "true_time_hint": 150, "label": "回拨前末点"}, received_at=151)

    add("A-BEACON-ROLLBACK", "A", {
        "kind": "beacon", "old_gen": "A-g0", "new_gen": "A-g1",
        "action": "clock_rollback", "observed_jump_minutes": -120,
        "note": "巡检把快约60分的钟往回拨约120分，换用 A-g1（此后约慢60分）",
    }, received_at=171)

    # ===== A：回拨后 A-g1（o≈-60，钟慢）；读数 210 -> 140 直观可见回拨 =====
    add("A-POST1", "A", {"kind": "event", "gen": "A-g1", "local_ts": 140,
                         "true_time_hint": 200, "label": "回拨后-1"}, received_at=201)
    add("A-POST2", "A", {"kind": "event", "gen": "A-g1", "local_ts": 180,
                         "true_time_hint": 240, "label": "回拨后-2"}, received_at=241)

    # ===== B：o≈0，序号/真时递增 =====
    add("B-EARLY", "B", {"kind": "event", "gen": "B-g0", "local_ts": 95,
                         "true_time_hint": 95, "label": "B-早"}, received_at=96)
    add("B-ANCHOR", "B", {"kind": "event", "gen": "B-g0", "local_ts": 110,
                          "true_time_hint": 110, "label": "因果终点"}, received_at=111)
    add("B-TGT", "B", {"kind": "event", "gen": "B-g0", "local_ts": 125,
                       "true_time_hint": 125, "label": "目标B"}, received_at=126)

    # ===== 跨设备已签名因果（A 签名）：真时延 20，落在 [10,30] =====
    add("CAUSAL-AB-1", "A", {
        "kind": "causal", "from_event": "A-ANCHOR", "to_event": "B-ANCHOR",
        "latency": [10, 30],
        "claim": "A指挥消息先于B确认；链路时延10..30分钟（A签名）",
    }, received_at=112)

    # ===== 晚到半班的 B 授时校准（封存时点之后才送达）=====
    # 校准参考钟读数 320，包晚到 240 分 -> received_at=560 > 封存截止 430。
    cal_b = build_envelope(
        rec_id="CAL-B-LATE", device="B", seq=nxt_seq("B"),
        payload={
            "kind": "calibration", "gen": "B-g0",
            "offset_interval": [-1, 1], "nominal_offset": 0,
            "sync_source": "演练授时站 MTC-02",
            "reference_clock_ts": 320,
            "delay_minutes": SHIFT_HALF_MIN,
            "delay_note": f"同步包晚到 {SHIFT_HALF_MIN} 分钟（半班），封存后才送达",
        },
        key=KEYS["B"], received_at=320 + SHIFT_HALF_MIN,
    )
    records.append(cal_b)

    # ===== 同号异摘要：固定 (A, seq=9) 两份合法签名、不同摘要 =====
    dup1 = build_envelope(
        rec_id="A-NOTE-DUP-v1", device="A", seq=9,
        payload={"kind": "note", "gen": "A-g1", "version": "v1",
                 "text": "班次正常，未发现时钟异常。"},
        key=KEYS["A"], received_at=400,
    )
    dup2 = build_envelope(
        rec_id="A-NOTE-DUP-v2", device="A", seq=9,
        payload={"kind": "note", "gen": "A-g1", "version": "v2",
                 "text": "其实回拨过时钟，原备注与本份摘要不同。"},
        key=KEYS["A"], received_at=470,
    )
    records.extend([dup1, dup2])

    # 完整性：全部记录都应通过摘要/签名；同号异摘要由 verify_bundle 点名。
    write_jsonl(out_dir / "records.jsonl", records)
    write_json(out_dir / "keys.json", {k: KEYS[k] for k in ("A", "B")})
    write_json(out_dir / "bounds_sealed.json", SEALED_BOUNDS)
    write_json(out_dir / "bounds_updated.json", UPDATED_INITIAL_BOUNDS)
    write_json(out_dir / "target.json", TARGET)

    sealed = [r for r in records
              if int(r.get("received_at") or 0) <= SEAL_CUTOFF]
    write_jsonl(out_dir / "sealed_records.jsonl", sealed)
    write_json(out_dir / "seal_meta.json", {
        "seal_cutoff_received_at": SEAL_CUTOFF,
        "late_or_post_seal_records": [
            r["rec_id"] for r in records
            if int(r.get("received_at") or 0) > SEAL_CUTOFF
        ],
        "shift_half_minutes": SHIFT_HALF_MIN,
    })

    raw_gap = 125 - 165  # s_B - s_A
    return {
        "case": "two_terminal_rollback_late_sync",
        "out_dir": str(out_dir),
        "record_count": len(records),
        "sealed_count": len(sealed),
        "target": TARGET,
        "raw_local_gap_B_minus_A": raw_gap,
        "raw_apparent_order": "按本地读数 A-TGT=165 晚于 B-TGT=125，看似颠倒",
        "true_gap_hint": 20,
    }


def build_empty_case(out_dir: Path) -> Dict[str, Any]:
    out_dir.mkdir(parents=True, exist_ok=True)
    records: List[Dict[str, Any]] = []

    def add(rec_id: str, dev: str, seq: int, payload: Dict[str, Any]) -> None:
        records.append(build_envelope(
            rec_id=rec_id, device=dev, seq=seq, payload=payload,
            key=KEYS[dev], received_at=seq,
        ))

    bounds = {"X-g0": [0, 2], "Y-g0": [0, 2]}
    # 两事件本地读数都取 0，简化边权。
    add("X-E", "X", 1, {"kind": "event", "gen": "X-g0", "local_ts": 0})
    add("Y-E", "Y", 1, {"kind": "event", "gen": "Y-g0", "local_ts": 0})
    add("CA-XY", "X", 2, {
        "kind": "causal", "from_event": "X-E", "to_event": "Y-E",
        "latency": [10, 20], "claim": "X->Y 至少10分",
    })
    add("CA-YX", "Y", 2, {
        "kind": "causal", "from_event": "Y-E", "to_event": "X-E",
        "latency": [10, 20], "claim": "Y->X 至少10分（与上一份冲突）",
    })

    write_jsonl(out_dir / "records.jsonl", records)
    write_json(out_dir / "keys.json", {k: KEYS[k] for k in ("X", "Y")})
    write_json(out_dir / "bounds.json", bounds)
    write_json(out_dir / "target.json", {"event1": "X-E", "event2": "Y-E"})
    return {
        "case": "empty_interval_contradiction",
        "out_dir": str(out_dir),
        "record_count": len(records),
        "target": {"event1": "X-E", "event2": "Y-E"},
    }
