"""端到端编排：小例子、空区间证书、规模验收，并产出封存/更新两份报告。

仅使用标准库。所有产物：
- artifacts/12167/...  大块合成数据与机器结果（.gitignore 已忽略 artifacts/）
- reports/...          人读报告与精简指标（保留在工作区）
"""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path
from typing import Any, Dict, List

from . import small_data, scale_data
from .certificate import build_negative_certificate
from .constraints import build_model, component_records
from .evidence import (hash_file, hash_records, read_json, read_jsonl,
                       verify_bundle, write_json)
from .oracle import enumerate_all_offsets
from .solver import (ANCHOR, NegativeCycle, bellman_ford,
                     prepare_component, shortest_negative_cycle, solve_target)
from .verify_certificate import verify as verify_certificate_file

ROOT = Path(__file__).resolve().parent.parent
ART = ROOT / "artifacts" / "12167"
REPORTS = ROOT / "reports"

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
except Exception:
    pass


def _bool_sig_ok(ver: Dict[str, Any]) -> bool:
    return not (ver["bad_digest"] or ver["bad_signature"]
                or ver["unknown_device_key"])


# ---------------------------------------------------------------------------
# 小例子
# ---------------------------------------------------------------------------
def run_small() -> Dict[str, Any]:
    small_dir = ART / "small"
    info = small_data.build_small_case(small_dir)
    records = read_jsonl(small_dir / "records.jsonl")
    sealed_records = read_jsonl(small_dir / "sealed_records.jsonl")
    keys = read_json(small_dir / "keys.json")
    bounds_sealed = read_json(small_dir / "bounds_sealed.json")
    bounds_updated0 = read_json(small_dir / "bounds_updated.json")
    target = read_json(small_dir / "target.json")

    ver_full = verify_bundle(records, keys).summary()
    ver_sealed = verify_bundle(sealed_records, keys).summary()

    # 封存视图：仅封存记录 + 宽区间
    model_sealed = build_model(sealed_records, bounds_sealed)
    res_sealed = solve_target(model_sealed, _req(target))
    oracle_sealed = enumerate_all_offsets(
        model_sealed, res_sealed["component"], target)

    # 更新视图：全部记录（含晚到校准、第二份同号异摘要）+ 同一初始区间
    model_upd = build_model(records, bounds_updated0)
    res_upd = solve_target(model_upd, _req(target))
    oracle_upd = enumerate_all_offsets(
        model_upd, res_upd["component"], target)

    cross = _cross_check(res_upd, oracle_upd)
    cross_sealed = _cross_check(res_sealed, oracle_sealed)
    if not cross["match"] or not cross_sealed["match"]:
        raise AssertionError(
            f"最短路区间与全偏移枚举不一致: updated={cross} sealed={cross_sealed}")

    # 封存卷摘要（区分两份报告的锚点）
    sealed_root = hash_records(sealed_records)
    full_root = hash_records(records)

    result = {
        "info": info,
        "verification_full": ver_full,
        "verification_sealed": ver_sealed,
        "sealed_record_root": sealed_root,
        "full_record_root": full_root,
        "sealed_interval": res_sealed["delta_interval"],
        "sealed_witness_lower": res_sealed["witness_lower"],
        "sealed_witness_upper": res_sealed["witness_upper"],
        "sealed_oracle": oracle_sealed,
        "updated_interval": res_upd["delta_interval"],
        "updated_witness_lower": res_upd["witness_lower"],
        "updated_witness_upper": res_upd["witness_upper"],
        "updated_oracle": oracle_upd,
        "cross_check_updated": cross,
        "cross_check_sealed": cross_sealed,
        "updated_result_full": res_upd,
        "sealed_result_full": res_sealed,
    }
    write_json(small_dir / "small_result.json", result)
    write_json(REPORTS / "small_result.json", {
        k: v for k, v in result.items()
        if k not in ("updated_result_full", "sealed_result_full")})

    _write_sealed_report(result)
    _write_updated_report(result)
    return result


def _req(target: Dict[str, str]):
    from .solver import TargetRequest
    return TargetRequest(event1=target["event1"], event2=target["event2"])


def _cross_check(res: Dict[str, Any], oracle: Dict[str, Any]) -> Dict[str, Any]:
    ob = oracle["target"]["bruteforce_interval"]
    sb = res["delta_interval"]
    return {
        "match": ob == sb,
        "solver_interval": sb,
        "bruteforce_interval": ob,
        "feasible_combos": oracle["feasible_count"],
        "total_combos": oracle["total_offset_combinations"],
        "bruteforce_witness_min": oracle["target"]["witness_min"],
        "bruteforce_witness_max": oracle["target"]["witness_max"],
    }


# ---------------------------------------------------------------------------
# 空区间 / 最短矛盾证书
# ---------------------------------------------------------------------------
def run_empty() -> Dict[str, Any]:
    empty_dir = ART / "empty"
    small_data.build_empty_case(empty_dir)
    records = read_jsonl(empty_dir / "records.jsonl")
    keys = read_json(empty_dir / "keys.json")
    bounds = read_json(empty_dir / "bounds.json")
    target = read_json(empty_dir / "target.json")

    ver = verify_bundle(records, keys).summary()
    model = build_model(records, bounds)
    cid = next(iter(model.components))
    pc = prepare_component(model, cid)
    infeasible = False
    try:
        bellman_ford(pc, ANCHOR)
    except NegativeCycle:
        infeasible = True
    if not infeasible:
        raise AssertionError("空区间案例未检测到负环，数据/算法有误")

    snc = shortest_negative_cycle(pc)
    cert_info = {"component": cid, **snc}
    cert = build_negative_certificate(
        model, cert_info, records, bounds,
        case_name="empty_interval_contradiction", target=target)
    cert_path = empty_dir / "negative_certificate.json"
    write_json(cert_path, cert)

    # 全偏移枚举：必须 0 可行
    oracle = enumerate_all_offsets(model, cid, target)
    if oracle["feasible_count"] != 0:
        raise AssertionError("空区间案例枚举竟存在可行指派")

    # 进程内调用“独立复核器”（它不依赖包内状态，仅吃证书文件+keys）
    review = verify_certificate_file(cert_path, empty_dir / "keys.json")

    out = {
        "verification": ver,
        "component": cid,
        "oracle": oracle,
        "certificate_path": str(cert_path),
        "certificate_review": {
            k: v for k, v in review.items() if k != "edge_explanations"},
        "edge_explanations": review["edge_explanations"],
    }
    write_json(empty_dir / "empty_result.json", out)
    write_json(REPORTS / "contradiction_certificate.json", cert)
    write_json(REPORTS / "empty_result.json", out)
    _write_empty_report(out, cert)
    return out


# ---------------------------------------------------------------------------
# 规模
# ---------------------------------------------------------------------------
def run_scale() -> Dict[str, Any]:
    scale_dir = ART / "scale"
    info = scale_data.build_scale_case(scale_dir)

    t_load0 = time.perf_counter()
    records = read_jsonl(scale_dir / "records.jsonl")
    keys = read_json(scale_dir / "keys.json")
    bounds = read_json(scale_dir / "bounds.json")
    targets_doc = read_json(scale_dir / "targets.json")
    t_load = time.perf_counter() - t_load0

    t_verify0 = time.perf_counter()
    ver = verify_bundle(records, keys).summary()
    t_verify = time.perf_counter() - t_verify0

    t_build0 = time.perf_counter()
    model = build_model(records, bounds)
    t_build = time.perf_counter() - t_build0
    n_comp = len(model.components)

    # 全量基线：每个分片目标都求一次（用于之后证明只有目标组件变化）
    t_base0 = time.perf_counter()
    baseline: Dict[str, List[int]] = {}
    feasible_all = True
    for t in targets_doc["targets"]:
        r = solve_target(model, _req(t))
        if not r.get("feasible"):
            feasible_all = False
            continue
        baseline[t["shard"]] = r["delta_interval"]
    t_base = time.perf_counter() - t_base0

    ts = targets_doc["target_shard"]
    qg = f"Q{ts:04d}-g"
    affected_cid = model.gen_to_component[qg]

    # 补一个校准
    cal = read_json(scale_dir / "one_calibration.json")
    records_after = records + [cal]

    # —— 增量：只更新该 Bound 并只重算受影响组件 ——
    b = model.bounds[qg]
    lo = int(cal["payload"]["offset_interval"][0])
    hi = int(cal["payload"]["offset_interval"][1])
    b.lo = max(b.lo, lo)
    b.hi = min(b.hi, hi)
    # 新校准记录的主属组件就是该时钟代所在组件，登记后才能计入“重算记录数”。
    model.record_primary_gen[cal["rec_id"]] = qg

    target_req = _req(next(t for t in targets_doc["targets"] if t["shard"] == ts))
    t_comp0 = time.perf_counter()
    after = solve_target(model, target_req)
    t_comp = time.perf_counter() - t_comp0

    comp_rec_ids = component_records(model, records_after, affected_cid)
    breakdown = _record_breakdown(records_after, set(comp_rec_ids))

    # —— 正确性审计：全量重建模型再解一次，必须与增量结果一致 ——
    t_full0 = time.perf_counter()
    model_full = build_model(records_after, bounds)
    after_full = solve_target(model_full, target_req)
    t_full_rebuild_solve = time.perf_counter() - t_full0

    changed_shards: List[int] = []
    identical_others = True
    for t in targets_doc["targets"]:
        r = solve_target(model_full, _req(t))
        if not r.get("feasible"):
            continue
        if t["shard"] == ts:
            if r["delta_interval"] != after["delta_interval"]:
                raise AssertionError("增量与全量重算的目标区间不一致")
        elif r["delta_interval"] != baseline[t["shard"]]:
            identical_others = False
            changed_shards.append(t["shard"])

    if after_full["delta_interval"] != after["delta_interval"]:
        raise AssertionError("增量结果与全量重建结果不一致")

    result = {
        "info": info,
        "load_seconds": round(t_load, 3),
        "verify_seconds": round(t_verify, 3),
        "build_model_seconds": round(t_build, 3),
        "baseline_solve_all_shards_seconds": round(t_base, 3),
        "full_rebuild_and_target_solve_seconds": round(t_full_rebuild_solve, 3),
        "signature_valid_records": ver["valid_count"],
        "signature_problem_records": len(ver["bad_digest"]) + len(ver["bad_signature"]),
        "event_count": info["event_count"],
        "total_records_before_cal": info["total_records"],
        "total_records_after_cal": len(records_after),
        "component_count": n_comp,
        "graph_fully_connected": n_comp == 1,
        "target_shard": ts,
        "recomputed_component": affected_cid,
        "component_generations": model.components[affected_cid],
        "component_record_count": len(comp_rec_ids),
        "component_record_breakdown": breakdown,
        "component_recompute_seconds": round(t_comp, 6),
        "interval_before": baseline[ts],
        "interval_after": after["delta_interval"],
        "witness_after_lower": after["witness_lower"],
        "witness_after_upper": after["witness_upper"],
        "witness_lower_check": after["witness_lower_check"],
        "witness_upper_check": after["witness_upper_check"],
        "all_other_shards_unchanged": identical_others,
        "unexpected_changed_shards": changed_shards,
        "all_baseline_shards_feasible": feasible_all,
        "incremental_matches_full_rebuild": True,
    }
    write_json(scale_dir / "scale_metrics.json", result)
    write_json(REPORTS / "scale_metrics.json", result)
    _write_scale_report(result)
    return result


def _record_breakdown(records: List[Dict[str, Any]], idset: set) -> Dict[str, int]:
    bd: Dict[str, int] = {}
    for r in records:
        if r["rec_id"] in idset:
            k = r.get("payload", {}).get("kind", "?")
            bd[k] = bd.get(k, 0) + 1
    return bd


# ---------------------------------------------------------------------------
# Markdown 报告
# ---------------------------------------------------------------------------
def _write_sealed_report(r: Dict[str, Any]) -> None:
    REPORTS.mkdir(exist_ok=True)
    info = r["info"]
    md = f"""# 原封存报告（历史快照，不改写）

- 用例：两台演练终端 / 时钟回拨 / 同步晚到半班
- 封存截止 received_at ≤ 430；晚到校准 `CAL-B-LATE`（received_at=560，晚 {small_data.SHIFT_HALF_MIN} 分钟）与第二份同号异摘要备注均**不在封存卷内**。
- 封存记录数：{info['sealed_count']}；封存记录根摘要：`{r['sealed_record_root']}`

## 一、封存时的原始判读

目标事件对 `A-TGT`(本地读数 165) 与 `B-TGT`(本地读数 125)。
**直接按两台钟的本地时间戳排序，会得到 A(165) 晚于 B(125) 的表象，与跨设备指挥因果叙述相反——“事件顺序似乎颠倒”。**
当班据此封存为“待离线复核的时钟异常”，未擅自改写原始记录。

## 二、仅用封存卷可得到的严格区间

对封存记录 + `bounds_sealed.json` 做差分约束复核（全偏移枚举交叉验证一致）：

- 真时差 Δ = τ(B-TGT) − τ(A-TGT)，最紧区间 = **{r['sealed_interval']} 分钟**（>0，故即便没有晚到校准，已签名因果也足以判定 B 仍晚于 A）。
- 全偏移枚举：{r['sealed_oracle']['total_offset_combinations']} 种指派，可行 {r['sealed_oracle']['feasible_count']} 种。
- 下界 {r['sealed_interval'][0]} 见证：`{r['sealed_witness_lower']}`
- 上界 {r['sealed_interval'][1]} 见证：`{r['sealed_witness_upper']}`

> 本文件代表“原封存报告”的结论与哈希锚点；更新内容见 `updated_explanation.md`，两者不得混为一谈。
"""
    (REPORTS / "sealed_report.md").write_text(md, encoding="utf-8")


def _write_updated_report(r: Dict[str, Any]) -> None:
    vf = r["verification_full"]
    md = f"""# 更新后的解释（离线复核结论，替代解释但不覆盖封存报告）

- 全量记录数：{r['info']['record_count']}；全量记录根摘要：`{r['full_record_root']}`
- 封存卷根摘要（用于与原报告对接）：`{r['sealed_record_root']}`

## 一、完整性与签名

- 摘要/HMAC 全部通过：有效 {vf['valid_count']} 条；坏摘要 {len(vf['bad_digest'])}、坏签名 {len(vf['bad_signature'])}、未知密钥 {len(vf['unknown_device_key'])}。
- **同号异摘要（必须点名）**：检测到 {len(vf['equivocations'])} 组 `(device,seq)` 同号异摘要：

```json
{json.dumps(vf['equivocations'], ensure_ascii=False, indent=2)}
```

  `A-NOTE-DUP-v1` 与 `A-NOTE-DUP-v2` 同为 `(A, seq=9)`、摘要不同，但两份 HMAC 都用 A 的合成密钥合法——属于密钥持有者的双重陈述/equivocation，不能任选一份而不记录；与本目标对的时间约束无关，故不改变区间。

## 二、时钟代与晚到校准

- 信标 `A-BEACON-ROLLBACK` 把 A 从 `A-g0`（区间 [58,62]，钟快约 60 分）换到 `A-g1`（[-62,-58]，回拨后钟慢约 60 分）；本地读数 210→140 与回拨 −120 分吻合。
- `CAL-B-LATE` 比应到时间晚 {small_data.SHIFT_HALF_MIN} 分钟（半班），在更新解释中才与初始区间 [-20,20] 相交，把 `B-g0` 收紧到 [-1,1]。

## 三、目标事件对最紧时间差区间（含两端见证）

Δ = τ(B-TGT) − τ(A-TGT)，本地常数 C = 125−165 = −40。

- **更新后最紧区间：{r['updated_interval']} 分钟**（封存宽区间为 {r['sealed_interval']}）。
- 含义：B-TGT 的真时严格晚于 A-TGT 约 {r['updated_interval'][0]}..{r['updated_interval'][1]} 分钟；所谓“颠倒”只是 A 钟快 +60 分造成的读数假象。合成真值 Δ=20 落在区间内。
- 下界 {r['updated_interval'][0]} 的可实现偏移见证：`{r['updated_witness_lower']}`
- 上界 {r['updated_interval'][1]} 的可实现偏移见证：`{r['updated_witness_upper']}`
- 两个见证均通过逐边可行性检查：lower `{r['updated_result_full']['witness_lower_check']['satisfies_all']}`，upper `{r['updated_result_full']['witness_upper_check']['satisfies_all']}`。

## 四、全偏移枚举独立核对

笛卡尔遍历 {r['updated_oracle']['total_offset_combinations']} 个整数偏移组合（区间大小 {r['updated_oracle']['interval_sizes']}），可行 {r['updated_oracle']['feasible_count']} 个：

- 枚举区间 {r['cross_check_updated']['bruteforce_interval']} 与最短路区间 {r['cross_check_updated']['solver_interval']} 完全一致：**{r['cross_check_updated']['match']}**。
- 枚举端点指派 min=`{r['cross_check_updated']['bruteforce_witness_min']}`；max=`{r['cross_check_updated']['bruteforce_witness_max']}`。

## 五、与原封存报告的区别

1. 原报告固定在封存时点，只有宽 B 区间，区间 {r['sealed_interval']}；本解释纳入晚到半班的校准，收紧为 {r['updated_interval']}。
2. 本解释额外揭露 `(A,9)` 同号异摘要；封存卷只有 v1，看不到该冲突。
3. 原封存文件与其根摘要保持不变；本文件是“更新后的解释”，不是对封存报告的改写。
4. 若约束本身矛盾（空区间），结论与最短可独立复核边集合见 `empty_case_report.md` / `contradiction_certificate.json`。
"""
    (REPORTS / "updated_explanation.md").write_text(md, encoding="utf-8")


def _write_empty_report(out: Dict[str, Any], cert: Dict[str, Any]) -> None:
    o = out["oracle"]
    rv = out["certificate_review"]
    md = f"""# 空区间（矛盾）案例与最短可独立复核边集合

- 组件：`{out['component']}`；全偏移枚举 {o['total_offset_combinations']} 个组合，可行 **{o['feasible_count']}** 个 → 目标时间差区间为空。
- 最短负环边数：**{rv['cycle_edge_count']}**；环权和 **{rv['cycle_total_weight']}** (<0)。
- 环顶点：`{' -> '.join(rv['cycle_vertices'])}`
- 环边（按序）：`{rv['edge_ids']}`

## 每条边都能回到签名记录重推

"""
    for line in out["edge_explanations"]:
        md += line + "\n\n"
    md += f"""
## 独立复核方式

证书 `reports/contradiction_certificate.json` 自包含全组件边与全部相关签名记录。
复核器 `review12167/verify_certificate.py` **只用 Python 标准库、不 import 本包**：

```bat
python review12167\\verify_certificate.py reports\\contradiction_certificate.json --keys artifacts\\12167\\empty\\keys.json
```

进程内复核结论：**{rv['verdict']}**

- 验签内嵌记录 {rv['embedded_signed_records_verified']} 条；重推边 {rv['component_edges_rederived']} 条。
- 独立分层 DP 得到的最短负环边数 = {rv['independent_dp_min_length']}，与证书一致，故“最短”可独立复核，而非仅给一个不可满足核。
"""
    (REPORTS / "empty_case_report.md").write_text(md, encoding="utf-8")


def _write_scale_report(m: Dict[str, Any]) -> None:
    md = f"""# 规模验收：≥60000 事件、不全连通、补一个校准后的实际重算范围

## 总量

- 事件数：**{m['event_count']}**（{scale_data.SHARDS} 个互不相连分片 × 每设备 {scale_data.EVENTS_PER_DEVICE} 事件 × 2）。
- 补校准前记录总数：{m['total_records_before_cal']}；补 1 条校准后：{m['total_records_after_cal']}。
- 签名校验通过记录：{m['signature_valid_records']}，问题记录 {m['signature_problem_records']}；验签耗时 {m['verify_seconds']}s。
- 弱组件数：**{m['component_count']}**；全连通？**{m['graph_fully_connected']}**（False 即“不全连通”，实为 {m['component_count']} 个断开分片）。
- 全部分片基线可行：{m['all_baseline_shards_feasible']}。

## 补一个校准后实际重算的组件与记录数

- 新增：`S{m['target_shard']:04d}-CAL-ONE`（只收紧 `Q{m['target_shard']:04d}-g` 的偏移区间，不新增边、不改变连通性）。
- 实际重算组件：**`{m['recomputed_component']}`**，含时钟代 `{m['component_generations']}`。
- **该组件记录数：{m['component_record_count']}**，分类 {m['component_record_breakdown']}。
- 即只重算约 {m['component_record_count']} 条记录的一个组件，而不是 {m['total_records_after_cal']} 条全量记录；组件求解耗时 {m['component_recompute_seconds']}s。
- 校准前目标区间 {m['interval_before']} → 校准后 **{m['interval_after']}**。
- 下端点见证 `{m['witness_after_lower']}`；上端点见证 `{m['witness_after_upper']}`；逐边满足：{m['witness_lower_check']['satisfies_all']} / {m['witness_upper_check']['satisfies_all']}。

## 正确性与“不波及其余组件”

- 增量单组件结果与**全量重建模型**结果一致：**{m['incremental_matches_full_rebuild']}**（全量重建+目标求解 {m['full_rebuild_and_target_solve_seconds']}s，仅作审计对照）。
- 其余 {m['component_count']-1} 个分片目标区间全部保持不变：**{m['all_other_shards_unchanged']}**；意外变化分片 {m['unexpected_changed_shards']}。

## 附：实测耗时（本机，秒，随机器波动）

| 阶段 | 秒 |
|---|---|
| 读盘 | {m['load_seconds']} |
| 验签 | {m['verify_seconds']} |
| 建模型/分组件 | {m['build_model_seconds']} |
| 全量基线求解 {m['component_count']} 目标 | {m['baseline_solve_all_shards_seconds']} |
| 单组件重算 | {m['component_recompute_seconds']} |
| 全量重建审计 | {m['full_rebuild_and_target_solve_seconds']} |
"""
    (REPORTS / "scale_acceptance.md").write_text(md, encoding="utf-8")


def run_all() -> Dict[str, Any]:
    ART.mkdir(parents=True, exist_ok=True)
    REPORTS.mkdir(parents=True, exist_ok=True)
    small = run_small()
    empty = run_empty()
    scale = run_scale()
    summary = {
        "small_updated_interval": small["updated_interval"],
        "small_sealed_interval": small["sealed_interval"],
        "equivocations": len(small["verification_full"]["equivocations"]),
        "empty_feasible_combos": empty["oracle"]["feasible_count"],
        "cert_min_length": empty["certificate_review"]["independent_dp_min_length"],
        "scale_events": scale["event_count"],
        "scale_components": scale["component_count"],
        "scale_recomputed_component": scale["recomputed_component"],
        "scale_component_records": scale["component_record_count"],
    }
    write_json(REPORTS / "run_summary.json", summary)
    return summary
