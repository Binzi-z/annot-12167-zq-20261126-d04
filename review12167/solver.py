"""差分约束求解：Bellman-Ford 最短路、端点偏移见证、最短负环证书。

边约定：Edge(u,v,w) 表示 o_v - o_u <= w。
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence, Tuple

from .constraints import ANCHOR, CaseModel, Edge

INF = 10**30


class NegativeCycle(Exception):
    def __init__(self, relax_edges: Optional[List[Edge]] = None):
        super().__init__("差分约束图存在负环（偏移区间不可满足）")
        self.relax_edges = relax_edges or []


@dataclass
class PreparedComponent:
    cid: str
    vertices: List[str]          # 末位固定为 ANCHOR
    index: Dict[str, int]
    edges: List[Edge]             # 含两条/变量的锚点边

    def idx(self, v: str) -> int:
        return self.index[v]


def prepare_component(model: CaseModel, cid: str) -> PreparedComponent:
    gens = list(model.components[cid])
    vertices = sorted(gens) + [ANCHOR]
    index = {v: i for i, v in enumerate(vertices)}
    # 优先使用建模时分好的组件边桶；缺省回退到全量过滤（保持兼容）。
    bucket = getattr(model, "edges_by_component", None) or {}
    if cid in bucket:
        edges: List[Edge] = list(bucket[cid])
    else:
        edges = [e for e in model.edges if e.u in index and e.v in index]
    for g in sorted(gens):
        b = model.bounds.get(g)
        if b is None:
            raise KeyError(
                f"时钟代 {g} 出现在组件 {cid} 中，却没有整数闭区间 bounds；"
                f"本复核要求每个时钟代都给出 [L,U]")
        edges.append(Edge(
            eid=f"BOUND-HI::{g}", u=ANCHOR, v=g, w=b.hi, origin="bound-upper",
            source_id=None,
            detail={"gen": g, "bound_side": "hi", "value": b.hi,
                    "hi_sources": list(b.hi_sources),
                    "calibration_ids": list(b.calibration_ids)},
        ))
        edges.append(Edge(
            eid=f"BOUND-LO::{g}", u=g, v=ANCHOR, w=-b.lo, origin="bound-lower",
            source_id=None,
            detail={"gen": g, "bound_side": "lo", "value": b.lo,
                    "lo_sources": list(b.lo_sources),
                    "calibration_ids": list(b.calibration_ids)},
        ))
    return PreparedComponent(cid=cid, vertices=vertices, index=index, edges=edges)


def bellman_ford(pc: PreparedComponent, source: str) -> List[int]:
    """从 source 出发的最短路；存在负环时抛 NegativeCycle。"""
    n = len(pc.vertices)
    s = pc.index[source]
    dist = [INF] * n
    dist[s] = 0
    for _ in range(n - 1):
        changed = False
        for e in pc.edges:
            u, v, w = pc.index[e.u], pc.index[e.v], e.w
            if dist[u] != INF and dist[u] + w < dist[v]:
                dist[v] = dist[u] + w
                changed = True
        if not changed:
            break
    relax: List[Edge] = []
    for e in pc.edges:
        u, v, w = pc.index[e.u], pc.index[e.v], e.w
        if dist[u] != INF and dist[u] + w < dist[v]:
            relax.append(e)
    if relax:
        raise NegativeCycle(relax)
    return dist


def shortest_negative_cycle(pc: PreparedComponent) -> Dict[str, Any]:
    """求边数（条数）最少的负环，并重建可复核的有序边集合。

    精确 k 边 DP：D_k[i][j] = i 到 j 恰走 k 条边的最小权。
    首个出现 D_k[i][i] < 0 的 k 即最短负环边数。
    """
    n = len(pc.vertices)
    m = len(pc.edges)
    if m == 0:
        raise ValueError("组件没有边，不可能矛盾")

    prev: List[List[int]] = [[INF] * n for _ in range(n)]
    for i in range(n):
        prev[i][i] = 0

    pred_layers: List[List[List[int]]] = []
    edge_layers: List[List[List[Optional[str]]]] = []
    found_k: Optional[int] = None
    found_start: Optional[int] = None

    for k in range(1, n + 1):
        cur = [[INF] * n for _ in range(n)]
        pred = [[-1] * n for _ in range(n)]
        chosen: List[List[Optional[str]]] = [[None] * n for _ in range(n)]
        for e in pc.edges:
            u, v, w = pc.index[e.u], pc.index[e.v], e.w
            for i in range(n):
                if prev[i][u] >= INF:
                    continue
                cand = prev[i][u] + w
                if cand < cur[i][v]:
                    cur[i][v] = cand
                    pred[i][v] = u
                    chosen[i][v] = e.eid
        pred_layers.append(pred)
        edge_layers.append(chosen)
        for i in range(n):
            if cur[i][i] < 0:
                found_k = k
                found_start = i
                break
        prev = cur
        if found_k is not None:
            break

    if found_k is None or found_start is None:
        raise ValueError("分层 DP 未发现负环；模型实际可行")

    # ---- 反向重建 ----
    eids_rev: List[str] = []
    j = found_start
    i = found_start
    for kk in range(found_k, 0, -1):
        eid = edge_layers[kk - 1][i][j]
        p = pred_layers[kk - 1][i][j]
        if eid is None or p < 0:
            raise RuntimeError("负环重建失败")
        eids_rev.append(eid)
        j = p
    if j != found_start:
        raise RuntimeError("重建出的边未闭合")
    eids = list(reversed(eids_rev))

    by_id = {e.eid: e for e in pc.edges}
    ordered_edges: List[Edge] = []
    cur_v = pc.vertices[found_start]
    cycle_vertices = [cur_v]
    total = 0
    for eid in eids:
        e = by_id[eid]
        if e.u != cur_v:
            raise RuntimeError(f"证书边不衔接：期望从 {cur_v} 出发，得到 {e.u}->{e.v}")
        ordered_edges.append(e)
        total += e.w
        cur_v = e.v
        cycle_vertices.append(cur_v)
    if cur_v != pc.vertices[found_start]:
        raise RuntimeError("证书环未回到起点")
    if total >= 0:
        raise RuntimeError(f"重建环权和非负：{total}")

    return {
        "length": found_k,
        "total_weight": total,
        "start_vertex": pc.vertices[found_start],
        "cycle_vertices": cycle_vertices,
        "edge_ids": eids,
        "edges": ordered_edges,
    }


@dataclass
class TargetRequest:
    event1: str   # 参考事件 e1
    event2: str   # 目标事件 e2；求 Delta = tau_e2 - tau_e1


def solve_target(
    model: CaseModel, req: TargetRequest
) -> Dict[str, Any]:
    """计算目标对最紧真时差区间及两端可实现偏移见证。"""
    env1 = model.events[req.event1]
    env2 = model.events[req.event2]
    s1, g1 = int(env1["payload"]["local_ts"]), str(env1["payload"]["gen"])
    s2, g2 = int(env2["payload"]["local_ts"]), str(env2["payload"]["gen"])
    c = s2 - s1
    cid = model.gen_to_component[g1]
    if model.gen_to_component[g2] != cid:
        # 理论上不会发生：目标对若没有约束相连，它们属于不同组件，
        # 此时时差只有各自区间推出的松散界。合成用例中显式拒绝歧义。
        return {
            "feasible": True, "connected": False,
            "message": "两个目标事件属于无约束连接的不同组件，无法给有限最紧差区间",
        }
    pc = prepare_component(model, cid)

    # 先从锚点跑一次：可行性 + 负环检测
    try:
        bellman_ford(pc, ANCHOR)
    except NegativeCycle:
        snc = shortest_negative_cycle(pc)
        return {
            "feasible": False, "connected": True, "component": cid,
            "C": c, "gen1": g1, "gen2": g2,
            "negative_cycle": _cycle_jsonable(snc),
        }

    d1 = bellman_ford(pc, g1)
    d2 = bellman_ford(pc, g2)
    z = pc.index[ANCHOR]

    d_g1_to_g2 = d1[pc.index[g2]]
    d_g2_to_g1 = d2[pc.index[g1]]
    lo = c - d_g1_to_g2
    hi = c + d_g2_to_g1

    witness_lo = {
        v: d1[pc.index[v]] - d1[z] for v in pc.vertices if v != ANCHOR
    }
    witness_hi = {
        v: d2[pc.index[v]] - d2[z] for v in pc.vertices if v != ANCHOR
    }
    check_lo = verify_witness(model, cid, witness_lo)
    check_hi = verify_witness(model, cid, witness_hi)
    delta_lo_value = c + witness_lo[g1] - witness_lo[g2]
    delta_hi_value = c + witness_hi[g1] - witness_hi[g2]

    return {
        "feasible": True,
        "connected": True,
        "component": cid,
        "event1": req.event1,
        "event2": req.event2,
        "local_ts1": s1,
        "local_ts2": s2,
        "gen1": g1,
        "gen2": g2,
        "C": c,
        "delta_interval": [lo, hi],
        "D_g1_to_g2": d_g1_to_g2,
        "D_g2_to_g1": d_g2_to_g1,
        "witness_lower": witness_lo,
        "witness_upper": witness_hi,
        "witness_lower_delta": delta_lo_value,
        "witness_upper_delta": delta_hi_value,
        "witness_lower_check": check_lo,
        "witness_upper_check": check_hi,
    }


def verify_witness(
    model: CaseModel, cid: str, offsets: Dict[str, int]
) -> Dict[str, Any]:
    """独立检查一个整数偏移指派是否满足该组件全部域与差分边。"""
    pc = prepare_component(model, cid)
    violations: List[str] = []
    for g in model.components[cid]:
        b = model.bounds[g]
        if not (b.lo <= offsets[g] <= b.hi):
            violations.append(f"域越界 {g}={offsets[g]} not in [{b.lo},{b.hi}]")
        if not isinstance(offsets[g], int):
            violations.append(f"非整数 {g}={offsets[g]!r}")
    for e in pc.edges:
        if e.u == ANCHOR or e.v == ANCHOR:
            continue  # 锚点边已由域检查覆盖
        lhs = offsets[e.v] - offsets[e.u]
        if lhs > e.w:
            violations.append(
                f"边 {e.eid} 违反: o_{e.v}-o_{e.u}={lhs} > {e.w} ({e.origin})"
            )
    return {"satisfies_all": not violations, "violations": violations,
            "checked_edges": sum(
                1 for e in pc.edges if e.u != ANCHOR and e.v != ANCHOR)}


def _cycle_jsonable(snc: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "length": snc["length"],
        "total_weight": snc["total_weight"],
        "start_vertex": snc["start_vertex"],
        "cycle_vertices": snc["cycle_vertices"],
        "edge_ids": snc["edge_ids"],
        "edges": [e.to_dict() for e in snc["edges"]],
    }


def find_contradiction_certificate(model: CaseModel) -> Optional[Dict[str, Any]]:
    """扫描所有组件，返回第一个矛盾组件的最短负环（JSON 友好）。"""
    for cid in sorted(model.components):
        pc = prepare_component(model, cid)
        try:
            bellman_ford(pc, ANCHOR)
        except NegativeCycle:
            snc = shortest_negative_cycle(pc)
            return {"component": cid, **_cycle_jsonable(snc)}
    return None
