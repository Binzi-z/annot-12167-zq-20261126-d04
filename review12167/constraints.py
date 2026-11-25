"""把已校验的合成取证记录归约为差分约束，并划分弱连通组件。

约定
----
每个时钟代 g 有一个整数偏移变量 o_g（本地读数 = 真时 + o_g）。
事件 e 的本地读数为 s_e、时钟代为 g(e)，则真时 tau_e = s_e - o_{g(e)}。

任意形如  a <= tau_f - tau_e <= b  的约束归约为两条差分约束：
    o_gf - o_ge <= (s_f - s_e) - a      （边 ge -> gf，权 C-a）
    o_ge - o_gf <= b - (s_f - s_e)      （边 gf -> ge，权 b-C）

同设备相邻事件按序号给出 tau_next >= tau_prev，同样归约为一条边。
闭区间 L_g <= o_g <= U_g 是一元域；求解时为每个弱组件放一个局部锚点 z：
    z -> g 权 U_g （o_g - o_z <= U_g）
    g -> z 权 -L_g（o_z - o_g <= -L_g），并归一化 o_z=0。
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

ANCHOR = "__anchor__"


@dataclass
class Edge:
    eid: str
    u: str
    v: str
    w: int
    origin: str                 # order | causal-lower | causal-upper
    source_id: Optional[str]    # 主要来源记录 rec_id
    detail: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "eid": self.eid, "u": self.u, "v": self.v, "w": self.w,
            "origin": self.origin, "source_id": self.source_id,
            "detail": self.detail,
        }


class DSU:
    def __init__(self) -> None:
        self.parent: Dict[str, str] = {}

    def add(self, x: str) -> None:
        if x not in self.parent:
            self.parent[x] = x

    def find(self, x: str) -> str:
        self.add(x)
        root = x
        while self.parent[root] != root:
            root = self.parent[root]
        while self.parent[x] != x:
            nxt = self.parent[x]
            self.parent[x] = root
            x = nxt
        return root

    def union(self, a: str, b: str) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[rb] = ra


@dataclass
class Bound:
    lo: int
    hi: int
    initial_lo: int
    initial_hi: int
    lo_sources: List[str] = field(default_factory=list)
    hi_sources: List[str] = field(default_factory=list)
    calibration_ids: List[str] = field(default_factory=list)

    def as_list(self) -> List[int]:
        return [self.lo, self.hi]


@dataclass
class CaseModel:
    events: Dict[str, Dict[str, Any]]
    edges: List[Edge]
    bounds: Dict[str, Bound]
    dsu: DSU
    components: Dict[str, List[str]]
    record_primary_gen: Dict[str, str]
    gen_to_component: Dict[str, str] = field(default_factory=dict)
    edges_by_component: Dict[str, List[Edge]] = field(default_factory=dict)

    def component_of_gen(self, gen: str) -> str:
        return self.gen_to_component[gen]


def _event_time_gen(env: Dict[str, Any]) -> Tuple[int, str]:
    p = env["payload"]
    return int(p["local_ts"]), str(p["gen"])


def build_model(
    records: List[Dict[str, Any]],
    initial_bounds: Dict[str, List[int]],
) -> CaseModel:
    """从一组（已决定是否包含晚到校准的）记录构造模型。

    initial_bounds: {gen: [L, U]} 勘验初始整数闭区间。
    记录中的 calibration 会与初始区间相交并收紧边界。
    """
    events: Dict[str, Dict[str, Any]] = {}
    calibrations: List[Dict[str, Any]] = []
    for env in records:
        kind = env.get("payload", {}).get("kind")
        if kind == "event":
            events[env["rec_id"]] = env
        elif kind == "calibration":
            calibrations.append(env)

    bounds: Dict[str, Bound] = {}
    for gen, lu in initial_bounds.items():
        lo, hi = int(lu[0]), int(lu[1])
        bounds[gen] = Bound(
            lo=lo, hi=hi, initial_lo=lo, initial_hi=hi,
            lo_sources=["initial_bounds"], hi_sources=["initial_bounds"],
        )

    # 应用校准（相交），保留边界来源
    for cal in calibrations:
        p = cal["payload"]
        gen = str(p["gen"])
        lo, hi = int(p["offset_interval"][0]), int(p["offset_interval"][1])
        b = bounds.get(gen)
        if b is None:
            b = Bound(lo=lo, hi=hi, initial_lo=lo, initial_hi=hi,
                       lo_sources=[cal["rec_id"]], hi_sources=[cal["rec_id"]])
            bounds[gen] = b
        else:
            if lo > b.lo:
                b.lo = lo
                b.lo_sources = [cal["rec_id"]]
            elif lo == b.lo:
                b.lo_sources.append(cal["rec_id"])
            if hi < b.hi:
                b.hi = hi
                b.hi_sources = [cal["rec_id"]]
            elif hi == b.hi:
                b.hi_sources.append(cal["rec_id"])
        b.calibration_ids.append(cal["rec_id"])

    dsu = DSU()
    for gen in bounds:
        dsu.add(gen)

    edges: List[Edge] = []
    edge_no = 0

    def new_eid() -> str:
        nonlocal edge_no
        edge_no += 1
        return f"E{edge_no:04d}"

    # ---- 同设备相邻事件的序号顺序约束 ----
    by_device: Dict[str, List[Dict[str, Any]]] = {}
    for env in events.values():
        by_device.setdefault(env["device"], []).append(env)
    for dev_events in by_device.values():
        dev_events.sort(key=lambda e: int(e["seq"]))
        for prev_env, next_env in zip(dev_events, dev_events[1:]):
            s1, g1 = _event_time_gen(prev_env)
            s2, g2 = _event_time_gen(next_env)
            dsu.add(g1); dsu.add(g2); dsu.union(g1, g2)
            edges.append(Edge(
                eid=new_eid(), u=g1, v=g2, w=s2 - s1, origin="order",
                source_id=next_env["rec_id"],
                detail={
                    "prev_event": prev_env["rec_id"],
                    "next_event": next_env["rec_id"],
                    "formula": "w = local_ts(next) - local_ts(prev)  [tau_next >= tau_prev]",
                },
            ))

    # ---- 跨设备已签名因果关系 ----
    for env in records:
        p = env.get("payload", {})
        if p.get("kind") != "causal":
            continue
        from_id, to_id = p["from_event"], p["to_event"]
        if from_id not in events or to_id not in events:
            raise ValueError(f"因果记录 {env['rec_id']} 引用了不存在的事件 {from_id}->{to_id}")
        s1, g1 = _event_time_gen(events[from_id])
        s2, g2 = _event_time_gen(events[to_id])
        a = int(p["latency"][0])
        bnd = int(p["latency"][1])
        c = s2 - s1
        dsu.add(g1); dsu.add(g2); dsu.union(g1, g2)
        edges.append(Edge(
            eid=new_eid(), u=g1, v=g2, w=c - a, origin="causal-lower",
            source_id=env["rec_id"],
            detail={
                "from_event": from_id, "to_event": to_id,
                "s_from": s1, "s_to": s2, "C": c, "lower_latency": a,
                "formula": f"w = C - a = {c} - {a} = {c - a}  [a <= tau_to-tau_from]",
            },
        ))
        edges.append(Edge(
            eid=new_eid(), u=g2, v=g1, w=bnd - c, origin="causal-upper",
            source_id=env["rec_id"],
            detail={
                "from_event": from_id, "to_event": to_id,
                "s_from": s1, "s_to": s2, "C": c, "upper_latency": bnd,
                "formula": f"w = b - C = {bnd} - ({c}) = {bnd - c}  [tau_to-tau_from <= b]",
            },
        ))

    # ---- 组件索引 ----
    comps: Dict[str, List[str]] = {}
    all_gens = set(bounds.keys())
    for e in edges:
        all_gens.add(e.u); all_gens.add(e.v)
    for gen in all_gens:
        dsu.add(gen)
    for gen in sorted(all_gens):
        root = dsu.find(gen)
        comps.setdefault(root, []).append(gen)
    components = {cid: sorted(gens) for cid, gens in sorted(comps.items())}
    # 用稳定的 C0.. 编号替换 DSU root
    root_to_cid = {root: f"C{i}" for i, root in enumerate(sorted(components.keys()))}
    self_components: Dict[str, List[str]] = {}
    gen_to_cid: Dict[str, str] = {}
    for root, gens in components.items():
        cid = root_to_cid[root]
        self_components[cid] = gens
        for g in gens:
            gen_to_cid[g] = cid

    # ---- 每条记录的主属组件（用于“重算记录数”度量）----
    record_primary_gen: Dict[str, str] = {}
    for env in records:
        p = env.get("payload", {})
        kind = p.get("kind")
        gen: Optional[str] = None
        if kind == "event":
            gen = str(p["gen"])
        elif kind == "calibration":
            gen = str(p["gen"])
        elif kind == "beacon":
            gen = str(p.get("new_gen") or p.get("old_gen"))
        elif kind == "note":
            gen = str(p.get("gen")) if p.get("gen") else None
        elif kind == "causal":
            fid = p.get("from_event")
            if fid in events:
                gen = str(events[fid]["payload"]["gen"])
        if gen is not None:
            record_primary_gen[env["rec_id"]] = gen

    # 边按组件分桶（一条边的两端必在同一 DSU 组件），供求解器 O(组件边数) 取用，
    # 避免规模案例下每个目标都全量扫描数万条边。
    edges_by_component: Dict[str, List[Edge]] = {cid: [] for cid in self_components}
    for e in edges:
        cid_e = gen_to_cid.get(e.u)
        if cid_e is not None:
            edges_by_component[cid_e].append(e)

    model = CaseModel(
        events=events, edges=edges, bounds=bounds, dsu=dsu,
        components=self_components, record_primary_gen=record_primary_gen,
        gen_to_component=gen_to_cid, edges_by_component=edges_by_component,
    )
    return model


def component_records(model: CaseModel, records: List[Dict[str, Any]], cid: str) -> List[str]:
    """返回主属该组件的全部记录 rec_id（唯一归属，便于精确计数）。"""
    gens = set(model.components[cid])
    out: List[str] = []
    for env in records:
        gen = model.record_primary_gen.get(env["rec_id"])
        if gen is not None and gen in gens:
            out.append(env["rec_id"])
    return out
