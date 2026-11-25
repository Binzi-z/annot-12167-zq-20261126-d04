"""构造自包含的最短负环证书（内嵌全组件边与相关签名记录）。

证书包含：
- component_edges: 该组件参与求解的全部差分边（含锚点区间边）；
- edge_ids: 最短负环按序使用的边；
- records:  去重内嵌的全部相关签名封装记录；
- initial_bounds + 校准来源：使区间锚点边也能被独立重推。
任何第三方仅凭本 JSON、keys.json 和 verify_certificate.py（纯标准库、
不 import 本包）即可复核签名、边权、闭合、负权和与“最短边数”。
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from . import CERT_SCHEMA_VERSION
from .constraints import ANCHOR, CaseModel
from .solver import prepare_component


def build_negative_certificate(
    model: CaseModel,
    cert_info: Dict[str, Any],
    records: List[Dict[str, Any]],
    initial_bounds: Dict[str, List[int]],
    *,
    case_name: str,
    target: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    by_id = {r["rec_id"]: r for r in records}
    cid = cert_info["component"]
    pc = prepare_component(model, cid)

    needed: List[str] = []

    def need(rid: Optional[str]) -> None:
        if rid and rid != "initial_bounds" and rid in by_id and rid not in needed:
            needed.append(rid)

    component_edges: List[Dict[str, Any]] = []
    for e in pc.edges:
        component_edges.append(e.to_dict())
        need(e.source_id)
        det = e.detail or {}
        for key in ("prev_event", "next_event", "from_event", "to_event"):
            need(det.get(key))
        for x in det.get("calibration_ids", []) or []:
            need(x)
        for x in (det.get("lo_sources", []) or []) + (det.get("hi_sources", []) or []):
            need(x)

    # 环上边的来源再保一道
    for e in cert_info["edges"]:
        need(e.source_id)
        for key in ("prev_event", "next_event", "from_event", "to_event"):
            need((e.detail or {}).get(key))

    embedded_records = {rid: by_id[rid] for rid in needed if rid in by_id}

    bound_provenance: Dict[str, Any] = {}
    for g in model.components[cid]:
        b = model.bounds[g]
        bound_provenance[g] = {
            "effective": [b.lo, b.hi],
            "initial": [b.initial_lo, b.initial_hi],
            "lo_sources": b.lo_sources,
            "hi_sources": b.hi_sources,
            "calibration_ids": b.calibration_ids,
        }

    return {
        "schema": CERT_SCHEMA_VERSION,
        "case_name": case_name,
        "anchor": ANCHOR,
        "target": target,
        "component": cid,
        "vertices": pc.vertices,
        "shortest_length": cert_info["length"],
        "total_weight": cert_info["total_weight"],
        "start_vertex": cert_info["start_vertex"],
        "cycle_vertices": cert_info["cycle_vertices"],
        "edge_ids": cert_info["edge_ids"],
        "cycle_edges": [e.to_dict() for e in cert_info["edges"]],
        "component_edges": component_edges,
        "initial_bounds": initial_bounds,
        "bound_provenance": bound_provenance,
        "records": embedded_records,
        "review_instructions": (
            "python review12167/verify_certificate.py <本证书.json> "
            "--keys <用例目录>/keys.json"
        ),
    }
