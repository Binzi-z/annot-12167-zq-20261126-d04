#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""最短矛盾边集合证书的独立复核器（只使用 Python 标准库）。

本脚本刻意不 import review12167 包内任何模块，可单独复制到任意
装有 Python 3.8+ 的 Windows 机器上离线运行：

    python verify_certificate.py certificate.json --keys keys.json

复核内容（任一项失败即以非零码退出）：
  1. 证书内嵌每条记录的 SHA-256 摘要与 HMAC-SHA256 签名；
  2. 不相信证书填写的边权：从签名载荷与事件读数重新推导全部边权/端点；
     区间锚点边由 initial_bounds 与校准记录重新取交推导；
  3. edge_ids 按序首尾闭合，权和严格 < 0（故不存在可行整数偏移指派）；
  4. 用独立实现的“精确 k 边”分层 DP 复核：全组件中负环的最小边数
     恰为证书声称的 shortest_length，且给出的环达到该长度。

退出码：0 通过；1 证书/复核失败；2 用法或文件错误。
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

DOMAIN_PREFIX = b"R12167-EVIDENCE-v1\n"
INF = 10**30

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
except Exception:
    pass


def canonical_bytes(obj: Any) -> bytes:
    return json.dumps(obj, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":")).encode("utf-8")


def core_object(env: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "rec_id": env["rec_id"], "device": env["device"], "seq": env["seq"],
        "received_at": env.get("received_at"), "payload": env["payload"],
    }


def compute_digest(env: Dict[str, Any]) -> str:
    data = DOMAIN_PREFIX + canonical_bytes(core_object(env))
    return "sha256:" + hashlib.sha256(data).hexdigest()


def compute_sig(env: Dict[str, Any], key: str) -> str:
    digest = compute_digest(env)
    return "hmac-sha256:" + hmac.new(
        key.encode("utf-8"), digest.encode("ascii"), hashlib.sha256
    ).hexdigest()


class CertError(Exception):
    pass


def load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def verify_signed_records(
    records: Dict[str, Dict[str, Any]], keys: Dict[str, str]
) -> List[str]:
    """返回通过校验的记录 id 列表；任何失败抛 CertError。"""
    ok: List[str] = []
    for rid, env in records.items():
        if not isinstance(env, dict) or env.get("rec_id") != rid:
            raise CertError(f"记录键与 rec_id 不一致: {rid}")
        if not hmac.compare_digest(str(env.get("digest", "")), compute_digest(env)):
            raise CertError(f"摘要不匹配，记录可能被篡改: {rid}")
        key = keys.get(env["device"])
        if key is None:
            raise CertError(f"设备 {env['device']} 无合成密钥，无法验签: {rid}")
        if not hmac.compare_digest(str(env.get("sig", "")), compute_sig(env, key)):
            raise CertError(f"HMAC 签名校验失败: {rid}")
        ok.append(rid)
    return ok


def ts_gen(records: Dict[str, Dict[str, Any]], rid: str) -> Tuple[int, str]:
    env = records.get(rid)
    if env is None:
        raise CertError(f"缺少内嵌事件记录: {rid}")
    p = env["payload"]
    return int(p["local_ts"]), str(p["gen"])


def effective_bounds(cert: Dict[str, Any],
                     records: Dict[str, Dict[str, Any]]
                     ) -> Dict[str, Tuple[int, int]]:
    initial = cert["initial_bounds"]
    bounds: Dict[str, List[int]] = {g: [int(v[0]), int(v[1])] for g, v in initial.items()}
    for env in records.values():
        p = env.get("payload", {})
        if p.get("kind") != "calibration":
            continue
        g = str(p["gen"]); lo = int(p["offset_interval"][0]); hi = int(p["offset_interval"][1])
        if g not in bounds:
            bounds[g] = [lo, hi]
        else:
            bounds[g][0] = max(bounds[g][0], lo)
            bounds[g][1] = min(bounds[g][1], hi)
    return {g: (v[0], v[1]) for g, v in bounds.items()}


def derive_edge_weight(edge: Dict[str, Any],
                       records: Dict[str, Dict[str, Any]],
                       bounds: Dict[str, Tuple[int, int]],
                       anchor: str) -> Tuple[str, str, int, str]:
    """独立重推一条边的 (u, v, w)，并与证书声明核对；不一致即报错。"""
    origin = edge["origin"]
    det = edge.get("detail", {})

    if origin == "order":
        s1, g1 = ts_gen(records, det["prev_event"])
        s2, g2 = ts_gen(records, det["next_event"])
        w = s2 - s1
        why = f"order: {det['prev_event']}->{det['next_event']} {s2}-{s1}={w}"
        u, v = g1, g2

    elif origin in ("causal-lower", "causal-upper"):
        rid = edge["source_id"]
        cenvelope = records.get(rid)
        if cenvelope is None:
            raise CertError(f"边 {edge['eid']} 缺少内嵌因果记录 {rid}")
        cp = cenvelope["payload"]
        fid, tid = cp["from_event"], cp["to_event"]
        s1, _ = ts_gen(records, fid)
        s2, g_to = ts_gen(records, tid)
        _, g_from = ts_gen(records, fid)
        c = s2 - s1
        a, b = int(cp["latency"][0]), int(cp["latency"][1])
        if origin == "causal-lower":
            u, v, w = g_from, g_to, c - a
            why = f"causal-lower {rid}: C={c}, a={a}, C-a={w}"
        else:
            u, v, w = g_to, g_from, b - c
            why = f"causal-upper {rid}: C={c}, b={b}, b-C={w}"

    elif origin == "bound-upper":
        g = det["gen"]; u, v = anchor, g
        if g not in bounds:
            raise CertError(f"锚点边引用未知时钟代 {g}")
        w = bounds[g][1]
        why = f"bound-upper {g}: U={w}（初始区间与校准取交）"

    elif origin == "bound-lower":
        g = det["gen"]; u, v = g, anchor
        if g not in bounds:
            raise CertError(f"锚点边引用未知时钟代 {g}")
        w = -bounds[g][0]
        why = f"bound-lower {g}: -L=-{bounds[g][0]}={w}"

    else:
        raise CertError(f"未知边来源类型: {origin}")

    if edge["u"] != u or edge["v"] != v or int(edge["w"]) != w:
        raise CertError(
            f"边 {edge['eid']} 与签名证据重推结果不符: "
            f"证书=({edge['u']}->{edge['v']}, w={edge['w']})，重推=({u}->{v}, w={w})"
        )
    return u, v, w, why


def cert_anchor(cert: Dict[str, Any]) -> str:
    return str(cert.get("anchor", "__anchor__"))


def min_negative_cycle_length(vertices: List[str],
                              edges: List[Tuple[str, str, int]]) -> Tuple[int, int]:
    """独立的精确 k 边分层 DP，返回 (最短负环边数, 该 k 下某个负对角值)。"""
    idx = {v: i for i, v in enumerate(vertices)}
    n = len(vertices)
    prev = [[INF] * n for _ in range(n)]
    for i in range(n):
        prev[i][i] = 0
    found: Optional[Tuple[int, int]] = None
    for k in range(1, n + 1):
        cur = [[INF] * n for _ in range(n)]
        for u, v, w in edges:
            ui, vi = idx[u], idx[v]
            for i in range(n):
                if prev[i][ui] < INF:
                    cand = prev[i][ui] + w
                    if cand < cur[i][vi]:
                        cur[i][vi] = cand
        for i in range(n):
            if cur[i][i] < 0:
                found = (k, cur[i][i])
                break
        prev = cur
        if found:
            return found
    raise CertError("分层 DP 未发现负环：证书不成立")


def verify(cert_path: Path, keys_path: Path) -> Dict[str, Any]:
    cert = load_json(cert_path)
    keys = load_json(keys_path)
    if cert.get("schema") != "r12167-negative-cycle-cert-v1":
        raise CertError(f"证书 schema 不符: {cert.get('schema')}")

    records = cert.get("records", {})
    signed_ok = verify_signed_records(records, keys)
    bounds = effective_bounds(cert, records)
    anchor = cert_anchor(cert)

    # 1) 重推全组件边
    verified_edges: List[Tuple[str, str, int]] = []
    explanations: List[str] = []
    for edge in cert["component_edges"]:
        u, v, w, why = derive_edge_weight(edge, records, bounds, anchor)
        verified_edges.append((u, v, w))
        explanations.append(f"  [{edge['eid']}] {u} -> {v} w={w}  {why}")

    # 2) 复核声称的环按序闭合且权和为负
    by_id = {e["eid"]: e for e in cert["component_edges"]}
    ids = cert["edge_ids"]
    if not ids:
        raise CertError("证书 edge_ids 为空")
    start = cert["start_vertex"]
    cur = start
    total = 0
    for eid in ids:
        e = by_id.get(eid)
        if e is None:
            raise CertError(f"环边 {eid} 不在 component_edges 中")
        if e["u"] != cur:
            raise CertError(f"环不衔接：{eid} 的起点 {e['u']} != 当前 {cur}")
        cur = e["v"]; total += int(e["w"])
    if cur != start:
        raise CertError(f"环未闭合：终点 {cur} != 起点 {start}")
    if total >= 0:
        raise CertError(f"环权和 {total} >= 0，不构成矛盾")
    if total != int(cert["total_weight"]):
        raise CertError("证书 total_weight 与重算不符")
    if len(ids) != int(cert["shortest_length"]):
        raise CertError("edge_ids 条数与 shortest_length 不符")

    # 3) 独立 DP 复核“最短边数”
    k, diag = min_negative_cycle_length(cert["vertices"], verified_edges)
    if k != int(cert["shortest_length"]):
        raise CertError(
            f"最短性不成立：独立 DP 得最短负环为 {k} 条边，"
            f"证书给的是 {cert['shortest_length']} 条"
        )

    return {
        "certificate": str(cert_path),
        "case_name": cert.get("case_name"),
        "component": cert.get("component"),
        "embedded_signed_records_verified": len(signed_ok),
        "component_edges_rederived": len(verified_edges),
        "cycle_edge_count": len(ids),
        "cycle_total_weight": total,
        "independent_dp_min_length": k,
        "dp_negative_diagonal_example": diag,
        "cycle_vertices": cert["cycle_vertices"],
        "edge_ids": ids,
        "edge_explanations": explanations,
        "verdict": "VERIFIED: 矛盾成立，且该边集合为最短（按边数）可独立复核证书",
    }


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        description="12167 最短矛盾边集合证书的独立离线复核器（标准库）")
    ap.add_argument("certificate", type=Path, help="negative_certificate.json 路径")
    ap.add_argument("--keys", type=Path, required=True, help="keys.json（合成 HMAC 密钥）")
    args = ap.parse_args(argv)
    try:
        result = verify(args.certificate, args.keys)
    except CertError as exc:
        print(f"[复核失败] {exc}")
        return 1
    except (OSError, json.JSONDecodeError, KeyError) as exc:
        print(f"[用法/文件错误] {type(exc).__name__}: {exc}")
        return 2
    except Exception as exc:  # noqa: BLE001 - CLI 兜底：任何意外都非零退出并给 traceback
        import traceback
        print("[复核器异常] 独立复核脚本自身或输入出现意外错误：")
        traceback.print_exc()
        print(f"{type(exc).__name__}: {exc}")
        return 2
    print("=" * 72)
    print("12167 矛盾证书独立复核")
    print("=" * 72)
    print(f"用例           : {result['case_name']}  组件 {result['component']}")
    print(f"验签内嵌记录   : {result['embedded_signed_records_verified']} 条全部通过")
    print(f"重推组件边     : {result['component_edges_rederived']} 条")
    print(f"环顶点         : {' -> '.join(result['cycle_vertices'])}")
    print(f"环边（{result['cycle_edge_count']} 条）     : {result['edge_ids']}")
    print(f"环权和         : {result['cycle_total_weight']} (<0)")
    print(f"独立DP最短边数 : {result['independent_dp_min_length']} "
          f"(负对角样例 {result['dp_negative_diagonal_example']})")
    print("-" * 72)
    for line in result["edge_explanations"]:
        print(line)
    print("-" * 72)
    print(result["verdict"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
