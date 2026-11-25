"""证据记录层：规范化摘要、HMAC 签名、封装/校验、同号异摘要检测、JSONL 读写。

签名方案（合成演练，密钥随用例目录公开，仅供离线复核）：
    core = {"rec_id","device","seq","received_at","payload"}
    digest = "sha256:" + SHA256(domain_prefix + canonical_json(core))
    sig    = "hmac-sha256:" + HMAC_SHA256(key[device], digest_hex_ascii)

规范化 JSON：UTF-8、键排序、无空白、ensure_ascii=False。
"""
from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

DOMAIN_PREFIX = b"R12167-EVIDENCE-v1\n"


def canonical_bytes(obj: Any) -> bytes:
    return json.dumps(
        obj, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def core_object(env: Dict[str, Any]) -> Dict[str, Any]:
    """抽取参与摘要/签名的核心字段（不含 digest/sig）。"""
    return {
        "rec_id": env["rec_id"],
        "device": env["device"],
        "seq": env["seq"],
        "received_at": env.get("received_at"),
        "payload": env["payload"],
    }


def compute_digest(env: Dict[str, Any]) -> str:
    data = DOMAIN_PREFIX + canonical_bytes(core_object(env))
    return "sha256:" + sha256_hex(data)


def compute_sig(env: Dict[str, Any], key: str) -> str:
    digest = compute_digest(env)
    mac = hmac.new(key.encode("utf-8"), digest.encode("ascii"), hashlib.sha256)
    return "hmac-sha256:" + mac.hexdigest()


def build_envelope(
    *,
    rec_id: str,
    device: str,
    seq: int,
    payload: Dict[str, Any],
    key: str,
    received_at: Optional[int] = None,
) -> Dict[str, Any]:
    env: Dict[str, Any] = {
        "schema": "r12167-envelope-v1",
        "rec_id": rec_id,
        "device": device,
        "seq": int(seq),
        "received_at": received_at,
        "payload": payload,
    }
    env["digest"] = compute_digest(env)
    env["sig"] = compute_sig(env, key)
    return env


@dataclass
class VerifyReport:
    valid: List[str] = field(default_factory=list)
    bad_digest: List[str] = field(default_factory=list)
    bad_signature: List[str] = field(default_factory=list)
    unknown_device_key: List[str] = field(default_factory=list)
    equivocations: List[Dict[str, Any]] = field(default_factory=list)
    duplicate_rec_id_diff_digest: List[Dict[str, Any]] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not (
            self.bad_digest
            or self.bad_signature
            or self.unknown_device_key
            or self.equivocations
            or self.duplicate_rec_id_diff_digest
        )

    def summary(self) -> Dict[str, Any]:
        return {
            "valid_count": len(self.valid),
            "bad_digest": self.bad_digest,
            "bad_signature": self.bad_signature,
            "unknown_device_key": self.unknown_device_key,
            "equivocations": self.equivocations,
            "duplicate_rec_id_diff_digest": self.duplicate_rec_id_diff_digest,
            "integrity_ok": self.ok,
        }


def verify_envelope(env: Dict[str, Any], keys: Dict[str, str]) -> Optional[str]:
    """返回 None 表示摘要与签名均通过，否则返回失败原因代码。"""
    expected_digest = compute_digest(env)
    if not hmac.compare_digest(str(env.get("digest", "")), expected_digest):
        return "bad_digest"
    device = env["device"]
    key = keys.get(device)
    if key is None:
        return "unknown_device_key"
    expected_sig = compute_sig(env, key)
    if not hmac.compare_digest(str(env.get("sig", "")), expected_sig):
        return "bad_signature"
    return None


def verify_bundle(
    records: Iterable[Dict[str, Any]], keys: Dict[str, str]
) -> VerifyReport:
    """校验全部记录，并检测 (device, seq) 同号异摘要 / rec_id 冲突。"""
    rep = VerifyReport()
    seq_index: Dict[Tuple[str, int], Dict[str, Any]] = {}
    id_index: Dict[str, Dict[str, Any]] = {}
    for env in records:
        rid = env.get("rec_id", "<?>")
        failure = verify_envelope(env, keys)
        if failure == "bad_digest":
            rep.bad_digest.append(rid)
        elif failure == "bad_signature":
            rep.bad_signature.append(rid)
        elif failure == "unknown_device_key":
            rep.unknown_device_key.append(rid)
        else:
            rep.valid.append(rid)

        digest = env.get("digest")
        seq_key = (env.get("device"), env.get("seq"))
        prev = seq_index.get(seq_key)
        if prev is None:
            seq_index[seq_key] = env
        elif prev.get("digest") != digest:
            rep.equivocations.append(
                {
                    "device": seq_key[0],
                    "seq": seq_key[1],
                    "rec_ids": [prev.get("rec_id"), rid],
                    "digests": [prev.get("digest"), digest],
                }
            )

        prev_id = id_index.get(rid)
        if prev_id is None:
            id_index[rid] = env
        elif prev_id.get("digest") != digest:
            rep.duplicate_rec_id_diff_digest.append(
                {
                    "rec_id": rid,
                    "seqs": [prev_id.get("seq"), env.get("seq")],
                    "digests": [prev_id.get("digest"), digest],
                }
            )
    return rep


def write_jsonl(path: Path, records: Iterable[Dict[str, Any]]) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    n = 0
    with path.open("w", encoding="utf-8", newline="\n") as fh:
        for rec in records:
            fh.write(json.dumps(rec, ensure_ascii=False, sort_keys=True))
            fh.write("\n")
            n += 1
    return n


def read_jsonl(path: Path) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as fh:
        for line_no, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}:{line_no} 不是合法 JSON: {exc}") from exc
    return out


def write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as fh:
        json.dump(obj, fh, ensure_ascii=False, indent=2, sort_keys=False)
        fh.write("\n")


def read_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def hash_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return "sha256:" + h.hexdigest()


def hash_records(records: List[Dict[str, Any]]) -> str:
    """对一组封装记录的规范化字节流求根摘要。"""
    h = hashlib.sha256()
    for env in records:
        h.update(canonical_bytes(env))
        h.update(b"\n")
    return "sha256:" + h.hexdigest()
