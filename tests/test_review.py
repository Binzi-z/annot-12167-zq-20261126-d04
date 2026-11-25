"""12167 复核工具的标准库测试套件。

运行（仓库根目录）：
    python -m unittest discover -s tests -v
或直接 python run_all.py。
"""
from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from review12167 import pipeline, scale_data, small_data  # noqa: E402
from review12167.constraints import build_model  # noqa: E402
from review12167.evidence import (read_json, read_jsonl, verify_bundle,  # noqa: E402
                                  write_json)
from review12167.oracle import enumerate_all_offsets  # noqa: E402
from review12167.solver import TargetRequest, solve_target  # noqa: E402

ART = ROOT / "artifacts" / "12167"


class SmallCaseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.res = pipeline.run_small()
        cls.small_dir = ART / "small"
        cls.records = read_jsonl(cls.small_dir / "records.jsonl")
        cls.keys = read_json(cls.small_dir / "keys.json")

    def test_all_records_have_valid_digest_and_signature(self) -> None:
        v = verify_bundle(self.records, self.keys).summary()
        self.assertEqual(v["bad_digest"], [])
        self.assertEqual(v["bad_signature"], [])
        self.assertEqual(v["unknown_device_key"], [])
        self.assertEqual(v["valid_count"], len(self.records))

    def test_same_seq_diff_digest_detected_once(self) -> None:
        equi = self.res["verification_full"]["equivocations"]
        self.assertEqual(len(equi), 1)
        e = equi[0]
        self.assertEqual((e["device"], e["seq"]), ("A", 9))
        self.assertEqual(len(set(e["digests"])), 2)

    def test_sealed_view_excludes_late_cal_and_dup2(self) -> None:
        ids = {r["rec_id"] for r in read_jsonl(self.small_dir / "sealed_records.jsonl")}
        self.assertNotIn("CAL-B-LATE", ids)
        self.assertNotIn("A-NOTE-DUP-v2", ids)
        self.assertIn("A-NOTE-DUP-v1", ids)

    def test_rollback_generations_present_and_distinct(self) -> None:
        gens = {p["gen"] for r in self.records
                if (p := r["payload"]).get("kind") == "event"}
        self.assertEqual(gens, {"A-g0", "A-g1", "B-g0"})
        beacons = [r for r in self.records
                   if r["payload"].get("kind") == "beacon"]
        self.assertEqual(len(beacons), 1)
        self.assertEqual(beacons[0]["payload"]["action"], "clock_rollback")

    def test_updated_interval_is_tight_and_matches_bruteforce(self) -> None:
        iv = self.res["updated_interval"]
        self.assertEqual(iv, [17, 23])
        self.assertTrue(self.res["cross_check_updated"]["match"])
        ob = self.res["updated_oracle"]
        # 5 * 5 * 3 = 75 个偏移组合（晚到校准把 B 收紧到 [-1,1]）
        self.assertEqual(ob["total_offset_combinations"], 75)
        self.assertGreater(ob["feasible_count"], 0)

    def test_sealed_interval_wider_than_updated(self) -> None:
        self.assertEqual(self.res["sealed_interval"], [10, 30])
        sw = self.res["sealed_interval"]; uw = self.res["updated_interval"]
        self.assertGreaterEqual(sw[1] - sw[0], uw[1] - uw[0])

    def test_endpoint_witnesses_are_realizable(self) -> None:
        full = self.res["updated_result_full"]
        self.assertTrue(full["witness_lower_check"]["satisfies_all"])
        self.assertTrue(full["witness_upper_check"]["satisfies_all"])
        self.assertEqual(full["witness_lower_delta"], full["delta_interval"][0])
        self.assertEqual(full["witness_upper_delta"], full["delta_interval"][1])

    def test_ground_truth_delta_inside_interval(self) -> None:
        # 合成真值：true B-TGT=125, A-TGT=105 -> Δ=20
        lo, hi = self.res["updated_interval"]
        self.assertLessEqual(lo, 20)
        self.assertGreaterEqual(hi, 20)

    def test_raw_local_order_was_apparently_reversed(self) -> None:
        # 原始读数 A=165 > B=125，看似 A 晚；严格区间却 >0（B 真时更晚）
        self.assertGreater(165, 125)
        self.assertGreater(self.res["updated_interval"][0], 0)


class EmptyCaseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.res = pipeline.run_empty()

    def test_bruteforce_has_no_feasible_assignment(self) -> None:
        self.assertEqual(self.res["oracle"]["feasible_count"], 0)
        self.assertEqual(self.res["oracle"]["total_offset_combinations"], 9)

    def test_certificate_is_two_edge_negative_cycle(self) -> None:
        rv = self.res["certificate_review"]
        self.assertEqual(rv["cycle_edge_count"], 2)
        self.assertLess(rv["cycle_total_weight"], 0)
        self.assertEqual(rv["independent_dp_min_length"], 2)

    def test_standalone_verifier_subprocess_exits_zero(self) -> None:
        cert = ROOT / "reports" / "contradiction_certificate.json"
        keys = ART / "empty" / "keys.json"
        script = ROOT / "review12167" / "verify_certificate.py"
        proc = subprocess.run(
            [sys.executable, str(script), str(cert), "--keys", str(keys)],
            capture_output=True, text=True, encoding="utf-8", errors="replace")
        self.assertEqual(proc.returncode, 0, msg=proc.stdout + proc.stderr)
        self.assertIn("VERIFIED", proc.stdout)

    def test_tampered_certificate_is_rejected(self) -> None:
        # 篡改证书里的环权和，独立复核必须失败（退出码 1）
        cert = json.loads((ROOT / "reports" / "contradiction_certificate.json")
                          .read_text(encoding="utf-8"))
        bad = ART / "empty" / "tampered_cert.json"
        cert["total_weight"] = 999
        write_json(bad, cert)
        keys = ART / "empty" / "keys.json"
        script = ROOT / "review12167" / "verify_certificate.py"
        proc = subprocess.run(
            [sys.executable, str(script), str(bad), "--keys", str(keys)],
            capture_output=True, text=True, encoding="utf-8", errors="replace")
        self.assertNotEqual(proc.returncode, 0)


class SolverPropertyTests(unittest.TestCase):
    def test_witness_matches_bruteforce_on_random_tiny_models(self) -> None:
        """构造若干随机小约束，验证最短路端点与枚举一致（含不可行情形）。"""
        import random
        from review12167.constraints import Edge

        rng = random.Random(20261126)
        for trial in range(40):
            k = rng.randint(2, 4)
            gens = [f"g{i}" for i in range(k)]
            bounds = {g: [0, rng.randint(1, 4)] for g in gens}
            model_records = []  # 直接构造最小 model 较繁琐，改为走 build_model 数据
            # 用随机“事件+因果”记录构造
            keys = {"D": "k"}
            recs = []
            seq = 0
            ev = {}
            for gi, g in enumerate(gens):
                seq += 1
                rid = f"E{gi}"
                ts = rng.randint(0, 30)
                ev[g] = (rid, ts)
                from review12167.evidence import build_envelope
                recs.append(build_envelope(
                    rec_id=rid, device="D", seq=seq,
                    payload={"kind": "event", "gen": g, "local_ts": ts},
                    key="k"))
            # 注意：同设备序边会按 seq 加入；这里 seq 与 gen 对应，权为随机 ts 差，
            # 可能自身矛盾——这正好覆盖不可行分支。
            for a in range(k):
                for b in range(a + 1, k):
                    if rng.random() < 0.6:
                        la, ua = sorted((rng.randint(-6, 6), rng.randint(-6, 6)))
                        from review12167.evidence import build_envelope
                        seq += 1
                        recs.append(build_envelope(
                            rec_id=f"C{a}{b}", device="D", seq=seq, key="k",
                            payload={"kind": "causal", "from_event": ev[gens[a]][0],
                                     "to_event": ev[gens[b]][0],
                                     "latency": [la, ua]}))
            bmodel = build_model(recs, bounds)
            cid = next(iter(bmodel.components))
            tgt = TargetRequest(event1=ev[gens[0]][0], event2=ev[gens[1]][0])
            res = solve_target(bmodel, tgt)
            ora = enumerate_all_offsets(bmodel, cid,
                                        {"event1": tgt.event1, "event2": tgt.event2})
            if not res["feasible"]:
                self.assertTrue(ora["empty"], msg=f"trial {trial}")
            else:
                self.assertFalse(ora["empty"])
                self.assertEqual(res["delta_interval"],
                                 ora["target"]["bruteforce_interval"],
                                 msg=f"trial {trial}")
                self.assertTrue(res["witness_lower_check"]["satisfies_all"])
                self.assertTrue(res["witness_upper_check"]["satisfies_all"])


class ScaleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.m = pipeline.run_scale()

    def test_at_least_60000_events(self) -> None:
        self.assertGreaterEqual(self.m["event_count"], 60000)
        self.assertEqual(self.m["event_count"],
                         2 * scale_data.SHARDS * scale_data.EVENTS_PER_DEVICE)

    def test_not_fully_connected_many_components(self) -> None:
        self.assertGreaterEqual(self.m["component_count"], 200)
        self.assertFalse(self.m["graph_fully_connected"])

    def test_recompute_touches_one_small_component_by_records(self) -> None:
        # 每分片 210 事件 + 7 因果 + 1 校准 = 218
        self.assertEqual(self.m["component_record_count"], 218)
        self.assertLess(self.m["component_record_count"],
                        self.m["total_records_after_cal"] / 100)

    def test_incremental_matches_full_and_others_unchanged(self) -> None:
        self.assertTrue(self.m["incremental_matches_full_rebuild"])
        self.assertTrue(self.m["all_other_shards_unchanged"])
        self.assertEqual(self.m["unexpected_changed_shards"], [])

    def test_signatures_all_valid_at_scale(self) -> None:
        self.assertEqual(self.m["signature_problem_records"], 0)
        self.assertEqual(self.m["signature_valid_records"],
                         self.m["total_records_before_cal"])

    def test_calibration_narrows_interval(self) -> None:
        before = self.m["interval_before"]; after = self.m["interval_after"]
        self.assertLessEqual(after[1] - after[0], before[1] - before[0])
        for w in ("witness_after_lower", "witness_after_upper"):
            pass
        self.assertTrue(self.m["witness_lower_check"]["satisfies_all"])
        self.assertTrue(self.m["witness_upper_check"]["satisfies_all"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
