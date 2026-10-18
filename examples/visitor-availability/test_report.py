import json
from pathlib import Path
import tempfile
import unittest

from compose import topology
from report import generate, metric_value, percentile, resource_summary, summarize_visits


class ReportTests(unittest.TestCase):
    def test_failures_and_missing_arrivals_remain_in_denominator(self):
        rows = [{"type": "visit", "phase": "measured", "outcome": "success", "latency_ms": 100},
                {"type": "visit", "phase": "measured", "outcome": "timeout", "latency_ms": 30000,
                 "challenges": 1, "proof_accepted": False},
                {"type": "visit", "phase": "measured", "outcome": "generator_miss"}]
        result = summarize_visits(rows, 4, 30000, 1000)
        self.assertEqual(result["success_percent"], 25)
        self.assertEqual(result["p95_ms"], 100)
        self.assertEqual(result["missing_records"], 1)
        self.assertEqual(result["challenge_timed_out"], 1)
        self.assertFalse(result["example_slo_met"])

    def test_percentile_empty_and_nearest_rank(self):
        self.assertIsNone(percentile([]))
        self.assertEqual(percentile(list(range(1, 101))), 95)

    def test_missing_and_zero_metric_are_distinguished(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "edge.metrics"
            self.assertIsNone(metric_value(path, "connections"))
            path.write_text('connections{frontend="ankah"} 0\nconnections{frontend="other"} 10\n')
            self.assertEqual(metric_value(path, "connections", frontend="ankah"), 0)
            self.assertIsNone(metric_value(path, "connections", frontend="missing"))

    def test_resources_use_cpu_deltas_and_simultaneous_memory_totals(self):
        samples = [{"time_ms": t, "containers": {
            "app": {"cpu_ns": t * 1000000, "memory_bytes": a},
            "edge": {"cpu_ns": t * 500000, "memory_bytes": b}}}
            for t, a, b in [(1000, 100, 20), (2000, 20, 100)]]
        result = resource_summary(samples, 1000, 2000, ["app", "edge"])
        self.assertEqual(result["cpu_seconds"], 1.5)
        self.assertEqual(result["sampled_peak_memory_bytes"], 120)
        self.assertFalse(resource_summary(samples[:1], 1000, 2000, ["app"])["complete"])
        self.assertFalse(resource_summary(samples, 1000, 2000, ["missing"])["complete"])

    def test_arms_keep_application_identical_and_include_dots_costs(self):
        direct, ankah, dots = [topology(arm) for arm in ("direct", "ankah", "dots")]
        for spec in (ankah, dots):
            for field in ("image", "build", "cpus", "mem_limit", "command"):
                self.assertEqual(spec["services"]["app"][field], direct["services"]["app"][field])
            self.assertNotIn("--proxy-abuse-profile", spec["services"]["ankah"]["command"])
        self.assertIn("mysql", dots["services"])
        self.assertIn("edge", dots["services"])
        self.assertNotIn("edge", ankah["services"])
        self.assertNotIn("ankah", direct["services"])

    def test_regeneration_pools_samples_and_flags_missing_solver_evidence(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for repeat, latency in [(1, 1), (2, 100)]:
                path = root / str(repeat)
                path.mkdir()
                cfg = {"arm": "ankah", "attack": "solved", "attack_rps": 1, "duration_s": 1,
                       "visitor_rps": 1, "timeout_ms": 30000, "new_slo_ms": 5000, "returning_slo_ms": 1000}
                (path / "manifest.json").write_text(json.dumps({"config": cfg, "start_ms": 0,
                    "end_ms": 1000, "serving_services": ["app", "ankah"]}))
                (path / "visitors.jsonl").write_text("\n".join(json.dumps({"actor": actor,
                    "type": "visit", "phase": "measured", "outcome": "success", "latency_ms": latency})
                    for actor in ("new", "returning")))
            result = generate(root)
            self.assertEqual(result["pooled"][0]["p95_ms"], 100)
            self.assertFalse(result["pooled"][0]["valid_load_comparison"])
            self.assertIn("solving attacker preparation missing from backend log", result["trials"][0]["invalid_reasons"])
            before = (root / "summary.json").read_bytes()
            generate(root)
            self.assertEqual(before, (root / "summary.json").read_bytes())
            (root / "metadata.json").write_text(json.dumps({"profile": "reference",
                "reference_protocol": True, "expected_trials": ["1", "2", "3"]}))
            incomplete = generate(root)
            self.assertFalse(incomplete["complete"])
            self.assertEqual(incomplete["missing_trials"], ["3"])


if __name__ == "__main__":
    unittest.main()
