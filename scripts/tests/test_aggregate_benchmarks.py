"""Tests for evidence-only benchmark aggregation."""
import unittest

from scripts.aggregate_benchmarks import aggregate


def row(baseline, scenario, seed, **metrics):
    return {"schema_version": 1, "baseline": baseline, "scenario": scenario, "seed": seed,
            "run_id": f"{baseline}{scenario}{seed}", "evidence_status": "PASS",
            "false_isolation_critical": False, "metrics": metrics or {"f1": .9}}


class AggregateTests(unittest.TestCase):
    def test_reports_seed_level_mean_and_t_interval_without_filling_missing(self):
        result = aggregate([row("B0", "S1", 1, f1=.5), row("B0", "S1", 2, f1=.9)], 2)
        group = result["groups"][0]
        self.assertTrue(group["coverage_complete"])
        self.assertAlmostEqual(group["metrics"]["f1"]["mean"], .7)
        self.assertIsNotNone(group["metrics"]["f1"]["ci95_half_width"])
        self.assertNotIn("recall", group["metrics"])

    def test_rejects_duplicate_seed_identity(self):
        with self.assertRaisesRegex(ValueError, "Duplicate"):
            aggregate([row("B3", "S2", 1), row("B3", "S2", 1)])


if __name__ == "__main__":
    unittest.main()
