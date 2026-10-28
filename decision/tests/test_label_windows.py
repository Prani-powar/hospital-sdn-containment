"""Conservative supervised-label creation checks."""
import unittest

from decision.features import FEATURE_FIELDS
from decision.label_windows import annotate, attack_starts


class LabelWindowsTests(unittest.TestCase):
    def feature_row(self, host, timestamp):
        feature = {field: 0 for field in FEATURE_FIELDS}
        feature.update(timestamp_ns=timestamp, window_s=5, host=host, role="admin")
        return {"check": "feature_window", "run_id": "seed_01", "feature": feature,
                "quality": {"valid": True, "feature_spec_version": "source-ingress-proxy-v1"}}

    def test_only_attack_source_is_labelled_after_attack_start(self):
        rows = [self.feature_row("reception1", 5), self.feature_row("guest1", 5),
                self.feature_row("reception1", 15), self.feature_row("guest1", 15)]
        labelled, summary = annotate(rows, [{"stage": "attack_start", "host": "reception1", "timestamp_ns": 10}])
        self.assertEqual([row["label"] for row in labelled], ["normal", "normal", "attack"])
        self.assertEqual(summary["skipped_unknown_post_attack"], 1)
        self.assertEqual(labelled[-1]["label_provenance"], "attack_source_after_recorded_start")

    def test_normal_only_run_has_no_attack_event_dependency(self):
        labelled, summary = annotate([self.feature_row("monitor1", 1)], [], normal_only=True)
        self.assertEqual(labelled[0]["label"], "normal")
        self.assertEqual(summary["attack_sources"], [])

    def test_attack_start_requires_safe_identity_and_timestamp(self):
        with self.assertRaisesRegex(ValueError, "attack_start needs a host"):
            attack_starts([{ "stage": "attack_start", "host": "", "timestamp_ns": 1}])


if __name__ == "__main__":
    unittest.main()
