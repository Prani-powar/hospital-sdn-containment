"""Offline ML pipeline tests using labelled synthetic feature windows."""
import unittest
from unittest.mock import patch
import tempfile

import json
from pathlib import Path
import numpy as np

from decision.features import FEATURE_FIELDS
from decision.ml_pipeline import MODEL_FIELDS, ROLES, _group_split, read_windows, train
from decision.ml_scoring import MlScorer

class MlPipelineTests(unittest.TestCase):
    def record(self, run_id, label, sample):
        feature = {name: 0 for name in FEATURE_FIELDS}
        feature.update(timestamp_ns=sample + 1, window_s=5, host="reception1", role="admin",
                       flow_count=2 + label * 15 + sample % 2, unique_dst=1 + label * 10,
                       unique_dst_ports=1 + label * 12, bytes_in=10, bytes_out=100 + label * 500,
                       pkts_in=1, pkts_out=2 + label * 20, new_peers=label * 8,
                       off_allow_list_flows=label * 6, short_flows=label * 4)
        return {"check": "feature_window", "run_id": run_id, "label": label, "feature": feature,
                "quality": {"valid": True, "feature_spec_version": "source-ingress-proxy-v1"}}

    def test_input_contract_and_grouped_holdout(self):
        path = Path("labelled.jsonl")
        records = []
        for label, prefix in ((0, "normal"), (1, "attack")):
            for run in range(3):
                records.append(self.record(f"{prefix}_{run}", label, 100 * run + label))
        with patch.object(Path, "is_file", return_value=True), patch.object(Path, "stat") as stat, \
             patch.object(Path, "read_text", return_value="".join(json.dumps(r) + "\n" for r in records)):
            stat.return_value.st_size = 100
            rows = read_windows([path], require_label=True)
        self.assertEqual(rows[0]["x"], [records[0]["feature"][name] for name in MODEL_FIELDS])
        train, test = _group_split(rows, .25, 3)
        labels = np.array([row["label"] for row in rows])
        groups = np.array([row["run_id"] for row in rows])
        self.assertEqual(set(labels[train]), {0, 1})
        self.assertEqual(set(labels[test]), {0, 1})
        self.assertFalse(set(groups[train]) & set(groups[test]))

    def test_unlabelled_windows_are_rejected_for_supervised_input(self):
        path = Path("bad.jsonl")
        record = self.record("run", 0, 1)
        del record["label"]
        with patch.object(Path, "is_file", return_value=True), patch.object(Path, "stat") as stat, \
             patch.object(Path, "read_text", return_value=json.dumps(record) + "\n"):
            stat.return_value.st_size = 100
            with self.assertRaisesRegex(ValueError, "missing label"):
                read_windows([path], require_label=True)

    def test_role_specific_m1_artifact_is_trained_from_clean_windows(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            normal, labelled, output = root / "normal.jsonl", root / "labelled.jsonl", root / "models"
            normals = []
            for role in ROLES:
                for sample in range(20):
                    record = self.record("clean_" + role, 0, sample)
                    record["feature"]["role"] = role
                    normals.append(record)
            normal.write_text("".join(json.dumps(v) + "\n" for v in normals), encoding="utf-8")
            rows = []
            for label, prefix in ((0, "normal"), (1, "attack")):
                for run in range(3):
                    for sample in range(3):
                        rows.append(self.record(f"{prefix}_{run}", label, 1000 + run * 10 + sample))
            labelled.write_text("".join(json.dumps(v) + "\n" for v in rows), encoding="utf-8")
            result = train([normal], [labelled], output, seed=4)
            self.assertEqual(set(result["models"]["m1_isolation_forest"]["role_models"]), ROLES)
            self.assertTrue((output / "roc_pr.png").is_file())
            scorer = MlScorer.from_directory(output)
            sample = normals[0]["feature"]
            scores = scorer.score(sample)
            self.assertEqual(scores["role"], sample["role"])
            self.assertEqual(scores["policy_binding"], "selected explicitly by decision.live --detector; scoring alone does not mutate")

    def test_explicit_validation_calibration_and_no_test_seed_fitting(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);normal=root/'normal.jsonl';labelled=root/'labelled.jsonl'
            clean=[];rows=[]
            for role in ROLES:
                for sample in range(20):
                    r=self.record('clean',0,sample);r['feature']['role']=role
                    r.update(seed=101,partition='validation');clean.append(r)
                for run,seed,partition in (('train',101,'validation'),('val',102,'validation'),('test',201,'test')):
                    for label in (0,1):
                        for sample in range(5):
                            r=self.record(run,label,sample);r['feature']['role']=role
                            r.update(seed=seed,partition=partition);rows.append(r)
            normal.write_text(''.join(json.dumps(r)+'\n' for r in clean))
            labelled.write_text(''.join(json.dumps(r)+'\n' for r in rows))
            manifest=dict(train_runs=['train'],validation_runs=['val'],test_runs=['test'])
            result=train([normal],[labelled],root/'models',split_manifest=manifest)
            self.assertEqual(result['fit_seeds'],[101])
            self.assertEqual(result['calibration_seeds'],[102])
            self.assertEqual(result['split']['test_runs'],['test'])
            self.assertIn(result['models']['m2_random_forest']['threshold'],(.25,.5,.75))
            with self.assertRaisesRegex(ValueError,'Held-out experiment seeds'):
                train([normal],[labelled],root/'bad',split_manifest=dict(train_runs=['test'],validation_runs=['val'],test_runs=['train']))


if __name__ == "__main__":
    unittest.main()
