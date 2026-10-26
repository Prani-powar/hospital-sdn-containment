"""Unit tests also collected by pytest; no root or network required."""
import copy
import json
import unittest
from pathlib import Path
from infra.smoke import validate

ROOT = Path(__file__).resolve().parents[1]


class ConfigurationTests(unittest.TestCase):
    """Attempt to weaken the infrastructure smoke test's guardrails."""

    def setUp(self) -> None:
        self.config = json.loads((ROOT / "smoke_config.json").read_text())

    def test_valid_config(self) -> None:
        validate(self.config)

    def test_reject_external_controller(self) -> None:
        self.config["controller_host"] = "0.0.0.0"
        with self.assertRaises(ValueError):
            validate(self.config)

    def test_reject_priority_override(self) -> None:
        for field in ("critical_priority", "quarantine_priority"):
            with self.subTest(field=field):
                bad = copy.deepcopy(self.config)
                bad[field] = 65535
                with self.assertRaises(ValueError):
                    validate(bad)

    def test_reject_non_expiring_or_unbounded_quarantine(self) -> None:
        for ttl in (0, -1, 3600, True, "4"):
            with self.subTest(ttl=ttl):
                self.config["quarantine_timeout_s"] = ttl
                with self.assertRaises(ValueError):
                    validate(self.config)

    def test_reject_invalid_ports(self) -> None:
        for port in (0, -1, 65536, True, "16653"):
            with self.subTest(port=port):
                self.config["controller_port"] = port
                with self.assertRaises(ValueError):
                    validate(self.config)

    def test_reject_unbounded_wait(self) -> None:
        self.config["connect_timeout_s"] = 0
        with self.assertRaises(ValueError):
            validate(self.config)


if __name__ == "__main__":
    unittest.main()
