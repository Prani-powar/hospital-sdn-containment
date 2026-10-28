"""Deterministic fan-out scoring and role-aware desired-policy proposals.

This module cannot write to the controller. Desired state is never evidence of
installed rules. No machine-learning model is used or claimed.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import math
from pathlib import Path
import uuid

import yaml

from controller.core import Fabric
from decision.features import FEATURE_FIELDS
from topology.hospital import UniqueKeyLoader, load_plan, require

NUMERIC_FIELDS = set(FEATURE_FIELDS) - {"host", "role", "window_s"}


def load_detection_config(path: Path, fabric: Fabric) -> dict:
    """Reject unsafe profiles and unbounded timing/history settings."""
    require(path.stat().st_size <= 100_000, "Detection config exceeds 100 KB")
    config = yaml.load(path.read_text(), Loader=UniqueKeyLoader)
    require(isinstance(config, dict) and config.get("schema_version") == 1, "Invalid schema")
    for key in ("model_version", "feature_spec_version", "profile_version"):
        require(isinstance(config.get(key), str) and 0 < len(config[key]) <= 100, f"Invalid {key}")
    for key, low, high in (("anomalous_windows", 1, 20), ("clean_windows", 1, 20),
                           ("vendor_escalation_windows", 1, 20), ("containment_timeout_s", 1, 60)):
        require(type(config.get(key)) is int and low <= config[key] <= high, f"Invalid {key}")
    for key in ("max_feature_age_s", "max_step_gap_s"):
        v = config.get(key)
        require(type(v) in (int, float) and math.isfinite(v) and 0.1 <= v <= 30, f"Invalid {key}")
    roles = {host["role"] for host in fabric.hosts.values()}
    require(isinstance(config.get("thresholds"), dict) and set(config["thresholds"]) == roles,
            "Every configured role needs thresholds")
    for thresholds in config["thresholds"].values():
        require(isinstance(thresholds, dict) and set(thresholds) == {
            "unique_dst", "unique_dst_ports", "off_profile_min"}, "Invalid threshold keys")
        for key, high in (("unique_dst", len(fabric.hosts) - 1),
                          ("unique_dst_ports", 65536), ("off_profile_min", 10000)):
            require(type(thresholds[key]) is int and 1 <= thresholds[key] <= high,
                    f"Invalid threshold {key}")
    require(isinstance(config.get("allowed_peers_by_role"), dict)
            and set(config["allowed_peers_by_role"]) == roles, "Missing policy role")
    overrides = config.get("allowed_peer_overrides")
    require(isinstance(overrides, dict) and set(overrides) <= fabric.hosts.keys(), "Invalid overrides")
    for peers in [config.get("management_peers")] + list(config["allowed_peers_by_role"].values()) + list(overrides.values()):
        require(isinstance(peers, list) and len(peers) <= len(fabric.hosts)
                and all(isinstance(p, str) and p in fabric.hosts for p in peers)
                and len(set(peers)) == len(peers), "Invalid allowed peers")
    require(config["management_peers"], "Isolation proposals require explicit management peers")
    pairs = config.get("protected_pairs")
    require(isinstance(pairs, list) and len(pairs) <= len(fabric.hosts)**2, "Invalid protected pairs")
    for pair in pairs:
        require(isinstance(pair, list) and len(pair) == 2 and pair[0] != pair[1]
                and all(isinstance(h, str) and h in fabric.hosts for h in pair), "Invalid protected pair")
        source, dst = pair
        role = fabric.hosts[source]["role"]
        if role in ("clinical", "iomt"):
            allowed = overrides.get(source, config["allowed_peers_by_role"][role])
            require(dst in allowed, "Policy removes a configured vital peer")
    require(isinstance(config.get("demo_hosts"), list) and 0 < len(config["demo_hosts"]) <= len(fabric.hosts)
            and all(h in fabric.hosts for h in config["demo_hosts"]), "Invalid demo inventory")
    return config


@dataclass
class HostState:
    """Fixed-inventory desired state; no observed-switch-state claim."""
    status: str = "NORMAL"
    last_timestamp_ns: int = -1
    anomalous_streak: int = 0
    clean_streak: int = 0
    version: int = 0
    action: str | None = None
    lease_until_ns: int = 0
    vendor_persistent: int = 0


class DetectionPolicy:
    """Single-owner synchronous planner with explicit source and quality checks."""

    def __init__(self, fabric: Fabric, config: dict, score_provider=None) -> None:
        self.fabric, self.config = fabric, config
        self.score_provider = score_provider
        self.states = {name: HostState() for name in fabric.hosts}
        self.epoch: str | None = None
        self.planner_epoch = uuid.uuid4().hex
        self.protected = {tuple(pair) for pair in config["protected_pairs"]}
        self.allowed = {name: sorted(config["allowed_peer_overrides"].get(
            name, config["allowed_peers_by_role"][host["role"]])) for name, host in fabric.hosts.items()}

    def invalidate(self, host: str | None = None) -> None:
        """Break evidence streaks, never infer a clean/release decision from missing data."""
        for name in ([host] if isinstance(host, str) and host in self.states else self.states):
            state = self.states[name]
            state.anomalous_streak = state.clean_streak = state.vendor_persistent = 0
            if state.action is None:
                state.status = "NORMAL"

    def _validate(self, feature: dict, quality: dict, now_ns: int) -> None:
        require(isinstance(feature, dict) and set(feature) == set(FEATURE_FIELDS), "Feature contract mismatch")
        require(feature["host"] in self.fabric.hosts, "Unknown feature host")
        require(feature["role"] == self.fabric.hosts[feature["host"]]["role"], "Role spoofing rejected")
        require(quality.get("valid") is True and
                quality.get("feature_spec_version") == self.config["feature_spec_version"] and
                quality.get("profile_version") == self.config["profile_version"], "Invalid feature quality/version")
        require(type(now_ns) is int and now_ns >= 0, "Invalid clock")
        for key in NUMERIC_FIELDS:
            require(type(feature[key]) is int and 0 <= feature[key] <= 2**63-1, f"Invalid feature {key}")
        window = feature["window_s"]
        require(type(window) in (int, float) and math.isfinite(window) and 0 < window <= 60,
                "Invalid window duration")
        require(0 <= now_ns - feature["timestamp_ns"] <= self.config["max_feature_age_s"] * 1e9,
                "Stale or future feature")
        require(feature["unique_dst"] <= len(self.fabric.hosts)-1 and
                feature["new_peers"] <= feature["unique_dst"] and
                max(feature["unique_dst"], feature["unique_dst_ports"], feature["short_flows"],
                    feature["off_allow_list_flows"]) <= feature["flow_count"], "Inconsistent feature counts")

    def score(self, feature: dict) -> dict:
        """Return exact Score contract; ratio >=1 means a configured threshold is met."""
        if self.score_provider is not None:
            score = self.score_provider(feature)
            require(isinstance(score, dict) and score.get('host') == feature['host']
                    and type(score.get('anomalous')) is bool
                    and type(score.get('anomaly_score')) in (int, float)
                    and math.isfinite(score['anomaly_score'])
                    and isinstance(score.get('model_version'), str), 'Invalid selected detector score')
            return score
        threshold = self.config["thresholds"][feature["role"]]
        off_profile = feature["off_allow_list_flows"] >= threshold["off_profile_min"]
        ratio = max(feature["unique_dst"] / threshold["unique_dst"],
                    feature["unique_dst_ports"] / threshold["unique_dst_ports"])
        return {"host": feature["host"], "anomaly_score": ratio if off_profile else 0.0,
                "anomalous": bool(off_profile and ratio >= 1), "model_version": self.config["model_version"]}

    def _proposal(self, name: str, action: str, now_ns: int, reason: str,
                  malicious_source: str | None = None) -> dict:
        state = self.states[name]
        role = self.fabric.hosts[name]["role"]
        require(action != "ISOLATE" or role in ("admin", "guest", "vendor"), "Unsafe isolation rejected")
        if action == "PROTECT":
            require(malicious_source in self.fabric.hosts and malicious_source != name,
                    "PROTECT needs an attributed source")
            require((malicious_source, name) not in self.protected, "PROTECT conflicts with a vital allow")
        state.version += 1
        peers = (sorted(set(self.config["management_peers"]) - {name}) if action == "ISOLATE"
                 else self.allowed[name] if action == "RESTRICT" else [])
        timeout = self.config["containment_timeout_s"] if action != "RELEASE" else 0
        contract = {"action": action, "host": name, "allowed_peers": peers,
                    "timeout_s": timeout, "reason": reason}
        identity = json.dumps([self.planner_epoch, self.epoch, name, state.version,
                               contract, malicious_source], sort_keys=True)
        proposal_id = hashlib.sha256(identity.encode()).hexdigest()
        return {"proposal_id": proposal_id, "version": state.version,
                "controller_epoch": self.epoch, "created_ns": now_ns,
                "planner_epoch": self.planner_epoch,
                "action": contract, "malicious_source": malicious_source,
                "applied": False, "scope": "desired_policy_only"}

    def tick(self, now_ns: int) -> list[dict]:
        """Expire desired leases even without new telemetry; never claim switch deletion."""
        require(type(now_ns) is int and now_ns >= 0, "Invalid clock")
        expired = []
        for name, state in self.states.items():
            if state.action and now_ns >= state.lease_until_ns:
                expired.append(self._proposal(name, "RELEASE", now_ns, "Desired lease expired; observed rules require reconciliation"))
                state.action = None
                state.lease_until_ns = 0
                state.status = "NORMAL"
                state.anomalous_streak = state.clean_streak = state.vendor_persistent = 0
        return expired

    def consume(self, feature: dict, quality: dict, now_ns: int, epoch: str,
                malicious_source: str | None = None) -> dict:
        """Consume one unique window. Caller must separately schedule tick for expiry."""
        name = feature.get("host") if isinstance(feature, dict) else None
        try:
            self._validate(feature, quality, now_ns)
            require(malicious_source is None or isinstance(malicious_source, str), "Invalid source attribution")
            require(isinstance(epoch, str) and 0 < len(epoch) <= 100, "Invalid epoch")
        except (ValueError, KeyError, TypeError, AttributeError) as exc:
            self.invalidate(name)
            return {"status": "invalid", "reason": str(exc)[:160], "score": None, "proposals": []}
        if self.epoch is not None and self.epoch != epoch:
            # An external executor must reconcile actual rules. Do not clear desired
            # leases or reuse evidence from the old controller connection.
            self.invalidate()
            for state in self.states.values():
                state.last_timestamp_ns = -1
        self.epoch = epoch
        state = self.states[name]
        stamp = feature["timestamp_ns"]
        if stamp <= state.last_timestamp_ns:
            return {"status": "duplicate_or_stale", "score": None, "proposals": []}
        if state.last_timestamp_ns >= 0 and stamp-state.last_timestamp_ns > self.config["max_step_gap_s"] * 1e9:
            self.invalidate(name)
        try:
            score = self.score(feature)
        except (ValueError, KeyError, TypeError, AttributeError) as exc:
            self.invalidate(name)
            return {'status': 'invalid', 'reason': str(exc)[:160], 'score': None, 'proposals': []}
        state.last_timestamp_ns = stamp
        proposals = []
        if score["anomalous"]:
            state.clean_streak = 0
            state.anomalous_streak = min(state.anomalous_streak+1, self.config["anomalous_windows"])
            if state.action:
                if feature["role"] == "vendor" and state.action == "RESTRICT":
                    state.vendor_persistent = min(state.vendor_persistent+1, self.config["vendor_escalation_windows"])
                    if state.vendor_persistent >= self.config["vendor_escalation_windows"]:
                        proposals.append(self._proposal(name, "ISOLATE", now_ns, "Vendor anomaly persisted after restriction"))
                        state.action = "ISOLATE"
                        state.lease_until_ns = now_ns + self.config["containment_timeout_s"] * 1_000_000_000
            elif state.anomalous_streak >= self.config["anomalous_windows"]:
                role = feature["role"]
                action = "ISOLATE" if role in ("admin", "guest") else "PROTECT" if role == "critical_server" else "RESTRICT"
                if action == "PROTECT" and (malicious_source not in self.fabric.hosts or malicious_source == name
                                             or (malicious_source, name) in self.protected):
                    state.status = "SUSPECT"
                    return {"status": "needs_source_attribution_or_human_review", "score": score,
                            "desired_state": state.status, "proposals": []}
                proposals.append(self._proposal(name, action, now_ns, "Consecutive anomalous windows: " + score["model_version"], malicious_source))
                state.action = action
                state.status = "CONTAINED"
                state.lease_until_ns = now_ns + self.config["containment_timeout_s"] * 1_000_000_000
            else:
                state.status = "SUSPECT"
        else:
            state.anomalous_streak = state.vendor_persistent = 0
            state.clean_streak = min(state.clean_streak+1, self.config["clean_windows"])
            if state.action and state.clean_streak >= self.config["clean_windows"]:
                state.status = "RELEASING"
                proposals.append(self._proposal(name, "RELEASE", now_ns, "Consecutive clean windows"))
                state.action = None
                state.lease_until_ns = 0
                state.status = "NORMAL"
            elif not state.action:
                state.status = "NORMAL"
        return {"status": "scored", "score": score, "proposals": proposals,
                "desired_state": state.status, "observed_state": "not_connected"}


def from_config(topology: Path, policy: Path) -> DetectionPolicy:
    """Build a planner using the shared, validated hospital inventory."""
    fabric = Fabric(load_plan(topology))
    return DetectionPolicy(fabric, load_detection_config(policy, fabric))
