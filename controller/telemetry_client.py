"""Async read-only controller boundary for a separate decision-service process."""
from __future__ import annotations

import asyncio
import http.client
import json
from urllib.parse import urlsplit

MAX_RESPONSE_BYTES = 4 * 1024 * 1024


class ObservationCursor:
    """Per-consumer continuity, independent of flow-counter snapshot completeness.

    First read starts at sequence zero for that epoch, exposing earlier evictions.
    Guard counts are packet-ins, not unique flows or lost clinical packets.
    """

    def __init__(self) -> None:
        self.epoch = None
        self.last_seq = 0
        self.guard_counts = {}

    def read(self, body: dict) -> dict:
        epoch = body["controller_epoch"]
        changed = self.epoch is not None and epoch != self.epoch
        first_read = self.epoch is None or changed
        previous = 0 if first_read else self.last_seq
        last = body["observation_last_seq"]
        if last < previous:
            raise ValueError("Observation sequence regressed within controller epoch")
        observations = [row for row in body["observations"] if row["seq"] > previous]
        expected = previous + 1
        missed = 0
        for row in observations:
            seq = row["seq"]
            if seq < expected or seq > last:
                raise ValueError("Invalid observation sequence ordering")
            missed += seq - expected
            expected = seq + 1
        missed += max(0, last - expected + 1)
        guards = body["observation_guard_drops"]
        baseline = {} if first_read else self.guard_counts
        delta = {key: value - baseline.get(key, 0) for key, value in guards.items()}
        if any(value < 0 for value in delta.values()):
            raise ValueError("Guard counters regressed within controller epoch")
        self.epoch, self.last_seq, self.guard_counts = epoch, last, dict(guards)
        return {"epoch_changed": changed, "first_read": first_read,
                "missed_observations": missed, "guard_drop_deltas": delta,
                "continuity_ok": not changed and missed == 0 and not any(delta.values()),
                "new_observations": observations}


def request_json(base_url: str, path: str, timeout_s: float = 2.0) -> tuple[int, dict]:
    """Read bounded JSON from the local API with no proxy or redirect following."""
    url = urlsplit(base_url)
    if (url.scheme != "http" or url.hostname != "127.0.0.1"
            or url.username or url.password or url.path not in ("", "/")
            or url.query or url.fragment):
        raise ValueError("Telemetry base URL must be http://127.0.0.1:PORT")
    if path not in ("/v1/health", "/v1/stats", "/v1/topology"):
        raise ValueError("Unsupported read-only telemetry path")
    if not 0.1 <= timeout_s <= 10:
        raise ValueError("HTTP I/O timeout must be in 0.1..10 seconds")
    connection = http.client.HTTPConnection(url.hostname, url.port or 80, timeout=timeout_s)
    try:
        connection.request("GET", path, headers={"Accept": "application/json"})
        response = connection.getresponse()
        raw = response.read(MAX_RESPONSE_BYTES + 1)
        if len(raw) > MAX_RESPONSE_BYTES:
            raise ValueError("Controller response exceeded size limit")
        if response.status not in (200, 503):
            raise RuntimeError(f"Controller returned HTTP {response.status}")
        body = json.loads(raw)
        if not isinstance(body, dict):
            raise ValueError("Expected a JSON object from controller")
        return response.status, body
    finally:
        connection.close()


class TelemetryClient:
    """Use a bounded number of executor calls; never block FastAPI's asyncio loop."""

    def __init__(self, base_url: str = "http://127.0.0.1:18080",
                 timeout_s: float = 2.0, concurrency: int = 2) -> None:
        if not 1 <= concurrency <= 4:
            raise ValueError("Concurrency must be 1..4")
        self.base_url, self.timeout_s = base_url, timeout_s
        self.slots = asyncio.Semaphore(concurrency)

    async def _get(self, path: str) -> tuple[int, dict]:
        return await self._run(request_json, self.base_url, path, self.timeout_s)

    async def _run(self, function: object, *args: object) -> tuple[int, dict]:
        """Retain worker admission through cancellation for reads and authenticated writes."""
        await self.slots.acquire()
        try:
            worker = asyncio.create_task(asyncio.to_thread(
                function, *args))
        except BaseException:
            self.slots.release()
            raise

        def finished(task: asyncio.Task) -> None:
            # Cancellation of a caller must not release its slot while the
            # executor's underlying HTTP operation is still running.
            self.slots.release()
            if not task.cancelled():
                task.exception()  # Retrieve errors even if the caller was cancelled.

        worker.add_done_callback(finished)
        return await asyncio.shield(worker)

    async def get_stats(self, require_complete: bool = True) -> dict:
        """Return current raw counters, rejecting incomplete telemetry by default."""
        status, body = await self._get("/v1/stats")
        if status != 200 or (require_complete and body.get("complete") is not True):
            raise RuntimeError("Controller telemetry is incomplete or stale")
        return body

    async def get_health(self) -> dict:
        """Return degraded health details as well as healthy responses."""
        _, body = await self._get("/v1/health")
        return body

    async def get_topology(self) -> dict:
        """Read the configured inventory through the same controller boundary."""
        status, body = await self._get("/v1/topology")
        if status != 200:
            raise RuntimeError("Controller topology is unavailable")
        return body
