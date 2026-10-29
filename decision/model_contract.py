"""Shared behavioural-vector contract; no ML dependencies at import time."""
FEATURE_VERSION = "source-ingress-proxy-v1"
# Timestamp identifies a collection cut, while host/role identify the lab
# inventory.  Neither belongs in a learned behavioural vector.
MODEL_FIELDS = ("flow_count", "unique_dst", "unique_dst_ports", "bytes_in", "bytes_out",
                "pkts_in", "pkts_out", "new_peers", "off_allow_list_flows", "short_flows")
ROLES = {"admin", "clinical", "critical_server", "iomt", "guest", "vendor"}
