"""Quick summary of all demo run reports."""
import json, glob, os

reports = sorted(glob.glob("artifacts/demo/*/report.json"))
if not reports:
    print("No runs found.")
else:
    print(f"{'RUN_ID[:12]':<14} {'SOURCE_HOST':<16} {'ACTION':<9} {'STATUS':<6} PHASES  CONFIRMED")
    print("-" * 75)
    for f in reports:
        try:
            r = json.load(open(f))
            rid = r.get("run_id", "?")[:12]
            host = r.get("source_host", "?")
            action = r.get("containment_action", "?")
            status = r.get("status", "?")
            phases = list(r.get("phases", {}).keys())
            confirmed = len(r.get("confirmed_actions", []))
            error = r.get("error", "")
            print(f"{rid:<14} {host:<16} {action:<9} {status:<6} {phases}  confirmed={confirmed}")
            if error:
                print(f"               error: {error}")
        except Exception as e:
            print(f"{f}: could not read — {e}")
