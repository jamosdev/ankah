"""Recalculate availability summaries from retained observations, without Docker."""
import argparse
from collections import Counter, defaultdict
import csv
import json
import math
import re
from pathlib import Path


def read_jsonl(path):
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def percentile(values, fraction=.95):
    """Nearest-rank percentile; never average independently calculated p95s."""
    return sorted(values)[math.ceil(len(values) * fraction) - 1] if values else None


def metric_value(path, name, **labels):
    values = []
    for line in path.read_text().splitlines() if path.exists() else []:
        match = re.fullmatch(re.escape(name) + r'(?:\{([^}]*)\})?\s+([0-9.eE+-]+)', line)
        if match and labels.items() <= dict(re.findall(r'(\w+)="([^"]*)"', match[1] or "")).items():
            values.append(float(match[2]))
    return sum(values) if values else None


def summarize_visits(rows, expected, timeout_ms, slo_ms):
    visits = [r for r in rows if r.get("type") == "visit" and r.get("phase") == "measured"]
    counts = Counter(r["outcome"] for r in visits)
    successful = [r for r in visits if r["outcome"] == "success" and r["latency_ms"] <= timeout_ms]
    challenges = [r for r in visits if r.get("challenges", 0)]
    accepted = [r for r in challenges if r.get("proof_accepted")]
    return {
        "offered": expected, "recorded": len(visits), "missing_records": max(0, expected - len(visits)),
        "successful": len(successful), "success_percent": 100 * len(successful) / expected if expected else None,
        "outcomes": dict(counts), "deadline_success_percent": 100 * len(successful) / expected if expected else None,
        "p95_ms": percentile([r["latency_ms"] for r in successful]),
        "p95_samples": len(successful), "p95_small_sample": len(successful) < 100,
        "challenged": len(challenges), "proof_accepted": len(accepted),
        "challenge_failed": sum(r["outcome"] != "timeout" and not r.get("proof_accepted") for r in challenges),
        "challenge_timed_out": sum(r["outcome"] == "timeout" and not r.get("proof_accepted") for r in challenges),
        "challenge_p95_ms": percentile([r["challenge_ms"] for r in accepted if r.get("challenge_ms") is not None]),
        "example_slo_met": bool(expected and len(successful) / expected >= .99 and
                                percentile([r["latency_ms"] for r in successful]) <= slo_ms),
    }


def resource_summary(samples, start, end, services):
    """Use cumulative CPU boundaries and simultaneous memory sums, not summed peaks."""
    measured = [s for s in samples if start <= s["time_ms"] <= end and "containers" in s]
    totals, per_service = [], {}
    for service in services:
        points = [(s["time_ms"], s["containers"][service]) for s in measured if service in s["containers"]]
        if len(points) < 2:
            per_service[service] = {"complete": False}
            continue
        delta = points[-1][1]["cpu_ns"] - points[0][1]["cpu_ns"]
        span = (points[-1][0] - points[0][0]) / 1000
        per_service[service] = {"complete": True, "cpu_seconds": delta / 1e9,
            "mean_cpu_cores": delta / 1e9 / span, "covered_seconds": span,
            "sampled_peak_memory_bytes": max(p[1]["memory_bytes"] for p in points)}
    for sample in measured:
        if all(service in sample["containers"] for service in services):
            totals.append(sum(sample["containers"][s]["memory_bytes"] for s in services))
    complete = bool(services and totals and all(p["complete"] for p in per_service.values()))
    return {"complete": complete, "containers": per_service,
            "samples": len(totals),
            "cpu_seconds": sum(p.get("cpu_seconds", 0) for p in per_service.values()) if complete else None,
            "mean_cpu_cores": sum(p.get("mean_cpu_cores", 0) for p in per_service.values()) if complete else None,
            "sampled_peak_memory_bytes": max(totals) if totals else None}


def trial_summary(path):
    manifest = json.loads((path / "manifest.json").read_text())
    cfg = manifest["config"]
    rows = read_jsonl(path / "visitors.jsonl") + read_jsonl(path / "attacker.jsonl")
    expected = math.floor(cfg["duration_s"] * cfg["visitor_rps"])
    cohorts = {actor: summarize_visits([r for r in rows if r.get("actor") == actor], expected,
                cfg["timeout_ms"], cfg["new_slo_ms"] if actor == "new" else cfg["returning_slo_ms"])
               for actor in ("new", "returning")}
    attacks = [r for r in rows if r.get("actor") == "attacker" and r.get("type") == "visit" and r.get("phase") == "measured"]
    expected_attack = math.floor(cfg["duration_s"] * cfg["attack_rps"])
    backend = []
    for line in (path / "app.log").read_text().splitlines() if (path / "app.log").exists() else []:
        if "BENCH " in line:
            try:
                backend.append(json.loads(line.split("BENCH ", 1)[1]))
            except ValueError:
                pass
    completed_ids = {r["id"] for r in backend if r["status"] == 200}
    misses = sum(r.get("outcome") == "generator_miss" for r in rows if r.get("phase") == "measured")
    samples = read_jsonl(path / "resources.jsonl")
    serving = resource_summary(samples, manifest["start_ms"], manifest["end_ms"], manifest["serving_services"])
    clients = resource_summary(samples, manifest["start_ms"], manifest["end_ms"], ["visitors", "attacker"])
    lifetime = {}
    for service in [*manifest["serving_services"], "visitors", "attacker"]:
        points = [s["containers"][service] for s in samples if service in s.get("containers", {})]
        if points:
            lifetime[service] = {"cpu_seconds_since_container_creation": points[-1]["cpu_ns"] / 1e9,
                "sampled_peak_memory_bytes": max(p["memory_bytes"] for p in points)}
    reasons = list(manifest.get("errors", []))
    if misses:
        reasons.append("generator missed arrivals")
    if any(c["recorded"] != expected for c in cohorts.values()) or len(attacks) != expected_attack:
        reasons.append("arrival records do not match fixed schedule")
    if not serving["complete"] or not clients["complete"]:
        reasons.append("resource samples incomplete")
    for stats in (serving, clients):
        if any(c.get("covered_seconds", 0) < cfg["duration_s"] - 2.5 for c in stats["containers"].values()):
            reasons.append("resource window coverage insufficient")
            break
    missing_backend = [r["id"] for r in attacks if r["outcome"] == "success" and r["id"] not in completed_ids]
    if missing_backend:
        reasons.append("successful attacker responses missing from backend completion log")
    prep = [r for r in rows if r.get("type") == "visit" and r.get("phase") == "setup"]
    if cfg["attack"] == "solved":
        if not any(r.get("id") == "setup_attacker" and r["outcome"] == "success" and
                   (cfg["arm"] == "direct" or r.get("proof_accepted")) for r in prep):
            reasons.append("solving attacker preparation not verified")
        if "setup_attacker" not in completed_ids:
            reasons.append("solving attacker preparation missing from backend log")
    dots = None
    if cfg["arm"] == "dots":
        dots = {"edge_acl_installs": metric_value(path / "edge.metrics", "edge_dots_acl_changes_total", op="install"),
                "edge_rejected_connections": metric_value(path / "edge.metrics", "edge_connections_rejected_total", frontend="ankah"),
                "gateway_install_errors": metric_value(path / "gateway.prom", "ankah_dots_operations_total", operation="install", result="error")}
    return {"trial": path.name, "config": cfg, "valid_load_comparison": not reasons,
            "invalid_reasons": reasons, "cohorts": cohorts,
            "attack": {"offered": expected_attack, "recorded": len(attacks),
                "outcomes": dict(Counter(r["outcome"] for r in attacks)),
                "http_statuses": dict(Counter(str(r["status"]) for r in attacks if "status" in r)),
                "backend_completed": sum(r["id"].startswith("attacker_") and r["status"] == 200 for r in backend),
                "successful_ids_missing_from_backend": missing_backend},
            "setup": prep,
            "setup_wire_requests": dict(Counter(r["actor"] for r in rows if r.get("type") == "wire_request" and r.get("phase") == "setup")),
            "measured_wire_requests": dict(Counter(r["actor"] for r in rows if r.get("type") == "wire_request" and r.get("phase") == "measured")),
            "resources": serving, "client_resources": clients,
            "container_lifetime_resources": lifetime, "observer_resources": manifest.get("observer_resources"),
            "dots_observations": dots}


def generate(root):
    trials = [trial_summary(p.parent) for p in sorted(root.glob("*/manifest.json"))]
    groups = defaultdict(list)
    for trial in trials:
        cfg = trial["config"]
        groups[(cfg["arm"], cfg["attack"], cfg["attack_rps"])].append(trial)
    pooled = []
    for (arm, attack, rate), members in groups.items():
        for actor in ("new", "returning"):
            rows = [row for member in members for row in read_jsonl(root / member["trial"] / "visitors.jsonl")
                    if row.get("actor") == actor]
            cfg = members[0]["config"]
            result = summarize_visits(rows, sum(m["cohorts"][actor]["offered"] for m in members), cfg["timeout_ms"],
                                      cfg["new_slo_ms"] if actor == "new" else cfg["returning_slo_ms"])
            pooled.append({"arm": arm, "attack": attack, "attack_rps": rate, "cohort": actor,
                "repeats": len(members), "valid_load_comparison": all(m["valid_load_comparison"] for m in members), **result})
    metadata = json.loads((root / "metadata.json").read_text()) if (root / "metadata.json").exists() else {}
    missing = sorted(set(metadata.get("expected_trials", [])) - {t["trial"] for t in trials})
    output = {"profile": metadata.get("profile", "unknown"), "reference_protocol": metadata.get("reference_protocol", False),
              "complete": bool(trials) and not missing, "missing_trials": missing,
              "percentile_method": "nearest rank of successful visits, never average of p95s",
              "trials": trials, "pooled": pooled}
    (root / "summary.json").write_text(json.dumps(output, indent=2) + "\n")
    fields = ["arm", "attack", "attack_rps", "cohort", "repeats", "valid_load_comparison", "offered",
              "successful", "success_percent", "p95_ms", "p95_samples", "challenge_p95_ms", "example_slo_met"]
    with (root / "summary.csv").open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(pooled)
    lines = ["# Visitor availability results", "",
             f'Profile: {output["profile"]}. Complete: {output["complete"]}. Full reference protocol: {output["reference_protocol"]}.', "",
             "Successful-visit p95 is conditional on success. Read failure counts and sample sizes alongside it.",
             "Example SLOs are configurable interpretation aids, not suitability guarantees. Resource peaks are sampled.", "",
             "| Deployment | Attack | RPS | Visitor | Repeats | Valid load | Correct / offered | p95 ms | Challenge p95 ms |",
             "|---|---|---:|---|---:|---|---:|---:|---:|"]
    fmt = lambda v: "n/a" if v is None else f"{v:.1f}"
    for row in pooled:
        lines.append(f'| {row["arm"]} | {row["attack"]} | {row["attack_rps"]} | {row["cohort"]} | {row["repeats"]} | {row["valid_load_comparison"]} | {row["successful"]} / {row["offered"]} | {fmt(row["p95_ms"])} | {fmt(row["challenge_p95_ms"])} |')
    lines += ["", "## Each repeat and serving resources", "",
              "| Trial | Valid load | Serving CPU seconds | Mean CPU cores | Sampled peak MiB |",
              "|---|---|---:|---:|---:|"]
    for trial in trials:
        resource = trial["resources"]
        memory = resource["sampled_peak_memory_bytes"]
        lines.append(f'| {trial["trial"]} | {trial["valid_load_comparison"]} | {fmt(resource["cpu_seconds"])} | {fmt(resource["mean_cpu_cores"])} | {fmt(memory / 1048576 if memory is not None else None)} |')
        if trial["invalid_reasons"]:
            lines += ["", trial["trial"] + ": " + "; ".join(trial["invalid_reasons"]), ""]
    lines += ["", "See summary.json for each repeat's cohort results, failures, setup charges, backend correlation, client costs, and per-container resources.",
              "Container lifetime CPU counters include startup, preparation, and draining; the table above uses the measured window only.",
              "Host-side sampling and Docker daemon overhead are outside container totals.",
              "Raw observations, manifests, logs, and metadata are retained beside this report.", ""]
    (root / "summary.md").write_text("\n".join(lines))
    return output


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("artifacts", type=Path)
    args = parser.parse_args()
    generate(args.artifacts.resolve())
