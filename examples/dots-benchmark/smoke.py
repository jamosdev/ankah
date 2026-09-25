#!/usr/bin/env python3
"""Build the dots-benchmark demo, run it, and check the mechanism.

Every observation is taken from inside the Compose networks with
`docker compose exec`, so host ports are only needed for people opening
Prometheus or Grafana in a browser.

A clean run (without --use-running) replaces any running copy of this demo:
it runs `docker compose down -v` before starting and again at the end, which
also deletes the demo credentials volume.

Usage:
  python3 smoke.py
  python3 smoke.py --keep
  python3 smoke.py --use-running
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path
from urllib.parse import quote

HERE = Path(__file__).resolve().parent
COMPOSE = ["docker", "compose", "-f", str(HERE / "compose.yaml")]
DOTS_BASE = (
    "https://edge-dots.demo.test:4443/v1/restconf/data/"
    "ietf-dots-data-channel:dots-data/dots-client=ankah-demo"
)
SAMPLE = re.compile(r"^([a-zA-Z_:][a-zA-Z0-9_:]*)(\{[^}]*\})?\s+(\S+)$")


def demo_env() -> dict[str, str]:
    env = os.environ.copy()
    env.setdefault("DOTS_BLOCK_SECONDS", "20")
    # Set explicitly, not as defaults: `make` exports the demo's own port
    # defaults, and the smoke stack must not collide with a demo on those.
    env["GRAFANA_PORT"] = os.environ.get("SMOKE_GRAFANA_PORT", "3001")
    env["PROMETHEUS_PORT"] = os.environ.get("SMOKE_PROMETHEUS_PORT", "9091")
    return env


ENV = demo_env()


def check(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)
    print(f"  ok: {message}", flush=True)


def compose(*args: str, capture: bool = False) -> str:
    result = subprocess.run(
        [*COMPOSE, *args],
        cwd=HERE,
        env=ENV,
        check=True,
        capture_output=capture,
        text=True,
    )
    return result.stdout if capture else ""


def exec_in(service: str, *command: str) -> str:
    return compose("exec", "-T", service, *command, capture=True)


def query(expr: str) -> list[dict]:
    url = "http://127.0.0.1:9090/api/v1/query?query=" + quote(expr, safe="")
    raw = exec_in("prometheus", "wget", "-qO-", url)
    body = json.loads(raw)
    if body.get("status") != "success":
        raise AssertionError(f"Prometheus query failed: {expr}: {raw}")
    return body["data"]["result"]


def scalar(expr: str) -> float:
    result = query(expr)
    if not result:
        return 0.0
    return sum(float(item["value"][1]) for item in result)


def prom_text(service: str, url: str) -> dict[tuple[str, tuple[tuple[str, str], ...]], float]:
    text = exec_in(service, "curl", "-fsS", url)
    samples: dict[tuple[str, tuple[tuple[str, str], ...]], float] = {}
    for line in text.splitlines():
        if line.startswith("#"):
            continue
        match = SAMPLE.match(line)
        if not match:
            continue
        labels = tuple(sorted(re.findall(r'(\w+)="([^"]*)"', match.group(2) or "")))
        samples[(match.group(1), labels)] = float(match.group(3))
    return samples


def sample_value(samples: dict, name: str, **labels: str) -> float:
    wanted = set(labels.items())
    return sum(v for (n, l), v in samples.items() if n == name and wanted <= set(l))


def edge_metric(name: str, **labels: str) -> float:
    samples = prom_text("edge", "http://172.30.1.10:9100/metrics")
    return sample_value(samples, name, **labels)


def wait_for(message: str, predicate, timeout: float = 90.0, interval: float = 2.0):
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        try:
            last = predicate()
            if last:
                print(f"  ok: {message}", flush=True)
                return last
        except (AssertionError, json.JSONDecodeError, subprocess.CalledProcessError) as err:
            last = err
        time.sleep(interval)
    raise AssertionError(f"timed out waiting for {message}; last={last!r}")


def all_targets_up() -> bool:
    result = query("up")
    up = {
        (item["metric"].get("job"), item["metric"].get("instance"))
        for item in result
        if item["value"][1] == "1"
    }
    expected = {
        ("edge", "172.30.1.10:9100"),
        ("anubis", "anubis:9090"),
        ("ankah", "172.30.1.21:9101"),
        ("backends", "fastapi:9102"),
        ("backends", "django:9102"),
        ("attacker", "172.30.0.20:9300"),
        ("legit-probe", "172.30.0.21:9301"),
        ("cadvisor", "172.30.2.30:8080"),
    }
    return expected <= up


def grafana_healthy() -> bool:
    health = json.loads(exec_in("prometheus", "wget", "-qO-", "http://grafana:3000/api/health"))
    dashboards = json.loads(exec_in("prometheus", "wget", "-qO-", "http://grafana:3000/api/search"))
    return health.get("database") == "ok" and any(d.get("title") == "DOTS Benchmark" for d in dashboards)


def attacker_alternates() -> bool:
    raw = exec_in("legit-probe", "curl", "-fsS", "http://172.30.0.20:9300/sequence")
    sequence = json.loads(raw)
    entries = sequence.get("entries", [])
    if len(entries) < 20:
        return False
    for prev, cur in zip(entries, entries[1:]):
        if cur["seq"] != prev["seq"] + 1:
            return False
        if cur["target"] == prev["target"]:
            return False
    return sequence.get("total", 0) >= len(entries)


def dots_acl_list() -> dict:
    raw = exec_in(
        "edge",
        "curl",
        "-fsS",
        "--resolve",
        "edge-dots.demo.test:4443:172.30.1.10",
        "--cacert",
        "/run/demo-certs/ca.crt",
        "--cert",
        "/run/demo-certs/ankah-dots-client.crt",
        "--key",
        "/run/demo-certs/ankah-dots-client.key",
        DOTS_BASE + "/acls",
    )
    return json.loads(raw)


def edge_acls() -> dict:
    return json.loads(exec_in("edge", "curl", "-fsS", "http://172.30.1.10:9100/acls"))


def assert_active_acl() -> None:
    # Instant checks first: the ACL is only active for DOTS_BLOCK_SECONDS.
    rules = edge_acls().get("rules", [])
    check(
        any(
            rule.get("src") == "172.30.0.20/32"
            and rule.get("dst") == "172.30.0.11/32"
            and rule.get("proto") == 6
            and rule.get("port_low") == 80
            for rule in rules
        ),
        "edge has the DOTS ACL for attacker to Ankah",
    )
    data = dots_acl_list()
    names = [acl.get("name") for acl in data.get("ietf-dots-data-channel:acls", {}).get("acl", [])]
    check("ankah-172-30-0-20" in names, "go-dots holds the ankah-172-30-0-20 ACL (read over mTLS)")
    wait_for(
        "Ankah counted a successful DOTS install",
        lambda: scalar('sum(ankah_dots_operations_total{operation="install",result="ok"})') > 0,
        timeout=20,
        interval=1,
    )


def probe_metric(name: str, **labels: str) -> float:
    samples = prom_text("legit-probe", "http://127.0.0.1:9301/metrics")
    return sample_value(samples, name, **labels)


def edge_gate_sample() -> dict[str, float]:
    samples = prom_text("edge", "http://172.30.1.10:9100/metrics")
    return {
        "acls": sample_value(samples, "edge_dots_acls"),
        "withdraws": sample_value(samples, "edge_dots_acl_changes_total", op="withdraw"),
        "rejected": sample_value(samples, "edge_connections_rejected_total", frontend="ankah"),
        "rejected_anubis": sample_value(samples, "edge_connections_rejected_total", frontend="anubis"),
        "accepted": sample_value(samples, "edge_connections_accepted_total", frontend="ankah"),
        "handled": sample_value(samples, "edge_http_requests_total", vhost="ankah.test"),
        "probe": probe_metric("probe_requests_total", target="ankah"),
    }


def wait_for_rejects() -> None:
    """Proves matching connections are closed before the HTTP handler.

    Over a window in which the ACL is active from start to end, connections to
    the Ankah address that the edge accepted must equal the requests its HTTP
    handler saw (one request per connection), and both must stay within what
    the legit probe alone can generate, while rejects keep rising.
    """
    base_challenges = scalar("sum(anubis_challenges_issued)")
    last = None
    for _ in range(3):
        start = edge_gate_sample()
        time.sleep(8)
        end = edge_gate_sample()
        if not (start["acls"] > 0 and end["acls"] > 0 and end["withdraws"] == start["withdraws"]):
            last = "ACL changed during the sampling window"
            continue
        delta = {key: end[key] - start[key] for key in start}
        last = delta
        check(delta["rejected"] >= 5, f"edge rejected {delta['rejected']:.0f} attacker connections to the Ankah address")
        check(delta["rejected_anubis"] == 0, "edge rejected nothing on the Anubis address")
        check(
            abs(delta["handled"] - delta["accepted"]) <= 2,
            f"HTTP handler saw only accepted connections "
            f"(accepted {delta['accepted']:.0f}, handled {delta['handled']:.0f})",
        )
        check(
            delta["accepted"] <= 3 * delta["probe"] + 3,
            f"accepted Ankah connections ({delta['accepted']:.0f}) are bounded by legit probe "
            f"attempts ({delta['probe']:.0f}), far below rejects ({delta['rejected']:.0f})",
        )
        wait_for(
            "Anubis keeps challenging the same attacker",
            lambda: scalar("sum(anubis_challenges_issued)") > base_challenges,
            timeout=20,
            interval=1,
        )
        return
    raise AssertionError(f"no stable ACL window for the reject check; last={last!r}")


def wait_for_legit_probe() -> None:
    """Legit traffic keeps succeeding on both sites, with no new failures."""
    def read(target: str, result: str) -> float:
        return probe_metric("probe_requests_total", target=target, result=result)

    base = {(t, r): read(t, r) for t in ("anubis", "ankah") for r in ("success", "failure")}

    def enough():
        now = {key: read(*key) for key in base}
        failures = sum(now[(t, "failure")] - base[(t, "failure")] for t in ("anubis", "ankah"))
        if failures:
            raise AssertionError(f"legit probe failed {failures:.0f} time(s) during the check")
        return all(now[(t, "success")] > base[(t, "success")] for t in ("anubis", "ankah"))

    wait_for("legit probe succeeds on both sites with no new failures", enough, timeout=45, interval=2)


def assert_backends_clean() -> None:
    attacker = scalar('sum(pi_requests_total{client="attacker"})')
    legit_fastapi = scalar('sum(pi_requests_total{backend="fastapi",client="legit"})')
    legit_django = scalar('sum(pi_requests_total{backend="django",client="legit"})')
    check(attacker == 0, "no attacker request reached either backend")
    check(legit_fastapi > 0 and legit_django > 0, "both backends received legit probe requests")


def attacker_metric(name: str, **labels: str) -> float:
    samples = prom_text("legit-probe", "http://172.30.0.20:9300/metrics")
    return sample_value(samples, name, **labels)


def wait_for_withdraw_and_reentry() -> None:
    """After the ACL is withdrawn, the attacker's own requests reach Ankah again.

    Only the attacker's challenged outcomes for the Ankah target count here;
    the legit probe also reaches that frontend and must not satisfy this.
    """
    # Take the baseline while the ACL is active: attacker requests to Ankah are
    # then reset at the edge, so its challenged count can only rise once the
    # rule is gone. The re-entry window lasts until Ankah escalates again,
    # roughly one threshold's worth of requests.
    wait_for("DOTS ACL is active before the withdraw check",
             lambda: edge_metric("edge_dots_acls") > 0, timeout=60, interval=0.5)
    base = attacker_metric("attacker_requests_completed_total", target="ankah", outcome="challenged")
    base_withdraw = edge_metric("edge_dots_acl_changes_total", op="withdraw")
    wait_for(
        "DOTS withdraw occurs",
        lambda: edge_metric("edge_dots_acl_changes_total", op="withdraw") > base_withdraw,
        timeout=80,
        interval=1,
    )
    wait_for(
        "attacker requests are challenged by Ankah again after the withdraw",
        lambda: attacker_metric(
            "attacker_requests_completed_total", target="ankah", outcome="challenged"
        ) > base,
        timeout=20,
        interval=0.5,
    )


def run_assertions() -> None:
    wait_for("all Prometheus scrape targets are up", all_targets_up, timeout=90, interval=2)
    wait_for("Grafana is healthy and has the DOTS dashboard", grafana_healthy, timeout=60, interval=2)
    wait_for("attacker alternates targets", attacker_alternates, timeout=45, interval=2)
    wait_for("Ankah registered with DOTS", lambda: scalar("ankah_dots_registered") == 1, timeout=60, interval=2)
    wait_for("DOTS ACL is active in the edge", lambda: edge_metric("edge_dots_acls") > 0, timeout=60, interval=1)
    assert_active_acl()
    wait_for_rejects()
    wait_for_legit_probe()
    assert_backends_clean()
    wait_for_withdraw_and_reentry()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--keep", action="store_true", help="leave the clean-run stack running after success")
    parser.add_argument("--use-running", action="store_true", help="check an already running stack")
    args = parser.parse_args()

    started = False
    try:
        if not args.use_running:
            print("resetting demo stack", flush=True)
            compose("down", "-v", "--remove-orphans")
            print("building and starting demo stack", flush=True)
            compose("up", "--build", "-d", "--wait")
            started = True
        run_assertions()
        print("smoke test passed", flush=True)
        return 0
    except Exception as err:
        print(f"smoke test failed: {err}", file=sys.stderr, flush=True)
        if started:
            try:
                compose("ps")
                compose("logs", "--no-color", "--tail", "80")
            except Exception:
                pass
        return 1
    finally:
        if started and not args.keep:
            print("stopping demo stack", flush=True)
            compose("down", "-v", "--remove-orphans")


if __name__ == "__main__":
    raise SystemExit(main())
