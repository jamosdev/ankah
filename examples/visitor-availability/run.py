#!/usr/bin/env python3
"""Run isolated, fixed-arrival visitor-availability comparisons on local Docker."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import http.client
import json
import math
import os
from pathlib import Path
import queue
import resource
import secrets
import subprocess
import sys
import threading
import time

from compose import HERE, ROOT, topology
from report import generate


def command(args, **kwargs):
    return subprocess.run([str(a) for a in args], check=True, **kwargs)


def captured(args):
    return command(args, capture_output=True, text=True).stdout


def fingerprint():
    inventory = command(["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
                        cwd=ROOT, capture_output=True).stdout
    digest = hashlib.sha256()
    for name in sorted(inventory.split(b"\0")):
        path = ROOT / os.fsdecode(name)
        if name and path.is_file():
            data = path.read_bytes()
            mode = b"executable" if path.stat().st_mode & 0o111 else b"file"
            for field in (name, mode, data):
                digest.update(len(field).to_bytes(8, "big"))
                digest.update(field)
    return digest.hexdigest()


def engine(path):
    """Use the selected Docker context, including TCP daemons in Linux CI."""
    process = subprocess.Popen(["docker", "system", "dial-stdio"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    watchdog = threading.Timer(20, process.kill)
    watchdog.start()

    class Connection:
        def makefile(self, *_args, **_kwargs):
            return process.stdout

    try:
        # Closing stdin before the response cancels requests on some daemons.
        process.stdin.write(f"GET {path} HTTP/1.1\r\nHost: docker\r\nConnection: close\r\n\r\n".encode())
        process.stdin.flush()
        response = http.client.HTTPResponse(Connection())
        response.begin()
        body = response.read()
        if response.status != 200:
            raise RuntimeError(f"Docker {path}: {response.status}: {body[:1024]!r}")
        return json.loads(body)
    finally:
        watchdog.cancel()
        process.stdin.close()
        process.stdout.close()
        process.wait(timeout=5)
        process.stderr.close()


class Worker:
    def __init__(self, compose, role, cfg, path):
        self.ready = queue.Queue()
        self.output = path.open("w")
        self.stderr = path.with_suffix(".stderr").open("w")
        self.process = subprocess.Popen([*compose, "exec", "-T", role, "node", "client.cjs", role],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=self.stderr, text=True, bufsize=1)
        self.thread = threading.Thread(target=self.collect, daemon=True)
        self.thread.start()
        self.send(cfg)

    def collect(self):
        for line in self.process.stdout:
            self.output.write(line)
            self.output.flush()
            try:
                row = json.loads(line)
                if row.get("type") in ("ready", "fatal"):
                    self.ready.put(row)
            except ValueError:
                self.ready.put({"type": "fatal", "error": "invalid worker JSON: " + line[:1024]})
        self.ready.put({"type": "fatal", "error": "worker exited before readiness"})

    def send(self, value):
        self.process.stdin.write(json.dumps(value) + "\n")
        self.process.stdin.flush()

    def close(self):
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait()
        self.thread.join(timeout=10)
        self.output.close()
        self.stderr.close()


def sampler(ids, path, stop):
    with path.open("w") as output, ThreadPoolExecutor(max_workers=len(ids)) as pool:
        while not stop.is_set():
            started = time.time()
            row = {"time_ms": started * 1000, "containers": {}}
            futures = {service: pool.submit(engine, f"/containers/{cid}/stats?stream=false&one-shot=true")
                       for service, cid in ids.items()}
            for service, future in futures.items():
                try:
                    raw = future.result()
                    memory = raw["memory_stats"]
                    cache = memory.get("stats", {}).get("inactive_file", memory.get("stats", {}).get("total_inactive_file", 0))
                    row["containers"][service] = {
                        "cpu_ns": raw["cpu_stats"]["cpu_usage"]["total_usage"],
                        "memory_bytes": max(0, memory.get("usage", 0) - cache), "raw": raw}
                except Exception as error:
                    row.setdefault("errors", {})[service] = str(error)
            output.write(json.dumps(row) + "\n")
            output.flush()
            stop.wait(max(0, 1 - (time.time() - started)))


def trial(root, cfg, repeat, images):
    observer_start = resource.getrusage(resource.RUSAGE_SELF)
    cli_start = resource.getrusage(resource.RUSAGE_CHILDREN)
    name = f'{cfg["arm"]}-{cfg["attack"]}-{cfg["attack_rps"]}-r{repeat}'
    path = root / name
    path.mkdir()
    compose_path = path / "compose.json"
    spec = topology(cfg["arm"])
    for service, settings in spec["services"].items():
        settings["image"] = images[service]["tag"]
    compose_path.write_text(json.dumps(spec, indent=2) + "\n")
    project = "ankah-availability-" + secrets.token_hex(5)
    compose = ["docker", "compose", "-p", project, "-f", str(compose_path)]
    manifest = {"config": cfg, "repeat": repeat, "project": project, "errors": [],
                "start_ms": 0, "end_ms": 0,
                "serving_services": [s for s in spec["services"] if s not in ("certs", "visitors", "attacker")]}
    workers, sampling = [], None
    stop = threading.Event()
    print(f"Running {name}", flush=True)
    try:
        command([*compose, "up", "-d", "--no-build", "--pull", "never", "--wait", "--wait-timeout", "240"])
        inspections = json.loads(captured(["docker", "inspect", *captured([*compose, "ps", "-aq"]).split()]))
        (path / "containers.json").write_text(json.dumps(inspections, indent=2) + "\n")
        for item in inspections:
            service = item["Config"]["Labels"]["com.docker.compose.service"]
            if item["Image"] != images[service]["id"]:
                raise RuntimeError("image identity changed for " + service)
        ids = {item["Config"]["Labels"]["com.docker.compose.service"]: item["Id"] for item in inspections
               if item["State"]["Running"]}
        if cfg["arm"] != "direct":
            (path / "executable.sha256").write_text(captured([*compose, "exec", "-T", "ankah", "sha256sum", "/usr/local/bin/ankah"]))
        sampling = threading.Thread(target=sampler, args=(ids, path / "resources.jsonl", stop), daemon=True)
        sampling.start()
        workers = [Worker(compose, role, cfg, path / (role + ".jsonl")) for role in ("visitors", "attacker")]
        for worker in workers:
            ready = worker.ready.get(timeout=90)
            if ready["type"] != "ready":
                raise RuntimeError(ready)
        start = time.time() * 1000 + 2000
        manifest.update(start_ms=start, end_ms=start + cfg["duration_s"] * 1000)
        for worker in workers:
            worker.send({"start_ms": start})
        for worker in workers:
            code = worker.process.wait(timeout=cfg["duration_s"] + cfg["timeout_ms"] / 1000 + 90)
            if code:
                raise RuntimeError(f"worker exited {code}, see {worker.stderr.name}")
    except Exception as error:
        manifest["errors"].append(repr(error))
        print(f"FAILED {name}: {error}", file=sys.stderr, flush=True)
    finally:
        for worker in workers:
            worker.close()
        stop.set()
        if sampling:
            sampling.join(timeout=30)
        # Logs and final metrics are collected before removing this trial only.
        for service in manifest["serving_services"]:
            result = subprocess.run([*compose, "logs", "--no-color", "--no-log-prefix", service],
                                    capture_output=True, text=True)
            (path / (service + ".log")).write_text(result.stdout + result.stderr)
        if cfg["arm"] != "direct":
            result = subprocess.run([*compose, "exec", "-T", "ankah", "sh", "-c",
                'wget -qO- --header "Authorization: Bearer $(cat /run/demo-certs/ankah-dashboard-token)" http://127.0.0.1:9101/metrics'],
                capture_output=True, text=True)
            (path / "gateway.prom").write_text(result.stdout + result.stderr)
        if cfg["arm"] == "dots":
            for route in ("metrics", "acls"):
                result = subprocess.run([*compose, "exec", "-T", "edge", "curl", "-fsS", "http://172.30.1.10:9100/" + route],
                                        capture_output=True, text=True)
                (path / ("edge." + route)).write_text(result.stdout + result.stderr)
        (path / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
        try:
            command([*compose, "down", "-v", "--remove-orphans"], timeout=90)
        except Exception as error:
            manifest["errors"].append("cleanup: " + repr(error))
        observer_end = resource.getrusage(resource.RUSAGE_SELF)
        cli_end = resource.getrusage(resource.RUSAGE_CHILDREN)
        manifest["observer_resources"] = {
            "host_harness_cpu_seconds": observer_end.ru_utime + observer_end.ru_stime - observer_start.ru_utime - observer_start.ru_stime,
            "docker_cli_cpu_seconds": cli_end.ru_utime + cli_end.ru_stime - cli_start.ru_utime - cli_start.ru_stime,
            "host_harness_process_lifetime_peak_rss_bytes": observer_end.ru_maxrss * 1024,
            "docker_daemon_cpu": "not isolated from other host workloads"}
        (path / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", choices=("smoke", "reference"), default="reference")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--arms", nargs="+", choices=("direct", "ankah", "dots"), default=["direct", "ankah", "dots"])
    parser.add_argument("--attacks", nargs="+", choices=("none", "unsolved", "solved"), default=["none", "unsolved", "solved"])
    parser.add_argument("--rates", nargs="+", type=int, default=[40, 200])
    parser.add_argument("--duration", type=int)
    parser.add_argument("--repeats", type=int)
    parser.add_argument("--work-factor", type=int, default=200000)
    parser.add_argument("--visitor-rps", type=float)
    parser.add_argument("--new-slo-ms", type=int, default=5000)
    parser.add_argument("--returning-slo-ms", type=int, default=1000)
    args = parser.parse_args()
    duration = args.duration if args.duration is not None else 300 if args.profile == "reference" else 8
    repeats = args.repeats if args.repeats is not None else 5 if args.profile == "reference" else 1
    visitor_rate = args.visitor_rps if args.visitor_rps is not None else 1 if args.profile == "reference" else .25
    if not 1 <= args.work_factor <= 2000000 or not 3 <= duration <= 900 or repeats < 1 or \
            not math.isfinite(visitor_rate) or visitor_rate <= 0 or duration * visitor_rate < 1 or \
            any(r <= 0 for r in args.rates) or min(args.new_slo_ms, args.returning_slo_ms) <= 0:
        parser.error("work factor 1..2000000, duration 3..900, positive repeats, visitor rate and attack rates required")
    if any(len(values) != len(set(values)) for values in (args.arms, args.attacks, args.rates)):
        parser.error("duplicate arms, attacks, or rates are not independent repeats; use --repeats")
    root = args.output.resolve()
    if root == ROOT or ROOT in root.parents:
        parser.error("keep generated artifacts outside the source checkout")
    root.mkdir(parents=True, exist_ok=False)
    metadata = {"profile": args.profile, "command": [sys.executable, *sys.argv], "python_version": sys.version,
        "source_fingerprint": fingerprint(),
        "commit": captured(["git", "-C", ROOT, "rev-parse", "HEAD"]).strip(),
        "working_tree": captured(["git", "-C", ROOT, "status", "--short"]),
        "build_configuration": "Release; strict warnings; bundled runtime dependencies; static Linux; WebAssembly enabled",
        "docker_info": engine("/info"), "docker_version": engine("/version"),
        "compose_version": captured(["docker", "compose", "version"]),
        "host_platform": captured(["uname", "-a"]),
        "host_cpu": Path("/proc/cpuinfo").read_text(), "host_memory": Path("/proc/meminfo").read_text(),
        "host_load": Path("/proc/loadavg").read_text(),
        "source_addresses": {"attacker": "172.30.0.20", "visitors": "172.30.0.21"},
        "same_host": True, "protocol": "HTTP/1.1 without TLS", "duration_s": duration, "repeats": repeats,
        "expected_trials": [f"{arm}-{attack}-{rate}-r{repeat}"
            for repeat in range(1, repeats + 1) for arm in args.arms for attack in args.attacks
            for rate in ([0] if attack == "none" else args.rates)],
        "reference_protocol": args.profile == "reference" and duration == 300 and repeats == 5 and
            set(args.arms) == {"direct", "ankah", "dots"} and set(args.attacks) == {"none", "unsolved", "solved"} and
            set(args.rates) == {40, 200} and visitor_rate == 1 and args.work_factor == 200000}
    (root / "metadata.json").write_text(json.dumps(metadata, indent=2) + "\n")
    # Preserve dirty tracked changes and new benchmark sources, so a hash of
    # an uncommitted development run is not its only reproducibility record.
    with (root / "source.patch").open("wb") as patch:
        patch.write(command(["git", "diff", "--binary", "HEAD"], cwd=ROOT, capture_output=True).stdout)
        untracked = captured(["git", "-C", ROOT, "ls-files", "--others", "--exclude-standard", str(HERE)]).splitlines()
        for name in untracked:
            path = Path(name)
            if path.suffix not in (".py", ".cjs", ".json", ".md") and not path.name.startswith("Dockerfile"):
                continue
            result = subprocess.run(["git", "diff", "--no-index", "--binary", "--", "/dev/null", str(path)],
                                    cwd=ROOT, capture_output=True)
            if result.returncode not in (0, 1):
                raise RuntimeError(result.stderr.decode())
            patch.write(result.stdout)
    # Build all selected components once. Each run receives fresh containers,
    # networks, credentials, session/statistics paths, and database state.
    build_spec = topology("dots" if "dots" in args.arms else "ankah" if "ankah" in args.arms else "direct")
    build_path = root / "build-compose.json"
    build_path.write_text(json.dumps(build_spec, indent=2) + "\n")
    print("Building benchmark images; log: " + str(root / "build.log"), flush=True)
    with (root / "build.log").open("w") as build_log:
        command(["docker", "compose", "-p", "ankah-availability-build", "-f", build_path, "build"],
                stdout=build_log, stderr=subprocess.STDOUT)
    images = {}
    run_tag = secrets.token_hex(8)
    for service, settings in build_spec["services"].items():
        image_id = captured(["docker", "image", "inspect", settings["image"], "--format", "{{.Id}}"]).strip()
        tag = "ankah-availability-frozen:" + run_tag + "-" + service
        command(["docker", "tag", image_id, tag])
        images[service] = {"id": image_id, "tag": tag}
    metadata["images"] = images
    (root / "metadata.json").write_text(json.dumps(metadata, indent=2) + "\n")
    try:
        for repeat in range(1, repeats + 1):
            # Rotate deployment order across repeats; never run arms together.
            arms = args.arms[(repeat - 1) % len(args.arms):] + args.arms[:(repeat - 1) % len(args.arms)]
            for attack in args.attacks:
                for rate in [0] if attack == "none" else args.rates:
                    for arm in arms:
                        cfg = {"arm": arm, "attack": attack, "attack_rps": rate,
                            "duration_s": duration, "visitor_rps": visitor_rate, "n": args.work_factor,
                            "origin": "http://ankah.test", "timeout_ms": 30000, "attack_timeout_ms": 5000,
                            "new_slo_ms": args.new_slo_ms, "returning_slo_ms": args.returning_slo_ms}
                        trial(root, cfg, repeat, images)
                        generate(root)
    finally:
        results = generate(root)
    if not results["trials"] or any(not row["valid_load_comparison"] for row in results["trials"]):
        raise SystemExit("Incomplete/invalid comparisons retained. See summary.json and trial logs.")
    if args.profile == "smoke":
        for row in results["trials"]:
            if row["config"]["arm"] != "direct" and row["config"]["attack"] == "none":
                visitor_requests = sum(row[phase].get(actor, 0) for phase in ("setup_wire_requests", "measured_wire_requests")
                                       for actor in ("new", "returning"))
                if visitor_requests > 40:
                    raise SystemExit("Smoke visitor wire requests exceed the initial client burst; revise the isolated request budget")
            if row["config"]["attack"] == "none" and any(c["successful"] != c["offered"] for c in row["cohorts"].values()):
                raise SystemExit("No-attack smoke visits failed; see retained response diagnostics.")
            if row["config"]["arm"] != "direct" and row["config"]["attack"] == "unsolved" and row["attack"]["backend_completed"]:
                raise SystemExit("Unsolved attacker reached protected backend")
            if row["attack"]["successful_ids_missing_from_backend"]:
                raise SystemExit("Successful attacker IDs missing from backend log")
            if row["config"]["arm"] == "dots" and row["config"]["attack"] == "unsolved":
                observed = row["dots_observations"]
                if not (observed["edge_acl_installs"] and observed["edge_rejected_connections"]):
                    raise SystemExit("DOTS smoke did not observe an ACL install and upstream rejection")
    print(root / "summary.md", flush=True)


if __name__ == "__main__":
    main()
