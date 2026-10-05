"""Local TLS fixture for browser smoke checks; no production hosts or credentials."""
import argparse
import hashlib
import json
from pathlib import Path
import signal
import sys
import threading

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('executable', type=Path)
parser.add_argument('assets', type=Path)
parser.add_argument('metadata', help='JSON output path, or - for stdout with stdin-controlled lifetime')
parser.add_argument('--bundle', type=Path)
parser.add_argument('--no-dashboard', action='store_true')
parser.add_argument('--routes', action='store_true', help='include isolated browser upstream policies')
args = parser.parse_args()
executable, assets = args.executable.resolve(), args.assets.resolve()
sys.argv = [__file__, str(executable), str(Path(__file__).resolve().parents[1] / 'build_static_bundle.py'),
            str(assets)]
from host_browser_test import BrowserHosts

if args.routes:
    from route_policy_test import RoutePolicies
    fixture = RoutePolicies()
else:
    fixture = BrowserHosts()
stopped = threading.Event()
for signum in (signal.SIGINT, signal.SIGTERM):
    signal.signal(signum, lambda *_: stopped.set())
try:
    fixture.setUp()
    fixture.stop()
    for host in fixture.hosts:
        path = fixture.root / (host + '.conf')
        content = path.read_text().replace('public-origin=https://' + host,
                                           f'public-origin=https://{host}:{fixture.port}')
        if args.bundle:
            content = content.replace('static-bundle=bundle', 'static-bundle=' + str(args.bundle.resolve()))
        path.write_text(content)
    fixture.config = [value.replace('public-origin=https://status.test',
                                     f'public-origin=https://status.test:{fixture.port}')
                      for value in fixture.config]
    if args.no_dashboard:
        fixture.config = [value for value in fixture.config if not value.startswith(
            ('dashboard-token-file=', 'no-stats-file='))] + ['no-dashboard=true']
    fixture.start()
    metadata = {'port': fixture.port, 'dashboard': not args.no_dashboard,
                'executable_sha256': hashlib.sha256(executable.read_bytes()).hexdigest()}
    if args.metadata == '-':
        print(json.dumps(metadata), flush=True)
        sys.stdin.read(1)
    else:
        destination = Path(args.metadata)
        destination.parent.mkdir(parents=True, exist_ok=True)
        temporary = destination.with_suffix('.tmp')
        temporary.write_text(json.dumps(metadata) + '\n')
        temporary.replace(destination)
        stopped.wait()
finally:
    fixture.doCleanups()
