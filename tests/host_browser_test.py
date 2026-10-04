"""Host-bound browser services with independent exact streaming routes."""
import gzip
import hashlib
import http.client
import http.server
import json
import os
from pathlib import Path
import re
import socket
import ssl
import subprocess
import struct
import sys
import tempfile
import threading
import time
import unittest
import urllib.parse

import brotli
from hpack import Decoder
from http2_client import Client, DATA, HEADERS
from process_support import start_gateway, windows_path
from static_test import solve
from dashboard_test import dashboard_code

EXE, BUILDER, ASSETS = sys.argv[1:4]
sys.argv = [sys.argv[0], *sys.argv[4:]]
TOKEN = 'a4' * 32


class H2(Client):
    def __init__(self, *args):
        self.bodies = {}
        self.headers = {}
        self.decoder = Decoder()
        super().__init__(*args)

    def process_frame(self, kind, flags, stream_id, payload):
        if kind == DATA:
            self.bodies.setdefault(stream_id, bytearray()).extend(payload)
        if kind == HEADERS:
            self.headers.setdefault(stream_id, {}).update(self.decoder.decode(payload))
        super().process_frame(kind, flags, stream_id, payload)


class BrowserHosts(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.records = []
        self.holding = threading.Event()
        self.release = threading.Event()
        self.addCleanup(self.release.set)
        owner = self

        class Backend(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                self.send_response(200)
                self.send_header('Content-Length', '6')
                self.end_headers()
                self.wfile.write(b'status')

            def do_POST(self):
                if self.headers.get('Authorization') != 'Bearer backend-test':
                    self.send_response(401)
                    self.send_header('Content-Length', '0')
                    self.end_headers()
                    return
                if self.headers.get('Idempotency-Key') == 'hold':
                    owner.holding.set()
                    owner.release.wait(10)
                body = self.rfile.read(int(self.headers.get('Content-Length', '0')))
                owner.records.append(body)
                self.send_response(202)
                self.send_header('Content-Length', '0')
                self.end_headers()

        self.backend = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Backend)
        threading.Thread(target=self.backend.serve_forever, daemon=True).start()
        self.addCleanup(self.backend.server_close)
        self.addCleanup(self.backend.shutdown)
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            self.port = sock.getsockname()[1]
        for host in ('status.test', 'submit.test', 'other.test'):
            subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                            '-subj', '/CN=' + host, '-addext', 'subjectAltName=DNS:' + host,
                            '-keyout', str(self.root / (host + '.key')),
                            '-out', str(self.root / (host + '.pem')), '-days', '1'],
                           check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        (self.root / 'secret').write_text('5a' * 32)
        (self.root / 'token').write_text(TOKEN)
        source = self.root / 'public'
        source.mkdir()
        self.landing = b'<html><a href="https://status.test">Service status</a></html>' + b' ' * 4096
        (source / 'index.html').write_bytes(self.landing)
        subprocess.run([sys.executable, BUILDER, '--project-root', str(self.root),
                        '--source', 'public', '--url-prefix', '/', '--output', str(self.root / 'bundle')],
                       check=True, capture_output=True)
        self.hosts = ['submit.test', 'other.test']
        for host in self.hosts:
            content = [f'public-origin=https://{host}', f'tls-cert={host}.pem',
                       f'tls-key={host}.key', 'static-bundle=bundle', 'static-challenge=true']
            if host == 'submit.test':
                content += [f'upstream=127.0.0.1:{self.backend.server_port}',
                            'route=submission POST /v1/smtp', 'body-limit=25165824', 'concurrency=2',
                            'connect-timeout-ms=5000', 'upload-timeout-ms=105000',
                            'response-timeout-ms=115000']
            (self.root / (host + '.conf')).write_text('\n'.join(content) + '\n')
        assets = windows_path(ASSETS) if os.environ.get('ANKAH_TEST_WINDOWS_PATHS') == '1' else ASSETS
        self.config = ['listen=[::]:' + str(self.port), 'public-origin=https://status.test',
                       f'upstream=127.0.0.1:{self.backend.server_port}', 'secret-file=secret',
                       'tls-cert=status.test.pem', 'tls-key=status.test.key', 'assets-dir=' + assets,
                       'dashboard-token-file=token', 'session-state-file=sessions', 'no-stats-file=true',
                       'allow-prefix=/', 'http3=off']
        self.process = None
        self.log = (self.root / 'gateway.log').open('w+b')
        self.addCleanup(self.log.close)
        self.addCleanup(self.stop)
        self.start()

    def start(self):
        (self.root / 'gateway.conf').write_text('\n'.join(self.config +
            ['virtual-host=' + host + '.conf' for host in self.hosts]) + '\n')
        self.process = start_gateway(EXE, ['--config', str(self.root / 'gateway.conf')],
                                     cwd=self.root, stdout=self.log, stderr=self.log)
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                self.log.seek(0)
                self.fail(self.log.read().decode(errors='replace'))
            try:
                with socket.create_connection(('127.0.0.1', self.port), timeout=.1):
                    return
            except OSError:
                time.sleep(.02)
        self.fail('gateway startup timeout')

    def stop(self):
        if self.process and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(15)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(5)
                self.fail('gateway shutdown timeout')

    def restart(self):
        self.stop()
        self.start()

    def request(self, path='/', method='GET', host='submit.test', headers=None,
                body=b'', protocol='h1', address='127.0.0.1'):
        headers = headers or {}
        if protocol == 'h2':
            client = H2(address, self.port, host)
            try:
                client.request(1, method, path, host, len(body), end_stream=not body, headers=headers)
                if body:
                    client.send_data(1, body, end_stream=True)
                client.wait_for(lambda: 1 in client.ended, 8, 'browser response')
                return int(client.response_status[1]), client.headers[1], bytes(client.bodies.get(1, b''))
            finally:
                client.close()
        context = ssl.create_default_context(cafile=str(self.root / (host + '.pem')))
        context.set_alpn_protocols(['http/1.1'])
        with context.wrap_socket(socket.create_connection((address, self.port), timeout=8),
                                 server_hostname=host) as connection:
            head = f'{method} {path} HTTP/1.1\r\nHost: {host}\r\nContent-Length: {len(body)}\r\n'
            head += ''.join(f'{k}: {v}\r\n' for k, v in headers.items())
            connection.sendall(head.encode() + b'\r\n' + body)
            reply = http.client.HTTPResponse(connection, method=method)
            reply.begin()
            return reply.status, {k.lower(): v for k, v in reply.getheaders()}, reply.read()

    def challenge(self, path='/', **options):
        status, headers, body = self.request(path, **options)
        self.assertEqual(status, 428, (status, headers, body[:256]))
        sid = re.search(rb"data-session='([a-f0-9]{32})'", body).group(1).decode()
        challenge = re.search(rb"data-challenge='([^']+)'", body).group(1).decode()
        cookie = headers['set-cookie'].split(';')[0]
        self.assertIn('Secure', headers['set-cookie'])
        self.assertNotIn('Domain=', headers['set-cookie'])
        return sid, challenge, cookie

    def complete(self, sid, challenge, cookie, **options):
        self.assertEqual(self.request(f'/ankah/answer/{sid}?answer={solve(challenge)}',
                                     'POST', **options)[0], 200)
        status, headers, _ = self.request('/ankah/finish/' + sid + '?', headers={'Cookie': cookie}, **options)
        self.assertEqual(status, 303)
        return headers['set-cookie'].split(';')[0], headers['location']

    def test_challenge_assets_completion_and_status(self):
        for protocol, address in [('h1', '127.0.0.1'), ('h2', '::1')]:
            options = dict(protocol=protocol, address=address)
            sid, challenge, cookie = self.challenge(**options)
            self.assertEqual(self.request('/ankah/qr/' + sid + '.png', **options)[1]['content-type'], 'image/png')
            phone = self.request('/ankah/solve/' + sid, **options)
            self.assertIn(challenge.encode(), phone[2])
            for asset in re.findall(rb"(?:src|data-worker|data-wasm)='(/ankah/[^']+)'", phone[2]):
                self.assertEqual(self.request(asset.decode(), **options)[0], 200)
            passed, target = self.complete(sid, challenge, cookie, **options)
            self.assertEqual(target, '/')
            result = self.request(headers={'Cookie': passed}, **options)
            self.assertEqual((result[0], result[2]), (200, self.landing))
            self.assertEqual(result[1]['cache-control'], 'private, no-cache')
            self.assertEqual(self.request(host='status.test', **options)[0], 200)

    def test_particle_assets_on_every_challenge_host(self):
        # Fresh process with the dashboard disabled proves decorative assets are
        # public challenge resources, independent of dashboard authentication.
        self.config = [value for value in self.config if not value.startswith(
            ('dashboard-token-file=', 'no-stats-file='))] + ['no-dashboard=true']
        self.restart()
        for host, protocol, language in [('status.test', 'h1', 'en'),
                                         ('submit.test', 'h2', 'ja'),
                                         ('other.test', 'h1', 'es')]:
            options = dict(host=host, protocol=protocol, headers={'Accept-Language': language})
            status, _, body = self.request('/ankah/unlock', **options)
            self.assertEqual(status, 428, (status, body[:256]))
            sid = re.search(rb"data-session='([a-f0-9]{32})'", body).group(1).decode()
            phone = self.request('/ankah/solve/' + sid, **options)
            self.assertEqual(phone[0], 200)
            for page in (body, phone[2]):
                self.assertIn(b'<div id=particles aria-hidden=true>', page)
                for attribute, filename, content_type in [
                        ('data-particles', 'particles.min.js', 'application/javascript'),
                        ('data-particle-config', 'particlejs.json', 'application/json')]:
                    asset = re.search((attribute + "='([^']+)'").encode(), page).group(1).decode()
                    self.assertRegex(asset, r'^/ankah/assets/[a-f0-9]{64}/' + re.escape(filename) + '$')
                    result = self.request(asset, **options)
                    self.assertEqual(result[0], 200)
                    self.assertTrue(result[1]['content-type'].startswith(content_type))
                    self.assertEqual(result[1]['cache-control'], 'public, max-age=31536000, immutable')
                    self.assertEqual(hashlib.sha256(result[2]).hexdigest(), asset.split('/')[3])
            self.assertIn("style-src 'unsafe-inline'", phone[1]['content-security-policy'])
        self.assertEqual(self.records, [])

    def test_cross_host_and_restart_binding(self):
        sid, challenge, cookie = self.challenge()
        passed, _ = self.complete(sid, challenge, cookie)
        self.assertEqual(self.request(headers={'Cookie': cookie})[0], 200)
        self.assertEqual(self.request('/ankah/finish/' + sid + '?extra', headers={'Cookie': cookie})[0], 403)
        self.hosts.reverse()
        self.restart()
        self.assertEqual(self.request(headers={'Cookie': cookie})[0], 200)
        for host in ('other.test', 'status.test'):
            for path in ('/ankah/qr/' + sid + '.png', '/ankah/solve/' + sid):
                self.assertEqual(self.request(path, host=host)[0], 404)
            self.assertEqual(self.request('/ankah/finish/' + sid, host=host, headers={'Cookie': cookie})[0], 403)
            self.assertEqual(self.request('/ankah/answer/' + sid + '?answer=' + str(solve(challenge)),
                                         'POST', host=host)[0], 403)
        for proof in (cookie, passed):
            self.assertEqual(self.request(host='other.test', headers={'Cookie': proof})[0], 428)
        self.assertEqual(self.records, [])

    def test_static_representation_authorization(self):
        sid, challenge, cookie = self.challenge()
        passed, _ = self.complete(sid, challenge, cookie)
        for protocol in ('h1', 'h2'):
            for encoding, decode in [('identity', lambda b: b), ('gzip', gzip.decompress), ('br', brotli.decompress)]:
                headers = {'Cookie': passed, 'Accept-Encoding': encoding}
                code, meta, body = self.request(headers=headers, protocol=protocol)
                self.assertEqual(code, 200)
                self.assertEqual(decode(body), self.landing)
                self.assertEqual(self.request(headers={**headers, 'If-None-Match': meta['etag']}, protocol=protocol)[0], 304)
                self.assertEqual(self.request(headers={'If-None-Match': meta['etag']}, protocol=protocol)[0], 428)
            self.assertEqual(self.request(method='HEAD', headers={'Cookie': passed}, protocol=protocol)[0], 200)
            self.assertEqual(self.request(headers={'Cookie': passed, 'Range': 'bytes=0-9'}, protocol=protocol)[2], self.landing[:10])
            self.assertEqual(self.request(headers={'Range': 'bytes=0-9'}, protocol=protocol)[0], 428)
            self.assertEqual(self.request(method='POST', protocol=protocol)[0], 405)

    def test_unlock_dashboard_and_shared_authentication(self):
        auth = {'Authorization': 'Bearer ' + TOKEN}
        for host, protocol in [('status.test', 'h1'), ('submit.test', 'h2'), ('other.test', 'h1')]:
            options = dict(host=host, protocol=protocol)
            sid, challenge, cookie = self.challenge('/ankah/unlock?return=/ankah/unlock', **options)
            passed, target = self.complete(sid, challenge, cookie, **options)
            self.assertEqual(target, '/ankah/unlock')
            newer = self.challenge('/ankah/unlock', headers={'Cookie': passed}, **options)
            self.assertNotEqual(newer[0], sid)
            self.assertEqual(self.request('/ankah-admin/', headers={'Cookie': passed}, **options)[0], 200)
            self.assertEqual(self.request('/ankah-admin/stats/live', **options)[0], 401)
            self.assertEqual(self.request('/ankah-admin/stats/live', headers=auth, **options)[0], 200)
        self.assertEqual(self.request('/ankah-admin/settings/disable', 'POST', headers=auth)[0], 204)
        for host in ('status.test', 'submit.test', 'other.test'):
            self.assertEqual(self.request('/ankah-admin/', host=host)[0], 410)

    def test_command_line_proof_stays_on_host(self):
        for protocol in ('h1', 'h2'):
            code, headers, _ = self.request(headers={'User-Agent': 'curl/8.0'}, protocol=protocol)
            self.assertEqual(code, 302)
            challenge = headers['location'].split('run-ankah-challenge-')[1]
            code, _, script = self.request('/ankah/challenge/' + challenge, protocol=protocol)
            self.assertEqual(code, 200)
            self.assertIn(b'https://submit.test', script)
            self.assertNotIn(b'https://status.test', script)
            path = '/ankah/open?' + urllib.parse.urlencode({'challenge': challenge, 'answer': solve(challenge)})
            self.assertEqual(self.request(path, 'POST', host='other.test', protocol=protocol)[0], 403)
            code, headers, _ = self.request(path, 'POST', protocol=protocol)
            self.assertEqual(code, 200)
            self.assertEqual(self.request(headers={'Cookie': headers['set-cookie'].split(';')[0]}, protocol=protocol)[0], 200)

    def test_submission_bypasses_challenge_and_capture(self):
        for protocol in ('h1', 'h2'):
            for target in ('/v1/smtp?', '/v1/smtp?a=1', '/v1/%73mtp', '/v1/smtp/extra'):
                self.assertEqual(self.request(target, 'POST', protocol=protocol)[0], 404)
            self.assertEqual(self.request('/v1/smtp', protocol=protocol)[0], 405)
            self.assertEqual(self.request('/v1/smtp', 'POST', protocol=protocol)[0], 401)
            payload = b'ankah_continue=0123456789abcdef0123456789abcdef'
            self.assertEqual(self.request('/v1/smtp', 'POST', body=payload,
                                         headers={'Authorization': 'Bearer backend-test'}, protocol=protocol)[0], 202)
        self.assertEqual(self.records, [payload, payload])
        self.assertEqual(self.request('/ankah-admin/', 'POST', body=payload)[0], 405)
        auth = {'Authorization': 'Bearer ' + TOKEN}
        code, _, body = self.request('/ankah-admin/stats/live', headers=auth)
        self.assertEqual(code, 200)
        self.assertEqual(json.loads(body)['gauges']['saved_posts'], 0)

    def test_browser_routes_do_not_consume_submission_capacity(self):
        clients = [H2('127.0.0.1', self.port, 'submit.test') for _ in range(3)]
        try:
            for client in clients[:2]:
                client.request(1, 'POST', '/v1/smtp', 'submit.test', 1, end_stream=False,
                               headers={'Authorization': 'Bearer backend-test', 'Idempotency-Key': 'hold'})
                client.ping(b'accepted')
                client.wait_for(lambda: b'accepted' in client.pings, 5, 'submission admission')
            self.assertTrue(self.holding.wait(5))
            clients[2].request(1, 'POST', '/v1/smtp', 'submit.test', 0, end_stream=True)
            clients[2].wait_for(lambda: 1 in clients[2].ended, 5, 'submission capacity')
            self.assertEqual(clients[2].response_status[1], b'503')
            self.assertEqual(self.request('/ankah/unlock')[0], 428)
            self.assertEqual(self.request('/ankah-admin/stats/live', headers={'Authorization': 'Bearer ' + TOKEN})[0], 200)
            self.assertEqual(self.request(host='status.test')[0], 200)
        finally:
            self.release.set()
            for client in clients:
                client.close()

    def test_unlock_rejects_foreign_returns_and_keeps_selected_origin(self):
        for target in ('//foreign.test/', '/\\foreign.test/', 'https://foreign.test/', '/'):
            status = self.request('/ankah/unlock?return=' + target)[0]
            self.assertEqual(status, 428 if target == '/' else 400)
        status, _, body = self.request(method='HEAD', headers={'Referer': 'https://status.test/'})
        self.assertEqual(status, 405)
        self.assertEqual(body, b'')
        self.assertEqual(self.request('/index.html')[0], 428)

    def test_private_dashboard_does_not_create_public_routes(self):
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            port = sock.getsockname()[1]
        self.config.append('dashboard-listen=127.0.0.1:' + str(port))
        self.restart()
        self.assertEqual(self.request('/ankah-admin/')[0], 404)
        self.assertEqual(self.request('/ankah/unlock')[0], 428)
        client = http.client.HTTPConnection('127.0.0.1', port, timeout=5)
        try:
            client.request('GET', '/stats/live', headers={'Authorization': 'Bearer ' + TOKEN})
            response = client.getresponse()
            self.assertEqual(response.status, 200)
            response.read()
        finally:
            client.close()

    def test_shared_authenticator_session(self):
        code = dashboard_code(int(time.time()) // 30, TOKEN)
        status, _, body = self.request('/ankah-admin/auth/login', 'POST',
                                       headers={'X-Ankah-Code': code}, protocol='h2')
        self.assertEqual(status, 200)
        auth = {'Authorization': 'Bearer ' + json.loads(body)['token']}
        self.assertEqual(self.request('/ankah-admin/stats/live', host='other.test', headers=auth)[0], 200)
        self.assertEqual(self.request('/ankah-admin/auth/logout', 'POST', host='status.test', headers=auth)[0], 204)
        self.assertEqual(self.request('/ankah-admin/stats/live', headers=auth)[0], 401)

    def test_legacy_snapshot_binds_only_primary_host(self):
        sid, challenge, cookie = self.challenge('/ankah/unlock', host='status.test')
        self.complete(sid, challenge, cookie, host='status.test')
        self.stop()
        header = struct.Struct('=8sIIIIQQ')
        candidates = list(self.root.glob('sessions.[01]'))
        self.assertTrue(candidates)
        path = max(candidates, key=lambda p: header.unpack_from(p.read_bytes())[5])
        data = path.read_bytes()
        magic, version, request_size, record_size, count, generation, _ = header.unpack_from(data)
        self.assertEqual(version, 2)
        self.assertEqual(count, 1)
        # This fixture has one bodyless session. Version 1 predates the host field.
        record = data[header.size:header.size + record_size - 256]
        legacy = header.pack(magic, 1, request_size, len(record), count, generation + 1,
                             header.size + len(record) + 32) + record
        path.write_bytes(legacy + hashlib.sha256(legacy).digest())
        self.start()
        self.assertEqual(self.request('/ankah/finish/' + sid, host='status.test', headers={'Cookie': cookie})[0], 303)
        self.assertEqual(self.request('/ankah/finish/' + sid, headers={'Cookie': cookie})[0], 403)
        self.assertEqual(self.request(headers={'Cookie': cookie})[0], 428)

    def test_configuration_rejects_conflicting_routes_and_invalid_bundles(self):
        self.stop()
        path = self.root / 'submit.test.conf'
        original = path.read_text()
        invalid = [original + 'route=reserved GET /ankah/unlock\n',
                   original + 'route=reserved GET /ankah-admin/stats/live\n',
                   original + 'route=reserved GET /index.html\n',
                   original + 'static-challenge=false\n',
                   original.replace('static-challenge=true', 'static-challenge=perhaps'),
                   original.replace('static-bundle=bundle', 'static-bundle=missing'),
                   original.replace('static-bundle=bundle\n', '')]
        for content in invalid:
            path.write_text(content)
            self.process = start_gateway(EXE, ['--config', str(self.root / 'gateway.conf')],
                                         cwd=self.root, stdout=self.log, stderr=self.log)
            self.assertNotEqual(self.process.wait(10), 0, content)
        path.write_text(original.replace('static-challenge=true', 'static-challenge=false'))
        self.start()
        self.assertEqual(self.request()[0], 200)
        self.assertEqual(self.request('/ankah/unlock')[0], 428)

    def test_custom_dashboard_and_disabled_configuration(self):
        self.config.append('dashboard-public-route=/operator/')
        self.restart()
        self.assertEqual(self.request('/operator/stats/live', headers={'Authorization': 'Bearer ' + TOKEN})[0], 200)
        self.assertEqual(self.request('/ankah-admin/')[0], 404)
        self.config = [s for s in self.config if not s.startswith(('dashboard-', 'no-stats-file='))]
        self.config.append('no-dashboard=true')
        self.restart()
        self.assertEqual(self.request('/operator/')[0], 404)
        self.assertEqual(self.request('/ankah-admin/')[0], 404)
        self.assertEqual(self.request('/ankah/unlock')[0], 428)


if __name__ == '__main__':
    unittest.main()
