"""Isolated routed-browser, policy-pool and protocol POST regressions."""
import http.client
import http.server
import os
from pathlib import Path
import shutil
import sys
import socket
import ssl
import subprocess
import threading
import time
import unittest

import host_browser_test as browser
from http2_client import HEADERS
from process_support import gateway_command


class RoutePolicies(browser.BrowserHosts):
    def setUp(self):
        super().setUp()
        self.stop()
        self.admin_records = []
        self.admin_cookie_fields = []
        self.admin_seen = []
        self.admin_condition = threading.Condition()
        owner = self

        class Admin(http.server.BaseHTTPRequestHandler):
            protocol_version = 'HTTP/1.1'

            def log_message(self, *_):
                pass

            def handle_request(self):
                with owner.admin_condition:
                    owner.admin_seen.append((self.command, self.path))
                    owner.admin_condition.notify_all()
                if self.path.startswith('/admin/hold'):
                    owner.release.wait(10)
                if self.headers.get('Transfer-Encoding') == 'chunked':
                    chunks = []
                    while True:
                        line = self.rfile.readline()
                        if not line:
                            return
                        amount = int(line.split(b';')[0], 16)
                        if not amount:
                            if self.rfile.readline() != b'\r\n':
                                return
                            break
                        data = self.rfile.read(amount)
                        if len(data) != amount or self.rfile.read(2) != b'\r\n':
                            return
                        chunks.append(data)
                    body = b''.join(chunks)
                else:
                    amount = int(self.headers.get('Content-Length', '0'))
                    body = self.rfile.read(amount)
                    if len(body) != amount:
                        return
                owner.admin_records.append((self.command, self.path, dict(self.headers), body))
                owner.admin_cookie_fields.append(self.headers.get_all('Cookie', []))
                if self.path == '/admin/drop':
                    self.close_connection = True
                    return
                status = 200
                if self.path.startswith('/oidc/') and self.command == 'POST' and body != b'signed=synthetic':
                    status = 403
                if self.path == '/admin/session':
                    status = 302
                self.send_response(status)
                self.send_header('Content-Length', str(len(body)))
                self.send_header('Cache-Control', 'private, no-store')
                if status == 302:
                    self.send_header('Location', '/oidc/login?next=%2Fadmin%2F')
                    self.send_header('Set-Cookie', 'session=opaque; Secure; HttpOnly; SameSite=None; Path=/')
                    self.send_header('Set-Cookie', 'csrf=opaque; Secure; Path=/admin/')
                self.end_headers()
                try:
                    if self.command != 'HEAD':
                        self.wfile.write(body)
                except OSError:
                    pass
                self.close_connection = True

            do_GET = do_HEAD = do_POST = handle_request

        self.admin = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Admin)
        threading.Thread(target=self.admin.serve_forever, daemon=True).start()
        self.addCleanup(self.admin.server_close)
        self.addCleanup(self.admin.shutdown)
        self.addCleanup(self.release.set)
        self.profile = '\n'.join([
            f'upstream=127.0.0.1:{self.admin.server_port}', 'body-limit=65536', 'concurrency=2',
            'connect-timeout-ms=5000', 'upload-timeout-ms=10000', 'response-timeout-ms=15000', ''])
        (self.root / 'admin-policy.conf').write_text(self.profile)
        path = self.root / 'submit.test.conf'
        self.host_config = path.read_text() + '\n'.join([
            'route=admin-get GET /admin/ policy=admin match=prefix query=allow challenge=on',
            'route=admin-head HEAD /admin/ policy=admin match=prefix query=allow challenge=on',
            'route=admin-post POST /admin/ policy=admin match=prefix query=allow challenge=on',
            'route=login GET /oidc/login policy=admin query=allow challenge=on',
            'route=callback POST /oidc/callback policy=admin',
            'route=logout POST /oidc/backchannel-logout policy=admin',
            'route=locked POST /admin/strict policy=admin',
            'upstream-policy=admin admin-policy.conf', ''])
        path.write_text(self.host_config)
        self.start()
        self.addCleanup(self.preserve_failure)

    def preserve_failure(self):
        destination = os.environ.get('ANKAH_ROUTE_FAILURE_DIR')
        if not destination or not self._outcome or not self._outcome.result:
            return
        result = self._outcome.result
        if any(test is self for test, _ in result.failures + result.errors):
            self.stop()
            root = Path(destination) / self._testMethodName
            root.mkdir(parents=True, exist_ok=True)
            for path in self.root.iterdir():
                if path.is_file():
                    shutil.copy2(path, root / path.name)

    def request(self, path='/', method='GET', host='submit.test', headers=None,
                body=b'', protocol='h1', address='127.0.0.1'):
        if protocol != 'h2' or len(body) <= 16384:
            return super().request(path, method, host, headers, body, protocol, address)
        client = browser.H2(address, self.port, host)
        try:
            client.request(1, method, path, host, len(body), end_stream=False, headers=headers or {})
            offset = 0
            deadline = time.monotonic() + 8
            while offset < len(body) and 1 not in client.ended and 1 not in client.resets:
                if time.monotonic() >= deadline:
                    self.fail('HTTP/2 upload stalled')
                sent = client.send_data(1, body[offset:], end_stream=True)
                offset += sent
                if not sent:
                    client.receive()
            client.wait_for(lambda: 1 in client.ended, 8, 'streamed browser response')
            return int(client.response_status[1]), client.headers[1], bytes(client.bodies.get(1, b''))
        finally:
            client.close()

    def proof(self, protocol='h1', host='submit.test'):
        sid, challenge, cookie = self.challenge('/ankah/unlock', protocol=protocol, host=host)
        return self.complete(sid, challenge, cookie, protocol=protocol, host=host)[0]

    def split_routed_cookies(self, target):
        sid, challenge, cookie = self.challenge(target, protocol='h2')
        result = self.request('/ankah/answer/' + sid + '?answer=' + str(browser.solve(challenge)),
                              'POST', protocol='h2')
        self.assertEqual(result[0], 200, (result[0], result[1], result[2][:256]))
        result = self.request('/ankah/finish/' + sid + '?', protocol='h2',
                              headers=[('cookie', 'existing=synthetic'), ('cookie', cookie)])
        self.assertEqual(result[0], 303, (result[0], result[1], result[2][:256]))
        self.assertEqual(result[1]['location'], target)
        passed = result[1]['set-cookie'].split(';')[0]
        fields = [('cookie', 'existing=synthetic'), ('x-cookie-control', 'kept'),
                  ('cookie', passed), ('cookie', 'application=fixture')]
        result = self.request(target, headers=fields, protocol='h2')
        self.assertEqual(result[0], 200, (result[0], result[1], result[2][:256]))
        self.assertEqual(self.admin_records[-1][1], target)
        self.assertEqual(self.admin_cookie_fields[-1],
                         ['existing=synthetic; ' + passed + '; application=fixture'])
        self.assertEqual(self.admin_records[-1][2]['x-cookie-control'], 'kept')
        self.assertEqual(self.records, [])

    def case_split_cookies_admin(self):
        self.split_routed_cookies('/admin/?view=mail&empty=')

    def case_split_cookies_login(self):
        self.split_routed_cookies('/oidc/login?next=%2Fadmin%2F')

    def case_split_cookies_overflow(self):
        result = self.request('/oidc/callback', 'POST', protocol='h2', body=b'signed=synthetic',
                              headers=[('cookie', 'a=' + 'x' * 2046),
                                       ('cookie', 'b=' + 'y' * 2046)])
        self.assertEqual(result[0], 400, (result[0], result[1], result[2][:256]))
        self.assertEqual(self.admin_records, [])
        self.assertEqual(self.admin_seen, [])

    def case_subresource_preserves_document_cookie(self):
        sid, challenge, cookie = self.challenge('/admin/?view=mail', protocol='h2')
        result = self.request('/admin/icon.png', protocol='h2',
                              headers={'Cookie': cookie, 'Sec-Fetch-Dest': 'image'})
        self.assertEqual(result[0], 428, (result[0], result[1], result[2][:256]))
        self.assertNotIn('set-cookie', result[1])
        self.assertEqual(self.admin_seen, [])
        passed, target = self.complete(sid, challenge, cookie, protocol='h2')
        self.assertEqual(target, '/admin/?view=mail')
        result = self.request('/admin/icon.png', protocol='h2',
                              headers={'Cookie': passed, 'Sec-Fetch-Dest': 'image'})
        self.assertEqual(result[0], 200, (result[0], result[1], result[2][:256]))

    def barrier(self, client, token=b'barrier!'):
        client.send_frame(6, 0, 0, token)
        client.wait_for(lambda: token in client.pings, 5, 'stream close barrier')

    def case_browser_paths_and_exact_ownership(self):
        for protocol, address in [('h1', '127.0.0.1'), ('h2', '::1')]:
            options = dict(protocol=protocol, address=address)
            target = '/oidc/login?next=%2Fadmin%2F&state=opaque+value'
            sid, challenge, cookie = self.challenge(target, **options)
            passed, returned = self.complete(sid, challenge, cookie, **options)
            self.assertEqual(returned, target)
            self.assertEqual(self.request(target, headers={'Cookie': passed}, **options)[0], 200)
            self.assertEqual(self.admin_records[-1][1], target)
            self.assertEqual(self.admin_records[-1][2]['X-Forwarded-Host'], 'submit.test')
            self.assertEqual(self.admin_records[-1][2]['X-Forwarded-Proto'], 'https')
            for target in ('/administer/', '/admin', '/admin/../oidc/callback', '/admin/%2e%2e/',
                           '/admin/a/..', '/admin/./x', '/admin//x', '/admin/\\x'):
                self.assertEqual(self.request(target, headers={'Cookie': passed}, **options)[0], 404, target)
            self.assertEqual(self.request('/admin/strict', headers={'Cookie': passed}, **options)[0], 405)
            self.assertEqual(self.request('/admin/strict?x=1', 'POST', **options)[0], 404)
            self.assertEqual(self.request('/oidc/login/child', **options)[0], 404)
            self.assertEqual(self.request('/v1/smtp?', 'POST', **options)[0], 404)
            self.assertEqual(self.request('/admin/?x=1', method='HEAD', headers={'Cookie': passed}, **options)[0], 200)
            self.assertEqual(self.request('/admin/?x=1', method='HEAD', **options)[::2], (428, b''))
            other = self.proof(protocol, 'other.test')
            self.assertEqual(self.request('/admin/', headers={'Cookie': other}, **options)[0], 428)
        self.assertEqual(self.records, [])

    def case_writes_and_oidc_never_capture_or_replay(self):
        payload = b'private-write-sentinel'
        for protocol in ('h1', 'h2'):
            self.assertEqual(self.request('/admin/write', 'POST', body=payload, protocol=protocol)[0], 428)
            self.assertEqual(self.admin_records, [])
        passed = self.proof()
        for protocol in ('h1', 'h2'):
            self.assertEqual(self.request('/admin/write', 'POST', headers={'Cookie': passed},
                                          body=payload, protocol=protocol)[0], 200)
            for target in ('/oidc/callback', '/oidc/backchannel-logout'):
                before = len(self.admin_records)
                self.assertEqual(self.request(target, 'POST', body=b'signed=synthetic', protocol=protocol)[0], 200)
                self.assertEqual(len(self.admin_records), before + 1)
                self.assertEqual(self.admin_records[-1][3], b'signed=synthetic')
                self.assertEqual(self.request(target, 'POST', body=b'invalid-token-sentinel', protocol=protocol)[0], 403)
            before = len(self.admin_records)
            self.assertEqual(self.request('/admin/drop', headers={'Cookie': passed}, protocol=protocol)[0], 502)
            self.assertEqual(len(self.admin_records), before + 1)
        self.assertEqual(self.records, [])
        self.stop()
        for path in self.root.iterdir():
            if path.name.startswith('sessions.') or path.suffix == '.log':
                data = path.read_bytes()
                for sentinel in (payload, b'invalid-token-sentinel', b'signed=synthetic'):
                    self.assertNotIn(sentinel, data, path.name)

    def case_policy_body_limits_and_streaming(self):
        for protocol in ('h1', 'h2'):
            self.assertEqual(self.request('/oidc/callback', 'POST', body=b'x' * 65536, protocol=protocol)[0], 403)
            before = len(self.admin_seen)
            self.assertEqual(self.request('/oidc/callback', 'POST', body=b'x' * 65537, protocol=protocol)[0], 413)
            self.assertEqual(len(self.admin_seen), before)
            self.assertEqual(self.request('/v1/smtp', 'POST', body=b'x' * 65537,
                headers={'Authorization': 'Bearer backend-test'}, protocol=protocol)[0], 202)
        client = browser.H2('127.0.0.1', self.port, 'submit.test')
        try:
            client.request(1, 'POST', '/oidc/callback', 'submit.test', end_stream=False)
            client.send_data(1, b'signed=synthetic', end_stream=True)
            client.wait_for(lambda: 1 in client.ended, 5, 'lengthless callback')
            self.assertEqual(client.response_status[1], b'200')
            client.request(3, 'POST', '/oidc/callback', 'submit.test', end_stream=False)
            client.send_body(3, 65537)
            client.wait_for(lambda: 3 in client.ended, 5, 'lengthless limit')
            self.assertEqual(client.response_status[3], b'413')
        finally:
            client.close()

    def case_shared_admin_pool_is_separate_from_submission(self):
        passed = self.proof()
        client = browser.H2('127.0.0.1', self.port, 'submit.test')
        try:
            for stream in (1, 3):
                client.request(stream, 'GET', '/admin/hold', 'submit.test', 0, headers={'cookie': passed})
            with self.admin_condition:
                self.assertTrue(self.admin_condition.wait_for(lambda: len(self.admin_seen) == 2, 5))
            code, headers, _ = self.request('/oidc/callback', 'POST', body=b'signed=synthetic')
            self.assertEqual(code, 503)
            self.assertEqual(headers['retry-after'], '1')
            self.assertEqual(self.request('/admin/')[0], 428)
            self.assertEqual(self.request('/v1/smtp', 'POST', headers={'Authorization': 'Bearer backend-test'})[0], 202)
            self.assertEqual(self.request(host='status.test')[0], 200)
            client.send_frame(3, 0, 1, (8).to_bytes(4, 'big'))
            self.barrier(client)
            self.assertEqual(self.request('/oidc/callback', 'POST', body=b'signed=synthetic')[0], 200)
            client.send_frame(3, 0, 3, (8).to_bytes(4, 'big'))
            self.barrier(client, b'released')
            # Repeated completion on one connection must return its pool slot.
            for stream in (5, 7, 9, 11):
                client.request(stream, 'POST', '/oidc/callback', 'submit.test', 16,
                               end_stream=False)
                client.send_data(stream, b'signed=synthetic', end_stream=True)
                client.wait_for(lambda: stream in client.ended, 5, 'reused policy slot')
                self.assertEqual(client.response_status[stream], b'200')
        finally:
            client.close()
            self.release.set()

    def case_submission_pool_does_not_block_admin(self):
        passed = self.proof()
        client = browser.H2('127.0.0.1', self.port, 'submit.test')
        try:
            for stream in (1, 3):
                client.request(stream, 'POST', '/v1/smtp', 'submit.test', 1, end_stream=False,
                    headers={'authorization': 'Bearer backend-test', 'idempotency-key': 'hold'})
                client.send_data(stream, b'x', end_stream=True)
            self.assertTrue(self.holding.wait(5))
            self.barrier(client)
            self.assertEqual(self.request('/v1/smtp', 'POST', headers={'Authorization': 'Bearer backend-test'})[0], 503)
            self.assertEqual(self.request('/oidc/callback', 'POST', body=b'signed=synthetic')[0], 200)
            self.assertEqual(self.request('/admin/', headers={'Cookie': passed})[0], 200)
            for stream in (1, 3):
                client.send_frame(3, 0, stream, (8).to_bytes(4, 'big'))
            self.barrier(client, b'released')
            self.assertEqual(self.request('/v1/smtp', 'POST', headers={'Authorization': 'Bearer backend-test'})[0], 202)
        finally:
            client.close()
            self.release.set()

    def case_chunked_h1_policy_limit(self):
        context = ssl.create_default_context(cafile=str(self.root / 'submit.test.pem'))
        for amount, expected in ((65536, 403), (65537, 413)):
            before = len(self.admin_records)
            with context.wrap_socket(socket.create_connection(('127.0.0.1', self.port), timeout=5),
                                     server_hostname='submit.test') as connection:
                head = b'POST /oidc/callback HTTP/1.1\r\nHost: submit.test\r\nTransfer-Encoding: chunked\r\n\r\n'
                body = f'{amount:x}\r\n'.encode() + b'x' * amount + b'\r\n0\r\n\r\n'
                connection.sendall(head + body)
                response = http.client.HTTPResponse(connection)
                response.begin()
                self.assertEqual(response.status, expected)
                response.read()
            self.assertEqual(len(self.admin_records), before + (expected == 403))

    def case_backend_headers_preserved(self):
        passed = self.proof()
        context = ssl.create_default_context(cafile=str(self.root / 'submit.test.pem'))
        with context.wrap_socket(socket.create_connection(('127.0.0.1', self.port), timeout=5),
                                 server_hostname='submit.test') as connection:
            connection.sendall(('GET /admin/session HTTP/1.1\r\nHost: submit.test\r\nCookie: ' + passed + '\r\n\r\n').encode())
            response = http.client.HTTPResponse(connection)
            response.begin()
            self.assertEqual(response.status, 302)
            self.assertEqual(response.getheader('Location'), '/oidc/login?next=%2Fadmin%2F')
            self.assertEqual(len([v for k, v in response.getheaders() if k.lower() == 'set-cookie']), 2)
            self.assertEqual(response.getheader('Cache-Control'), 'private, no-store')
            response.read()
        class HeaderClient(browser.H2):
            def __init__(self, *args):
                from hpack import Decoder
                self.raw_decoder = Decoder()
                self.raw_headers = []
                super().__init__(*args)
            def process_frame(self, kind, flags, stream, payload):
                if kind == HEADERS:
                    self.raw_headers.extend(self.raw_decoder.decode(payload))
                super().process_frame(kind, flags, stream, payload)
        client = HeaderClient('::1', self.port, 'submit.test')
        try:
            client.request(1, 'GET', '/admin/session', 'submit.test', 0, headers={'cookie': passed})
            client.wait_for(lambda: 1 in client.ended, 5, 'redirect response')
            self.assertEqual(client.response_status[1], b'302')
            self.assertEqual(len([v for k, v in client.raw_headers if k == 'set-cookie']), 2)
            self.assertIn(('location', '/oidc/login?next=%2Fadmin%2F'), client.raw_headers)
        finally:
            client.close()

    def case_completed_h2_timer_keeps_connection_available(self):
        self.stop()
        (self.root / 'admin-policy.conf').write_text(self.profile.replace('upload-timeout-ms=10000', 'upload-timeout-ms=100')
            .replace('response-timeout-ms=15000', 'response-timeout-ms=300'))
        self.start()
        client = browser.H2('127.0.0.1', self.port, 'submit.test')
        try:
            self.barrier(client)
            client.request(1, 'POST', '/admin/strict', 'submit.test', 0)
            client.wait_for(lambda: 1 in client.ended, 2, 'bodyless route completion')
            self.assertEqual(client.response_status[1], b'200')
            end = time.monotonic() + .5
            while time.monotonic() < end:
                client.receive(.05)
            client.request(3, 'POST', '/oidc/callback', 'submit.test', 16, end_stream=False)
            client.send_data(3, b'signed=synthetic', end_stream=True)
            client.wait_for(lambda: 3 in client.ended, 2, 'connection reuse past completed deadline')
            self.assertEqual(client.response_status[3], b'200')
        finally:
            client.close()

    def case_policy_deadlines_and_backend_recovery(self):
        self.stop()
        (self.root / 'admin-policy.conf').write_text(self.profile.replace('upload-timeout-ms=10000', 'upload-timeout-ms=400')
            .replace('response-timeout-ms=15000', 'response-timeout-ms=600'))
        self.start()
        passed = self.proof()
        context = ssl.create_default_context(cafile=str(self.root / 'submit.test.pem'))
        with context.wrap_socket(socket.create_connection(('127.0.0.1', self.port), timeout=3),
                                 server_hostname='submit.test') as connection:
            start = time.monotonic()
            connection.sendall(('GET /admin/hold HTTP/1.1\r\nHost: submit.test\r\nCookie: ' + passed + '\r\n\r\n').encode())
            response = connection.recv(4096)
            self.assertTrue(not response or response.startswith(b'HTTP/1.1 408'), response)
            self.assertGreater(time.monotonic() - start, .4)
            self.assertLess(time.monotonic() - start, 2)
        client = browser.H2('127.0.0.1', self.port, 'submit.test')
        try:
            start = time.monotonic()
            client.request(1, 'GET', '/admin/hold', 'submit.test', 0, headers={'cookie': passed})
            client.wait_for(lambda: 1 in client.resets or 1 in client.ended, 2, 'absolute response deadline')
            self.assertGreater(time.monotonic() - start, .4)
            self.assertLess(time.monotonic() - start, 2)
            if 1 in client.ended and 1 not in client.resets:
                self.assertEqual(client.response_status[1], b'408')
            client.request(3, 'POST', '/oidc/callback', 'submit.test', 16, end_stream=False)
            client.send_data(3, b'signed=synthetic', end_stream=True)
            client.wait_for(lambda: 3 in client.ended, 2, 'reuse after deadline')
            self.assertEqual(client.response_status[3], b'200')
        finally:
            client.close()
        for protocol in ('h1', 'h2'):
            self.assertEqual(self.request('/v1/smtp', 'POST', headers={'Authorization': 'Bearer backend-test'}, protocol=protocol)[0], 202)
            self.assertEqual(self.request(host='status.test', protocol=protocol)[0], 200)
        self.stop()
        with socket.socket() as unavailable:
            unavailable.bind(('127.0.0.1', 0))
            unused_port = unavailable.getsockname()[1]
            (self.root / 'admin-policy.conf').write_text(self.profile.replace(str(self.admin.server_port), str(unused_port)))
            self.start()
            self.assertEqual(self.request('/oidc/callback', 'POST', body=b'signed=synthetic')[0], 502)
            self.assertEqual(self.request('/v1/smtp', 'POST', headers={'Authorization': 'Bearer backend-test'})[0], 202)
            self.stop()
        (self.root / 'admin-policy.conf').write_text(self.profile)
        self.start()
        self.assertEqual(self.request('/oidc/callback', 'POST', body=b'signed=synthetic')[0], 200)

    def case_invalid_configuration_fails_startup(self):
        self.stop()
        path = self.root / 'submit.test.conf'
        invalid = [
            'route=missing GET /missing policy=absent',
            'route=duplicate GET /extra query=allow query=reject',
            'route=bad GET /bad unknown=on',
            'route=prefix GET /missing-slash match=prefix',
            'route=reserved GET /ankah/ match=prefix policy=admin',
            'route=static GET / match=prefix policy=admin',
            'route=duplicate GET /admin/ match=prefix policy=admin',
            'upstream-policy=admin admin-policy.conf',
            'upstream-policy=default admin-policy.conf',
            'upstream-policy=invalid missing-policy.conf',
        ]
        for extra in invalid:
            path.write_text(self.host_config + extra + '\n')
            result = subprocess.run(gateway_command(browser.EXE, ['--config', str(self.root / 'gateway.conf')]),
                                    cwd=self.root, capture_output=True, timeout=15)
            self.assertNotEqual(result.returncode, 0, (extra, result.stdout, result.stderr))
        path.write_text(self.host_config)
        for extra in ('body-limit=1', 'concurrency=0', 'response-timeout-ms=1',
                      'route=recursive GET /', 'upstream-policy=recursive admin-policy.conf'):
            (self.root / 'admin-policy.conf').write_text(self.profile + extra + '\n')
            result = subprocess.run(gateway_command(browser.EXE, ['--config', str(self.root / 'gateway.conf')]),
                                    cwd=self.root, capture_output=True, timeout=15)
            self.assertNotEqual(result.returncode, 0, (extra, result.stdout, result.stderr))


def suite(names=None):
    names = names or [name for name in dir(RoutePolicies) if name.startswith('case_')]
    return unittest.TestSuite(RoutePolicies(name) for name in names)


if __name__ == '__main__':
    result = unittest.TextTestRunner(verbosity=2).run(suite(sys.argv[1:]))
    raise SystemExit(not result.wasSuccessful())
