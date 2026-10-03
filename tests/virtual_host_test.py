"""Isolated exact-route TLS/Unix gateway regression tests; synthetic data only."""
import hashlib
import http.client
import http.server
import json
import os
from pathlib import Path
import signal
import socket
import socketserver
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest

from http2_client import Client, DATA, HEADERS, request_headers

LIMIT = 25165824
EXE, ASSETS = sys.argv[1:3]
del sys.argv[1:3]

class H2(Client):
    def __init__(self, address, port, name):
        self.bodies = {}
        super().__init__(address, port, server_name=name)

    def process_frame(self, kind, flags, stream_id, payload):
        if kind == DATA:
            self.bodies.setdefault(stream_id, bytearray()).extend(payload)
        super().process_frame(kind, flags, stream_id, payload)

class UnixServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True

class Gateway(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='ankah-host-')
        self.root = Path(self.temp.name)
        self.records, self.receipts = [], {}
        self.revoked = False
        self.started = threading.Event()
        self.release = threading.Event()
        owner = self
        class Backend(http.server.BaseHTTPRequestHandler):
            protocol_version = 'HTTP/1.1'
            def log_message(self, *_): pass
            def reply(self, status, body):
                self.send_response(status)
                self.send_header('Content-Length', str(len(body)))
                self.send_header('Content-Type', 'application/json')
                self.send_header('Retry-After', '7')
                self.end_headers()
                self.wfile.write(body)
                self.close_connection = True
            def do_GET(self): self.reply(200, b'status')
            def do_POST(self):
                owner.started.set()
                auth = self.headers.get('Authorization')
                if auth != 'Bearer sentinel-secret' or owner.revoked:
                    self.reply(401, b'{"error":"unauthorized"}')
                    return
                if self.headers.get('Idempotency-Key') == 'hold':
                    owner.release.wait(10)
                chunks = []
                if self.headers.get('Transfer-Encoding') == 'chunked':
                    while True:
                        line = self.rfile.readline()
                        if not line: return
                        n = int(line.split(b';')[0], 16)
                        if not n:
                            if self.rfile.readline() != b'\r\n': return
                            break
                        data = self.rfile.read(n)
                        if len(data) != n or self.rfile.read(2) != b'\r\n': return
                        chunks.append(data)
                else:
                    n = int(self.headers.get('Content-Length', '0'))
                    data = self.rfile.read(n)
                    if len(data) != n: return
                    chunks.append(data)
                body = b''.join(chunks)
                if self.headers.get('Idempotency-Key') == 'real-duration': time.sleep(10)
                owner.records.append((dict(self.headers), len(body), hashlib.sha256(body).hexdigest()))
                if self.headers.get('Idempotency-Key') == 'interim':
                    for _ in range(20):
                        try: self.wfile.write(b'HTTP/1.1 103 Early Hints\r\nLink: </fixed>\r\n\r\n')
                        except OSError: return
                        time.sleep(.1)
                    self.close_connection = True
                    return
                if self.headers.get('Idempotency-Key') == 'partial':
                    self.wfile.write(b'HTTP/1.1 202 Accepted\r\nContent-Length: 100\r\n\r\npartial')
                    self.close_connection = True
                    return
                if self.headers.get('Idempotency-Key') == 'drop':
                    self.close_connection = True
                    return
                key = self.headers.get('Idempotency-Key')
                receipt = json.dumps({'sha256': hashlib.sha256(body).hexdigest()}).encode()
                duplicate = key in owner.receipts
                owner.receipts[key] = receipt
                self.reply(200 if duplicate else 202, receipt)
        self.unix = UnixServer(str(self.root/'submission.sock'), Backend)
        self.tcp = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Backend)
        for server in (self.unix, self.tcp):
            threading.Thread(target=server.serve_forever, daemon=True).start()
        for name in ('status.test', 'submit.test'):
            subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes',
                            '-subj',f'/CN={name}','-keyout',str(self.root/(name+'.key')),
                            '-out',str(self.root/(name+'.pem')),'-days','1'],check=True,
                           stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        (self.root/'secret').write_text('5a'*32)
        with socket.socket() as sock:
            sock.bind(('127.0.0.1',0)); self.port = sock.getsockname()[1]
        self.host_config = '\n'.join([
            'public-origin=https://submit.test', 'tls-cert=submit.test.pem',
            'tls-key=submit.test.key', f'upstream=unix:{self.root}/submission.sock',
            'route=submission POST /v1/smtp', f'body-limit={LIMIT}', 'concurrency=2',
            'connect-timeout-ms=5000', 'upload-timeout-ms=105000',
            'response-timeout-ms=115000', ''])
        (self.root/'host.conf').write_text(self.host_config)
        (self.root/'gateway.conf').write_text('\n'.join([
            'listen=[::]:'+str(self.port), 'public-origin=https://status.test',
            f'upstream=127.0.0.1:{self.tcp.server_port}', 'secret-file=secret',
            f'assets-dir={ASSETS}', 'tls-cert=status.test.pem', 'tls-key=status.test.key',
            'http3=off', 'no-dashboard=true', 'no-session-state-file=true',
            'allow-prefix=/', 'virtual-host=host.conf', 'max-connections=64',
            'max-h2-streams=32', 'upload-queue-bytes=524288',
            'request-queue-bytes=4194304', 'response-queue-bytes=8388608',
            'log-unknown-languages=unknown.log', '']))
        self.log = (self.root/'gateway.log').open('w+')
        self.proc = subprocess.Popen([EXE,'--config',str(self.root/'gateway.conf')],
                                     cwd=self.root, stdout=self.log, stderr=self.log)
        end = time.monotonic()+5
        while time.monotonic()<end:
            if self.proc.poll() is not None:
                self.log.seek(0); self.fail(self.log.read())
            try:
                with socket.create_connection(('127.0.0.1',self.port),timeout=.1): break
            except OSError: time.sleep(.01)
        else: self.fail('startup timeout')

    def tearDown(self):
        self.release.set()
        self.proc.terminate()
        try: self.proc.wait(5)
        except subprocess.TimeoutExpired: self.proc.kill(); self.proc.wait()
        self.log.close()
        for server in (self.unix,self.tcp): server.shutdown(); server.server_close()
        self.temp.cleanup()

    def tls(self, name='submit.test', address='127.0.0.1'):
        context = ssl._create_unverified_context()
        return context.wrap_socket(socket.create_connection((address,self.port),timeout=6),server_hostname=name)

    def request(self, target='/v1/smtp', method='POST', body=b'', headers=(), name='submit.test', address='127.0.0.1'):
        with self.tls(name, address) as sock:
            head = f'{method} {target} HTTP/1.1\r\nHost: {name}\r\n'.encode()
            if not any(k.lower() in ('content-length','transfer-encoding') for k,v in headers):
                head += f'Content-Length: {len(body)}\r\n'.encode()
            head += b''.join(f'{k}: {v}\r\n'.encode() for k,v in headers)
            sock.sendall(head+b'\r\n')
            try: sock.sendall(body)
            except (OSError,ssl.SSLError): pass
            reply = http.client.HTTPResponse(sock); reply.begin()
            return reply.status, dict(reply.getheaders()), reply.read()

    def auth(self, key='key'):
        return [('Authorization','Bearer sentinel-secret'),('Idempotency-Key',key),
                ('Cookie','ankah_sid=0123456789abcdef0123456789abcdef; ankah_pass=synthetic'),
                ('Content-Type','multipart/form-data; boundary=sentinel-boundary')]

    def test_literal_routing_and_isolation(self):
        for address in ('127.0.0.1','::1'):
            self.assertEqual(self.request('/', 'GET', name='status.test',address=address)[0],200)
            self.assertEqual(self.request(headers=self.auth(),address=address)[0],202 if address=='127.0.0.1' else 200)
        before=len(self.records)
        self.started.clear()
        for target in ('/v1/smtp?','/v1/smtp?a=1','/v1/%73mtp','/v1/smtp/', '/v1/./smtp','/v1/x/../smtp','/v1/smtp/child','/ankah/continue','/ankah-admin/','/ankah/healthz'):
            self.assertEqual(self.request(target,headers=self.auth())[0],404,target)
        self.assertEqual(self.request(method='GET')[0],405)
        for headers, expected in [([('Host','submit.test')],400),
                                  ([('Authorization','one'),('Authorization','two')],400),
                                  ([('Connection','Authorization')],400),
                                  ([('X-Ankah-Internal-Host','status.test')],400),
                                  ([('Content-Length',str(LIMIT+1))],413)]:
            self.assertEqual(self.request(headers=headers)[0],expected)
        with self.tls('status.test') as sock:
            sock.sendall(b'POST /v1/smtp HTTP/1.1\r\nHost: submit.test\r\nContent-Length: 0\r\n\r\n')
            r=http.client.HTTPResponse(sock);r.begin();self.assertEqual(r.status,421)
        self.assertEqual(len(self.records),before)
        self.assertFalse(self.started.is_set(), "rejected request contacted submission backend")

    def test_receipt_auth_and_no_replay(self):
        body=b'--sentinel-boundary\r\nContent-Disposition: form-data; name="message"\r\n\r\nsentinel-body\r\n--sentinel-boundary--\r\n'
        self.assertEqual(self.request(body=body)[::2],(401,b'{"error":"unauthorized"}'))
        first=self.request(body=body,headers=self.auth())
        second=self.request(body=body,headers=self.auth())
        self.assertEqual((first[0],second[0]),(202,200));self.assertEqual(first[2],second[2])
        self.assertEqual(first[1]['Retry-After'],'7')
        self.assertEqual(self.records[-1][2],hashlib.sha256(body).hexdigest())
        self.assertEqual(self.records[-1][0]['Content-Type'],self.auth()[-1][1])
        continuation=b'ankah_continue=0123456789abcdef0123456789abcdef'
        self.assertEqual(self.request(body=continuation,headers=self.auth('continue'))[0],202)
        self.assertEqual(self.records[-1][2],hashlib.sha256(continuation).hexdigest())
        self.revoked=True
        self.assertEqual(self.request(body=body,headers=self.auth())[0],401)
        self.revoked=False
        self.assertEqual(self.request(body=body,headers=self.auth('drop'))[0],502)
        self.assertEqual(sum(r[0]['Idempotency-Key']=='drop' for r in self.records),1)
        for path in self.root.iterdir():
            if path.suffix in ('.log',) or path.name in ('ankah.sessions','ankah.stats'):
                data=path.read_bytes()
                for sentinel in (b'sentinel-secret',b'sentinel-body',b'sentinel-boundary',first[2]):
                    self.assertNotIn(sentinel,data)

    def test_limits_h1(self):
        body=b'x'*LIMIT
        self.assertEqual(self.request(body=body,headers=self.auth('length'))[0],202)
        chunk=lambda b: f'{len(b):x}\r\n'.encode()+b+b'\r\n0\r\n\r\n'
        self.assertEqual(self.request(body=chunk(body),headers=self.auth('chunk')+[('Transfer-Encoding','chunked')])[0],202)
        before=len(self.records)
        self.assertEqual(self.request(body=chunk(body+b'x'),headers=self.auth('over')+[('Transfer-Encoding','chunked')])[0],413)
        self.assertEqual(len(self.records),before)

    def test_h2_streaming(self):
        for address in ('127.0.0.1','::1'):
            h=H2(address,self.port,'submit.test')
            try:
                h.request(1,'POST','/v1/smtp','submit.test',end_stream=False,
                          headers=dict(self.auth(address)))
                h.send_body(1,1024,end_stream=False)
                self.assertTrue(self.started.wait(2),'lengthless upload buffered before backend connection')
                h.end_stream(1)
                h.wait_for(lambda:1 in h.ended,5,'receipt')
                self.assertEqual(h.response_status[1],b'202')
                self.assertEqual(self.records[-1][1:],(1024,hashlib.sha256(b'x'*1024).hexdigest()))
            finally:h.close()
        h=H2('127.0.0.1',self.port,'submit.test')
        try:
            for stream_id,target in enumerate(('/v1/smtp?', '/v1/%73mtp', '/v1/smtp/',
                                               '/v1/./smtp', '/v1/smtp/child', '/ankah/continue')):
                sid=2*stream_id+1
                h.request(sid,'POST',target,'submit.test',0)
                h.wait_for(lambda:sid in h.ended,5,'literal rejection')
                self.assertEqual(h.response_status[sid],b'404')
        finally:h.close()
        h=H2('127.0.0.1',self.port,'submit.test')
        try:
            h.request(1,'POST','/v1/smtp','status.test',0)
            h.wait_for(lambda:1 in h.ended,5,'mismatch')
            self.assertEqual(h.response_status[1],b'421')
        finally:h.close()

    def test_concurrency_cancel_and_status(self):
        stalled=[]
        try:
            for _ in range(2):
                sock=self.tls();stalled.append(sock)
                sock.sendall(b'POST /v1/smtp HTTP/1.1\r\nHost: submit.test\r\nContent-Length: 100\r\nAuthorization: Bearer sentinel-secret\r\nIdempotency-Key: hold\r\n\r\nx')
            self.assertTrue(self.started.wait(2));time.sleep(.1)
            result=self.request(headers=self.auth())
            self.assertEqual(result[0],503);self.assertEqual(result[1]['Retry-After'],'1')
            self.assertEqual(self.request('/', 'GET', name='status.test')[0],200)
        finally:
            for sock in stalled:sock.close()
            self.release.set()
        time.sleep(.1)
        self.assertEqual(self.request(headers=self.auth())[0],202)

    def restart(self, config=None):
        self.proc.terminate(); self.proc.wait(5)
        if config is not None: (self.root/'host.conf').write_text(config)
        self.proc = subprocess.Popen([EXE,'--config',str(self.root/'gateway.conf')],
                                     cwd=self.root, stdout=self.log, stderr=self.log)
        end=time.monotonic()+5
        while time.monotonic()<end:
            if self.proc.poll() is not None:
                self.log.seek(0);self.fail(self.log.read())
            try:
                with socket.create_connection(('127.0.0.1',self.port),timeout=.1):return
            except OSError:time.sleep(.01)
        self.fail('restart timeout')

    def test_upstream_failures_and_tcp(self):
        original=self.root/'submission.sock'
        original.rename(self.root/'saved.sock')
        self.assertEqual(self.request(headers=self.auth())[0],502)
        with socket.socket(socket.AF_UNIX) as dead:
            dead.bind(str(original))
            self.assertEqual(self.request(headers=self.auth())[0],502)
        original.unlink();(self.root/'saved.sock').rename(original)
        if os.geteuid()!=0:
            original.chmod(0)
            self.assertEqual(self.request(headers=self.auth())[0],502)
            original.chmod(0o600)
        self.assertEqual(self.records,[])
        self.restart(self.host_config.replace(f'unix:{original}',f'127.0.0.1:{self.tcp.server_port}'))
        self.assertEqual(self.request(body=b'tcp',headers=self.auth())[0],202)

    def test_h2_exact_limit_and_over(self):
        for declared in (True,False):
            for amount in (LIMIT,LIMIT+1):
                before=len(self.records)
                h=H2('127.0.0.1',self.port,'submit.test')
                try:
                    h.request(1,'POST','/v1/smtp','submit.test',amount if declared else None,
                              end_stream=False,headers=dict(self.auth(f'{declared}-{amount}')))
                    if not declared or amount==LIMIT:
                        h.send_body(1,amount,timeout=30)
                    h.wait_for(lambda:1 in h.ended,5,'limit response')
                    self.assertEqual(h.response_status[1],b'202' if amount==LIMIT else b'413')
                    self.assertEqual(len(self.records),before+(amount==LIMIT))
                finally:h.close()

    def test_framing_and_trailers(self):
        for body, headers in [(b'',[('Content-Length','1'),('Transfer-Encoding','chunked')]),
                              (b'0\r\nX-Trailer: sentinel\r\n\r\n',[('Transfer-Encoding','chunked')]),
                              (b'',[('Content-Length','1'),('Content-Length','2')])]:
            self.assertEqual(self.request(body=body,headers=self.auth()+headers)[0],400)
        self.assertEqual(self.records,[])

    def test_h2_trailers_and_ambiguous_headers(self):
        from hpack import Encoder
        h=H2('127.0.0.1',self.port,'submit.test')
        try:
            h.request(1,'POST','/v1/smtp','submit.test',end_stream=False,headers=dict(self.auth()))
            h.send_data(1,b'x')
            h.send_frame(HEADERS,5,1,Encoder().encode([('x-trailer','sentinel')]))
            h.wait_for(lambda:1 in h.ended or 1 in h.resets,5,'trailer rejection')
            self.assertTrue(1 in h.resets or h.response_status[1]==b'400')
        finally:h.close()
        for field in ('authorization','idempotency-key','content-type'):
            h=H2('127.0.0.1',self.port,'submit.test')
            try:
                headers=[(':method','POST'),(':scheme','https'),(':authority','submit.test'),
                         (':path','/v1/smtp'),(field,'one'),(field,'two')]
                h.send_frame(HEADERS,5,1,Encoder().encode(headers))
                h.wait_for(lambda:1 in h.ended or 1 in h.resets,5,'duplicate rejection')
                self.assertTrue(1 in h.resets or h.response_status[1]==b'400')
            finally:h.close()
        self.assertEqual(self.records,[])

    def test_absolute_upload_deadline(self):
        self.restart(self.host_config.replace('upload-timeout-ms=105000','upload-timeout-ms=300')
                     .replace('response-timeout-ms=115000','response-timeout-ms=1000'))
        with self.tls() as sock:
            sock.sendall(b'POST /v1/smtp HTTP/1.1\r\nHost: submit.test\r\nContent-Length: 100\r\nAuthorization: Bearer sentinel-secret\r\n\r\n')
            start=time.monotonic()
            for _ in range(4):
                time.sleep(.1)
                try:sock.sendall(b'x')
                except OSError:break
            r=http.client.HTTPResponse(sock);r.begin()
            self.assertEqual(r.status,408)
            self.assertLess(time.monotonic()-start,1)
        self.assertEqual(self.records,[])
        self.assertEqual(self.request(headers=self.auth())[0],202)

    def real_upload_processing(self):
        h=H2('127.0.0.1',self.port,'submit.test')
        start=time.monotonic()
        try:
            h.request(1,'POST','/v1/smtp','submit.test',end_stream=False,
                      headers=dict(self.auth('real-duration')))
            for i in range(100):
                due=start+i+1
                time.sleep(max(0,due-time.monotonic()))
                self.assertEqual(h.send_data(1,b'x'),1)
                h.receive(.01)
            h.end_stream(1)
            h.wait_for(lambda:1 in h.ended,max(0,120-(time.monotonic()-start)),
                       '100-second upload plus 10-second processing')
            self.assertEqual(h.response_status[1],b'202')
            self.assertGreaterEqual(time.monotonic()-start,109)
            self.assertLess(time.monotonic()-start,115)
        finally:h.close()

    def test_early_rejection_and_incomplete_response(self):
        with self.tls() as sock:
            sock.sendall(b'POST /v1/smtp HTTP/1.1\r\nHost: submit.test\r\nTransfer-Encoding: chunked\r\n\r\n')
            reply=http.client.HTTPResponse(sock);reply.begin()
            self.assertEqual(reply.status,401)
            self.assertEqual(reply.read(),b'{"error":"unauthorized"}')
            try: sock.sendall(f'{LIMIT+1:x}\r\n'.encode()+b'x'*65536)
            except OSError: pass
        self.assertEqual(self.records,[])
        with self.assertRaises(http.client.IncompleteRead):
            self.request(body=b'once',headers=self.auth('partial'))
        self.assertEqual(sum(r[0]['Idempotency-Key']=='partial' for r in self.records),1)

    def test_interim_responses_do_not_extend_deadline(self):
        self.restart(self.host_config.replace('response-timeout-ms=115000','response-timeout-ms=500')
                     .replace('upload-timeout-ms=105000','upload-timeout-ms=400'))
        with self.tls() as sock:
            sock.sendall(b'POST /v1/smtp HTTP/1.1\r\nHost: submit.test\r\nContent-Length: 0\r\nAuthorization: Bearer sentinel-secret\r\nIdempotency-Key: interim\r\n\r\n')
            start=time.monotonic();data=b''
            while True:
                part=sock.recv(4096)
                if not part: break
                data+=part
            elapsed=time.monotonic()-start
            self.assertIn(b'103 Early Hints',data)
            self.assertGreater(elapsed,.35)
            self.assertLess(elapsed,1)
        self.assertEqual(len(self.records),1)

    def test_stalled_h2_queues(self):
        streams=[]
        try:
            for _ in range(2):
                h=H2('127.0.0.1',self.port,'submit.test');streams.append(h)
                h.request(1,'POST','/v1/smtp','submit.test',LIMIT,end_stream=False,
                          headers=dict(self.auth('hold')))
                sent=h.send_until_stalled(1,LIMIT,timeout=2)
                self.assertLess(sent,LIMIT,'missing upload backpressure')
            self.assertEqual(self.request(headers=self.auth())[0],503)
            self.assertEqual(self.request('/', 'GET', name='status.test')[0],200)
            status=Path(f'/proc/{self.proc.pid}/status').read_text()
            rss=int(next(line.split()[1] for line in status.splitlines() if line.startswith('VmRSS:')))
            self.assertLess(rss,192*1024)
            print(f'gateway_stalled_rss_kib={rss}',flush=True)
        finally:
            for h in streams:h.close()
            self.release.set()
        time.sleep(.1)
        self.assertEqual(self.request(headers=self.auth())[0],202)
        self.log.flush()
        for line in (self.root/'gateway.log').read_text().splitlines():
            if 'request_peak=' in line:
                fields=dict(field.split('=',1) for field in line.split() if '=' in field)
                self.assertLessEqual(int(fields['request_peak']),4194304)
                self.assertLessEqual(int(fields['response_peak']),8388608)

    def test_h2_partial_second_header_deadline(self):
        h=H2('127.0.0.1',self.port,'submit.test')
        try:
            h.request(1,'POST','/v1/smtp','submit.test',0)
            h.wait_for(lambda:1 in h.ended,3,'initial rejection')
            # A new header block must get its own deadline on an admitted connection.
            h.send_frame(HEADERS,0,3,request_headers('POST','/v1/smtp','submit.test'))
            started=time.monotonic()
            h.wait_for(lambda:3 in h.resets,6,'partial headers reset')
            self.assertGreaterEqual(time.monotonic()-started,4.5)
            self.assertLess(time.monotonic()-started,6)
        finally:h.close()

    def test_tls_and_header_absolute_deadlines(self):
        started=time.monotonic()
        raw=socket.create_connection(('127.0.0.1',self.port),timeout=12)
        try:
            with self.tls() as sock:
                sock.sendall(b'POST /v1/smtp HTTP/1.1\r\nHost: submit.test\r\n')
                for _ in range(4):
                    time.sleep(1)
                    sock.sendall(b'X')
                self.assertEqual(sock.recv(1),b'')
                self.assertLess(time.monotonic()-started,6)
            self.assertEqual(raw.recv(1),b'')
            self.assertGreaterEqual(time.monotonic()-started,9.5)
            self.assertLess(time.monotonic()-started,11)
            self.assertEqual(self.records,[])
        finally:raw.close()

    def test_truncated_upload_and_h2_concurrency(self):
        with self.tls() as sock:
            sock.sendall(b'POST /v1/smtp HTTP/1.1\r\nHost: submit.test\r\nContent-Length: 100\r\nAuthorization: Bearer sentinel-secret\r\n\r\nx')
        time.sleep(.1)
        self.assertEqual(self.records,[])
        h=H2('127.0.0.1',self.port,'submit.test')
        try:
            for sid in (1,3):
                h.request(sid,'POST','/v1/smtp','submit.test',100,end_stream=False,
                          headers=dict(self.auth('hold')))
            h.request(5,'POST','/v1/smtp','submit.test',0,headers=dict(self.auth('third')))
            h.wait_for(lambda:5 in h.ended,3,'third stream rejection')
            self.assertEqual(h.response_status[5],b'503')
            self.assertEqual(self.request('/', 'GET', name='status.test')[0],200)
            h.reset(1);h.reset(3);h.receive(.1)
        finally:h.close();self.release.set()
        time.sleep(.1)
        self.assertEqual(self.request(headers=self.auth())[0],202)

    def test_invalid_configuration(self):
        for extra in ('unknown-key=1', 'body-limit=1', 'concurrency=0',
                      'route=submission POST /another', 'route=other POST /v1/smtp',
                      'public-origin=https://status.test', 'virtual-host=host.conf'):
            (self.root/'host.conf').write_text(self.host_config+extra+'\n')
            result=subprocess.run([EXE,'--config',str(self.root/'gateway.conf')],
                                  cwd=self.root,capture_output=True,timeout=5)
            self.assertNotEqual(result.returncode,0,extra)
            self.assertIn(b'invalid configuration',result.stderr,extra)
        (self.root/'host.conf').write_text(self.host_config)

    def test_authorities_and_h2_conflicts(self):
        for authority,expected in [('unknown.test',421),('submit.test:444',421),
                                   ('submit.test:',400),('submit.test:0',400),
                                   ('submit.test.',400),('user@submit.test',400),
                                   ('SUBMIT.TEST:443',202)]:
            with self.tls() as sock:
                sock.sendall(f'POST /v1/smtp HTTP/1.1\r\nHost: {authority}\r\nContent-Length: 0\r\nAuthorization: Bearer sentinel-secret\r\n\r\n'.encode())
                reply=http.client.HTTPResponse(sock);reply.begin();reply.read()
                self.assertEqual(reply.status,expected,authority)
        h=H2('127.0.0.1',self.port,'submit.test')
        try:
            h.request(1,'POST','/v1/smtp','submit.test',0,headers={'host':'status.test'})
            h.wait_for(lambda:1 in h.ended,5,'conflict')
            self.assertEqual(h.response_status[1],b'421')
        finally:h.close()
        with self.tls(None) as sock:self.assertEqual(sock.recv(1),b'')

    def test_certificate_generation(self):
        with self.tls('status.test') as a, self.tls() as b:
            first=a.getpeercert(binary_form=True);second=b.getpeercert(binary_form=True)
            self.assertNotEqual(first,second)
        existing=self.tls('status.test')
        old_key=(self.root/'submit.test.key').read_bytes()
        subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes',
                        '-subj','/CN=status.test','-keyout',str(self.root/'status.test.key'),
                        '-out',str(self.root/'status.test.pem'),'-days','1'],check=True,
                       stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        (self.root/'submit.test.key').write_text('invalid')
        self.proc.send_signal(signal.SIGHUP);time.sleep(.1)
        with self.tls() as b:self.assertEqual(second,b.getpeercert(binary_form=True))
        with self.tls('status.test') as a:self.assertEqual(first,a.getpeercert(binary_form=True))
        (self.root/'submit.test.key').write_bytes(old_key)
        self.proc.send_signal(signal.SIGHUP);time.sleep(.1)
        with self.tls('status.test') as a:self.assertNotEqual(first,a.getpeercert(binary_form=True))
        existing.sendall(b'GET / HTTP/1.1\r\nHost: status.test\r\n\r\n')
        reply=http.client.HTTPResponse(existing);reply.begin();self.assertEqual(reply.status,200)
        reply.read();existing.close()
        with self.assertRaises((ssl.SSLError,OSError)):
            with self.tls('unknown.test') as sock:sock.recv(1)

if __name__=='__main__':unittest.main()
