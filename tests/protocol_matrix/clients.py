"""Strict HTTP/1.1, HTTP/2, and HTTP/3 clients for the matrix."""

import asyncio
import socket
import ssl
from dataclasses import dataclass
from urllib.parse import urlsplit

import httpx
import h2.config
import h2.connection
import h2.events
from aioquic.asyncio import QuicConnectionProtocol, connect
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.h3.events import DataReceived, HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import ConnectionTerminated, ProtocolNegotiated, StreamReset


H3_NO_APPLICATION_PROTOCOL = 0x178
QUIC_INTERNAL_ERROR = 0x1


class H3NegotiationUnavailable(ConnectionError):
    """The peer did not establish a connection using an HTTP/3 ALPN."""


@dataclass
class Response:
    status: int
    headers: dict[str, str]
    body: bytes
    version: str


def _headers(items):
    output = {}
    for name, value in items:
        key = name.decode().lower() if isinstance(name, bytes) else name.lower()
        item = value.decode() if isinstance(value, bytes) else value
        output[key] = f"{output[key]}, {item}" if key in output else item
    return output


class HttpxClient:
    def __init__(self, base_url, protocol, ca_file):
        self.base_url = base_url.rstrip("/")
        self.protocol = protocol
        context = ssl.create_default_context(cafile=ca_file)
        self.client = httpx.Client(
            http1=protocol == "h1",
            http2=protocol == "h2",
            verify=context,
            timeout=httpx.Timeout(20),
            trust_env=False,
        )

    def close(self):
        self.client.close()

    def request(self, method, path, headers=None, content=None):
        response = self.client.request(method, self.base_url + path,
                                       headers=headers, content=content)
        expected = "HTTP/1.1" if self.protocol == "h1" else "HTTP/2"
        if response.http_version != expected:
            raise AssertionError(f"expected {expected}, negotiated {response.http_version}")
        return Response(response.status_code, dict(response.headers),
                        response.content, response.http_version)


class MatrixH3Connection(H3Connection):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.head_streams = set()

    def _check_content_length(self, stream):
        # A HEAD Content-Length describes the selected GET representation,
        # not bytes carried on this stream.
        if stream.stream_id in self.head_streams:
            return
        super()._check_content_length(stream)


class H3Protocol(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.http = None
        self.waiters = {}
        self.responses = {}
        self.alpn = None
        self.termination = None

    def quic_event_received(self, event):
        if isinstance(event, ConnectionTerminated):
            self.termination = event
            self._fail_waiters(ConnectionError(
                f"QUIC connection terminated with error {event.error_code}: "
                f"{event.reason_phrase}"))
            return
        if isinstance(event, ProtocolNegotiated):
            self.alpn = event.alpn_protocol
            if self.alpn in H3_ALPN:
                self.http = MatrixH3Connection(self._quic)
        if self.http is None:
            return
        if isinstance(event, StreamReset):
            waiter = self.waiters.pop(event.stream_id, None)
            if waiter is not None and not waiter.done():
                waiter.set_exception(ConnectionError(
                    f"HTTP/3 stream reset with error {event.error_code}"))
            return
        for http_event in self.http.handle_event(event):
            stream_id = getattr(http_event, "stream_id", None)
            if stream_id not in self.waiters:
                continue
            response = self.responses[stream_id]
            if isinstance(http_event, HeadersReceived):
                response["headers"].extend(http_event.headers)
            elif isinstance(http_event, DataReceived):
                response["body"].extend(http_event.data)
            if getattr(http_event, "stream_ended", False):
                waiter = self.waiters.pop(stream_id)
                waiter.set_result(response)

    def _fail_waiters(self, error):
        for waiter in self.waiters.values():
            if not waiter.done():
                waiter.set_exception(error)
        self.waiters.clear()

    async def request(self, method, scheme, authority, path, headers=None, content=b""):
        if self.http is None or self.alpn not in H3_ALPN:
            raise ConnectionError("HTTP/3 ALPN was not negotiated")
        stream_id = self._quic.get_next_available_stream_id()
        loop = asyncio.get_running_loop()
        waiter = loop.create_future()
        self.waiters[stream_id] = waiter
        self.responses[stream_id] = {
            "method": method,
            "headers": [],
            "body": bytearray(),
        }
        if method == "HEAD":
            self.http.head_streams.add(stream_id)
        if method == "CONNECT":
            fields = [(b":method", b"CONNECT"), (b":authority", path.encode())]
        else:
            fields = [(b":method", method.encode()), (b":scheme", scheme.encode()),
                      (b":authority", authority.encode()), (b":path", path.encode())]
        fields.extend((name.lower().encode(), str(value).encode())
                      for name, value in (headers or {}).items())
        chunks = ([content] if content else []) if isinstance(
            content, (bytes, bytearray)) else list(content or [])
        self.http.send_headers(stream_id=stream_id, headers=fields,
                               end_stream=not chunks)
        for index, chunk in enumerate(chunks):
            self.http.send_data(stream_id=stream_id, data=bytes(chunk),
                                end_stream=index + 1 == len(chunks))
        self.transmit()
        return await asyncio.wait_for(waiter, timeout=20)


def _h3_negotiation_unavailable(protocol):
    if protocol is None or protocol.alpn in H3_ALPN:
        return False
    if protocol.alpn is not None:
        return True
    termination = protocol.termination
    if termination is None:
        return False
    if termination.error_code == H3_NO_APPLICATION_PROTOCOL:
        return True
    return (termination.error_code == QUIC_INTERNAL_ERROR and
            termination.reason_phrase == "Idle timeout")


async def _h3_requests(base_url, ca_file, requests):
    split = urlsplit(base_url)
    host = split.hostname
    port = split.port or 443
    configuration = QuicConfiguration(is_client=True, alpn_protocols=H3_ALPN)
    configuration.idle_timeout = 10.0
    configuration.load_verify_locations(ca_file)
    configuration.server_name = host
    created = []

    def create_protocol(*args, **kwargs):
        protocol = H3Protocol(*args, **kwargs)
        created.append(protocol)
        return protocol

    try:
        async with connect(host, port, configuration=configuration,
                           create_protocol=create_protocol,
                           wait_connected=True) as protocol:
            if protocol.alpn not in H3_ALPN:
                raise H3NegotiationUnavailable(
                    f"HTTP/3 ALPN was not negotiated, selected {protocol.alpn!r}")
            tasks = [protocol.request(method, split.scheme, split.netloc, path,
                                      headers, content)
                     for method, path, headers, content in requests]
            raw = await asyncio.gather(*tasks)
    except ConnectionError as error:
        protocol = created[0] if created else None
        if not isinstance(error, H3NegotiationUnavailable) and \
                _h3_negotiation_unavailable(protocol):
            detail = (protocol.termination.reason_phrase
                      if protocol.termination is not None else "ALPN unavailable")
            raise H3NegotiationUnavailable(detail) from error
        raise
    else:
        if protocol.alpn not in H3_ALPN:
            raise AssertionError("HTTP/3 ALPN changed after negotiation")
        output = []
        for item in raw:
            headers = _headers(item["headers"])
            status = int(headers.pop(":status"))
            output.append(Response(status, headers, bytes(item["body"]), "HTTP/3"))
        return output


class H3Client:
    def __init__(self, base_url, ca_file):
        self.base_url = base_url.rstrip("/")
        self.ca_file = ca_file

    def close(self):
        pass

    def request(self, method, path, headers=None, content=None):
        return asyncio.run(_h3_requests(self.base_url, self.ca_file,
                           [(method, path, headers or {}, content or b"")]))[0]

    def concurrent(self, requests):
        return asyncio.run(_h3_requests(self.base_url, self.ca_file, requests))


def client_for(base_url, protocol, ca_file):
    if protocol == "h3":
        return H3Client(base_url, ca_file)
    return HttpxClient(base_url, protocol, ca_file)


def connect_request(base_url, protocol, ca_file, authority):
    if protocol == "h3":
        return asyncio.run(_h3_requests(base_url, ca_file,
                           [("CONNECT", authority, {}, b"")]))[0]
    if protocol == "h2":
        return _h2_connect(base_url, ca_file, authority)
    split = urlsplit(base_url)
    head = (f"CONNECT {authority} HTTP/1.1\r\nHost: {split.netloc}\r\n"
            "Connection: close\r\n\r\n").encode()
    return raw_h1_request(base_url, ca_file, head)


def _h2_connect(base_url, ca_file, authority):
    split = urlsplit(base_url)
    context = ssl.create_default_context(cafile=ca_file)
    context.set_alpn_protocols(["h2"])
    config = h2.config.H2Configuration(client_side=True, header_encoding="utf-8")
    connection = h2.connection.H2Connection(config=config)
    response_headers = []
    response_body = bytearray()
    ended = False
    with socket.create_connection((split.hostname, split.port or 443), timeout=10) as plain:
        with context.wrap_socket(plain, server_hostname=split.hostname) as stream:
            if stream.selected_alpn_protocol() != "h2":
                raise AssertionError("HTTP/2 was not negotiated")
            connection.initiate_connection()
            stream.sendall(connection.data_to_send())
            connection.send_headers(1, [
                (":method", "CONNECT"),
                (":authority", authority),
            ], end_stream=True)
            stream.sendall(connection.data_to_send())
            while not ended:
                data = stream.recv(65535)
                if not data:
                    raise ConnectionError("connection closed before HTTP/2 response ended")
                for event in connection.receive_data(data):
                    if isinstance(event, h2.events.ResponseReceived):
                        response_headers.extend(event.headers)
                    elif isinstance(event, h2.events.DataReceived):
                        response_body.extend(event.data)
                        connection.acknowledge_received_data(
                            event.flow_controlled_length, event.stream_id)
                    elif isinstance(event, h2.events.StreamEnded) and event.stream_id == 1:
                        ended = True
                    elif isinstance(event, h2.events.StreamReset) and event.stream_id == 1:
                        raise ConnectionError(
                            f"HTTP/2 stream reset with error {event.error_code}")
                outbound = connection.data_to_send()
                if outbound:
                    stream.sendall(outbound)
    headers = _headers(response_headers)
    if ":status" not in headers:
        raise ConnectionError("HTTP/2 response omitted :status")
    status = int(headers.pop(":status"))
    return Response(status, headers, bytes(response_body), "HTTP/2")


def raw_h1_request(base_url, ca_file, head, body=b"", wait_for_continue=False):
    split = urlsplit(base_url)
    context = ssl.create_default_context(cafile=ca_file)
    context.set_alpn_protocols(["http/1.1"])
    with socket.create_connection((split.hostname, split.port or 443), timeout=10) as plain:
        with context.wrap_socket(plain, server_hostname=split.hostname) as stream:
            if stream.selected_alpn_protocol() not in (None, "http/1.1"):
                raise AssertionError("HTTP/1.1 was not negotiated")
            stream.sendall(head)
            buffered = b""
            if wait_for_continue:
                buffered = _read_header(stream)
                if not buffered.startswith(b"HTTP/1.1 100 "):
                    raise AssertionError(f"expected 100 Continue, got {buffered!r}")
            stream.sendall(body)
            header = _read_header(stream)
            while header.startswith(b"HTTP/1.1 100 "):
                header = _read_header(stream)
            status_line, *lines = header[:-4].split(b"\r\n")
            status = int(status_line.split(b" ", 2)[1])
            headers = _headers(line.split(b":", 1) for line in lines if b":" in line)
            length = int(headers.get("content-length", "0"))
            payload = _read_exact(stream, length)
            return Response(status, headers, payload, "HTTP/1.1")


def _read_header(stream):
    data = bytearray()
    while not data.endswith(b"\r\n\r\n"):
        chunk = stream.recv(1)
        if not chunk:
            raise ConnectionError("connection closed before response headers")
        data.extend(chunk)
        if len(data) > 65536:
            raise ValueError("response headers too large")
    return bytes(data)


def _read_exact(stream, length):
    data = bytearray()
    while len(data) < length:
        chunk = stream.recv(length - len(data))
        if not chunk:
            raise ConnectionError("connection closed before response body")
        data.extend(chunk)
    return bytes(data)
