"""Small HTTP/2 test client with explicit flow-control handling."""

import socket
import ssl
import struct
import time

from hpack import Decoder


DATA = 0
HEADERS = 1
RST_STREAM = 3
SETTINGS = 4
PING = 6
GOAWAY = 7
WINDOW_UPDATE = 8

END_STREAM = 1
ACK = 1
END_HEADERS = 4


def integer(value, prefix, lead=0):
    limit = (1 << prefix) - 1
    if value < limit:
        return bytes((lead | value,))
    encoded = bytearray((lead | limit,))
    value -= limit
    while value >= 128:
        encoded.append((value & 127) | 128)
        value >>= 7
    encoded.append(value)
    return bytes(encoded)


def text(value):
    encoded = value.encode()
    return integer(len(encoded), 7) + encoded


def indexed(value):
    return integer(value, 7, 128)


def literal(name_index, value):
    return integer(name_index, 4) + text(value)


def request_headers(method, path, authority, length=None, headers=None):
    methods = {"GET": 2, "POST": 3}
    block = bytearray(indexed(methods[method]))
    block.extend(indexed(7))
    block.extend(literal(4, path))
    block.extend(literal(1, authority))
    if length is not None:
        block.extend(literal(28, str(length)))
    for name, value in (headers or {}).items():
        block.extend(integer(0, 4))
        block.extend(text(name.lower()))
        block.extend(text(value))
    return bytes(block)


class Client:
    def __init__(self, host, port):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        context.set_alpn_protocols(["h2"])
        raw = socket.create_connection((host, port), timeout=5)
        self.socket = context.wrap_socket(raw, server_hostname="localhost")
        assert self.socket.selected_alpn_protocol() == "h2"
        self.socket.settimeout(.05)
        self.input = bytearray()
        self.connection_window = 65535
        self.window_update_delay = 0
        self.delayed_window_updates = []
        self.initial_stream_window = 65535
        self.max_frame_size = 16384
        self.stream_windows = {}
        self.sent = {}
        self.ended = set()
        self.responses = set()
        self.response_headers = {}
        self.response_status = {}
        self.header_decoder = Decoder()
        self.received = {}
        self.resets = {}
        self.events = []
        self.pings = set()
        self.saw_settings = False
        self.send_raw(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
        self.send_frame(SETTINGS, 0, 0)
        self.wait_for(lambda: self.saw_settings, 3, "server SETTINGS")

    def close(self):
        self.socket.close()

    def send_raw(self, data):
        self.socket.sendall(data)

    def send_frame(self, kind, flags, stream_id, payload=b""):
        size = len(payload)
        header = bytes((size >> 16, (size >> 8) & 255, size & 255, kind, flags))
        header += struct.pack("!I", stream_id)
        self.send_raw(header + payload)

    def request(self, stream_id, method, path, authority, length=None,
                end_stream=None, headers=None):
        flags = END_HEADERS
        if end_stream is None:
            end_stream = length is None
        if end_stream:
            flags |= END_STREAM
        self.stream_windows[stream_id] = self.initial_stream_window
        self.sent[stream_id] = 0
        self.send_frame(HEADERS, flags, stream_id,
                        request_headers(method, path, authority, length, headers))

    def send_data(self, stream_id, data, end_stream=False):
        available = min(self.connection_window,
                        self.stream_windows[stream_id], self.max_frame_size,
                        len(data))
        if not available:
            return 0
        flags = END_STREAM if end_stream and available == len(data) else 0
        self.send_frame(DATA, flags, stream_id, data[:available])
        self.connection_window -= available
        self.stream_windows[stream_id] -= available
        self.sent[stream_id] += available
        return available

    def end_stream(self, stream_id):
        self.send_frame(DATA, END_STREAM, stream_id)

    def delivered(self, stream_id):
        return (self.sent[stream_id] - self.initial_stream_window +
                self.stream_windows[stream_id])

    def receive_window(self, size):
        """Change the initial window the server may use for response DATA."""
        self.send_frame(SETTINGS, 0, 0, struct.pack("!HI", 4, size))

    def ping(self, value):
        assert len(value) == 8
        self.send_frame(PING, 0, 0, value)

    def reset(self, stream_id):
        self.send_frame(RST_STREAM, 0, stream_id, struct.pack("!I", 8))

    def receive(self, timeout=.05):
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            try:
                data = self.socket.recv(65536)
            except (socket.timeout, ssl.SSLWantReadError):
                break
            if not data:
                raise AssertionError("HTTP/2 connection closed")
            self.input.extend(data)
            self.process_frames()
            if len(data) < 65536:
                break
        self.apply_delayed_window_updates()

    def apply_delayed_window_updates(self):
        now = time.monotonic()
        waiting = []
        for due, stream_id, change in self.delayed_window_updates:
            if due > now:
                waiting.append((due, stream_id, change))
            elif stream_id:
                self.stream_windows[stream_id] += change
            else:
                self.connection_window += change
        self.delayed_window_updates = waiting

    def process_frames(self):
        while len(self.input) >= 9:
            size = int.from_bytes(self.input[:3], "big")
            if len(self.input) < 9 + size:
                return
            kind = self.input[3]
            flags = self.input[4]
            stream_id = int.from_bytes(self.input[5:9], "big") & 0x7fffffff
            payload = bytes(self.input[9:9 + size])
            del self.input[:9 + size]
            self.process_frame(kind, flags, stream_id, payload)

    def process_frame(self, kind, flags, stream_id, payload):
        if stream_id and kind in (DATA, HEADERS, RST_STREAM):
            self.events.append((stream_id, kind, bool(flags & END_STREAM)))
        if kind == SETTINGS and not flags & ACK:
            old_window = self.initial_stream_window
            for offset in range(0, len(payload), 6):
                setting, value = struct.unpack("!HI", payload[offset:offset + 6])
                if setting == 4:
                    self.initial_stream_window = value
                elif setting == 5:
                    self.max_frame_size = value
            change = self.initial_stream_window - old_window
            for current in self.stream_windows:
                self.stream_windows[current] += change
            self.send_frame(SETTINGS, ACK, 0)
            self.saw_settings = True
        elif kind == WINDOW_UPDATE:
            change = struct.unpack("!I", payload)[0] & 0x7fffffff
            if self.window_update_delay:
                self.delayed_window_updates.append(
                    (time.monotonic() + self.window_update_delay, stream_id, change))
            elif stream_id:
                self.stream_windows[stream_id] += change
            else:
                self.connection_window += change
        elif kind == RST_STREAM:
            self.resets[stream_id] = struct.unpack("!I", payload)[0]
        elif kind == PING and flags & ACK:
            self.pings.add(payload)
        elif kind == DATA:
            self.received[stream_id] = self.received.get(stream_id, 0) + len(payload)
            if payload:
                update = struct.pack("!I", len(payload))
                self.send_frame(WINDOW_UPDATE, 0, 0, update)
                self.send_frame(WINDOW_UPDATE, 0, stream_id, update)
            if flags & END_STREAM:
                self.ended.add(stream_id)
        elif kind == HEADERS:
            self.responses.add(stream_id)
            self.response_headers.setdefault(stream_id, []).append(payload)
            for name, value in self.header_decoder.decode(payload, raw=True):
                if name == b":status":
                    self.response_status[stream_id] = value
            if flags & END_STREAM:
                self.ended.add(stream_id)
        elif kind == GOAWAY:
            raise AssertionError("server sent GOAWAY")

    def wait_for(self, condition, timeout, description):
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            if condition():
                return
            self.receive(min(.05, end - time.monotonic()))
        raise AssertionError(f"timed out waiting for {description}")

    def send_body(self, stream_id, size, timeout=5, end_stream=True):
        sent = 0
        block = b"x" * 16384
        end = time.monotonic() + timeout
        while sent < size and time.monotonic() < end:
            count = self.send_data(stream_id, block[:min(len(block), size - sent)],
                                   end_stream=end_stream and sent + len(block) >= size)
            if count:
                sent += count
            else:
                self.receive(.05)
        if sent != size:
            raise AssertionError(f"sent {sent} of {size} bytes on stream {stream_id}")

    def send_until_stalled(self, stream_id, size, timeout=15):
        """Send up to size bytes without END_STREAM; stop early on backpressure."""
        sent = 0
        block = b"s" * 16384
        last_progress = time.monotonic()
        end = last_progress + timeout
        while sent < size and time.monotonic() < end:
            count = self.send_data(stream_id, block[:min(len(block), size - sent)])
            if count:
                sent += count
                last_progress = time.monotonic()
                continue
            self.receive(.05)
            if (not self.stream_windows[stream_id] and
                    time.monotonic() - last_progress >= .25):
                return sent
        if sent == size:
            return sent
        raise AssertionError(
            f"stream {stream_id} did not become backpressured: "
            f"sent={sent}, stream_window={self.stream_windows[stream_id]}, "
            f"connection_window={self.connection_window}")

    def fill_until_stalled(self, stream_id, limit=64 << 20, timeout=15):
        sent = self.send_until_stalled(stream_id, limit, timeout)
        if sent == limit:
            raise AssertionError("upstream did not apply backpressure")
        return sent
