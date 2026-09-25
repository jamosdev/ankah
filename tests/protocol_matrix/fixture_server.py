#!/usr/bin/env python3
"""Stateful HTTP fixture for the isolated protocol matrix."""

import argparse
import base64
import hashlib
import http.server
import json
import threading
import uuid
import xml.etree.ElementTree as ET
from urllib.parse import parse_qs, urlsplit


DAV = "DAV:"
ET.register_namespace("D", DAV)


class State:
    def __init__(self):
        self.lock = threading.RLock()
        self.records = []
        self.resources = {}
        self.collections = {"/matrix/dav/"}
        self.properties = {}
        self.locks = {}
        self.tus = {}
        self.ranges = {}


STATE = State()


def parent_collection(path):
    path = path.rstrip("/")
    parent = path.rsplit("/", 1)[0] + "/"
    return parent


def body_digest(body):
    return hashlib.sha256(body).hexdigest()


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "AnkahProtocolFixture/1"

    def log_message(self, *_):
        pass

    def read_body(self):
        if self.headers.get("Transfer-Encoding", "").lower() == "chunked":
            output = bytearray()
            while True:
                line = self.rfile.readline(4097)
                if not line.endswith(b"\r\n"):
                    raise ValueError("invalid chunk size")
                size = int(line[:-2].split(b";", 1)[0], 16)
                if not size:
                    while True:
                        trailer = self.rfile.readline(4097)
                        if trailer == b"\r\n":
                            return bytes(output)
                        if not trailer.endswith(b"\r\n"):
                            raise ValueError("invalid trailer")
                output.extend(self.rfile.read(size))
                if self.rfile.read(2) != b"\r\n":
                    raise ValueError("invalid chunk data")
        length = int(self.headers.get("Content-Length", "0"))
        return self.rfile.read(length)

    def send_bytes(self, status, body=b"", headers=None, head=False):
        self.send_response(status)
        for name, value in (headers or {}).items():
            self.send_header(name, str(value))
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        if not head and body:
            self.wfile.write(body)

    def send_json(self, status, value, headers=None, head=False):
        body = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
        merged = {"Content-Type": "application/json"}
        merged.update(headers or {})
        self.send_bytes(status, body, merged, head)

    def record(self, body):
        record = {
            "id": uuid.uuid4().hex,
            "method": self.command,
            "target": self.path,
            "headers": {name.lower(): value for name, value in self.headers.items()},
            "body_length": len(body),
            "body_sha256": body_digest(body),
            "body_base64": base64.b64encode(body).decode(),
        }
        with STATE.lock:
            STATE.records.append(record)
        return record

    def dispatch(self, head=False):
        split = urlsplit(self.path)
        path = split.path
        if path == "/matrix/_ready":
            self.send_bytes(200, b"ready\n", head=head)
            return
        if path == "/matrix/_trailers":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Transfer-Encoding", "chunked")
            self.send_header("Trailer", "X-Matrix-Trailer")
            self.send_header("Connection", "close")
            self.end_headers()
            if not head:
                self.wfile.write(
                    b"5\r\nhello\r\n0\r\nX-Matrix-Trailer: complete\r\n\r\n")
            return
        if path == "/matrix/_records":
            query = parse_qs(split.query)
            wanted = query.get("path", [None])[0]
            target = query.get("target", [None])[0]
            with STATE.lock:
                records = [item for item in STATE.records
                           if (wanted is None or urlsplit(item["target"]).path == wanted) and
                           (target is None or item["target"] == target)]
            self.send_json(200, {"count": len(records), "records": records}, head=head)
            return
        try:
            body = self.read_body()
        except (ValueError, OSError):
            self.send_bytes(400, b"invalid body\n")
            return
        record = self.record(body)
        if path == "/matrix/tus" or path.startswith("/matrix/tus/"):
            self.handle_tus(path, body, head)
        elif path.startswith("/matrix/content-range/"):
            self.handle_content_range(path, body, head)
        elif path.startswith("/matrix/dav/"):
            self.handle_dav(path, body, head)
        else:
            self.handle_echo(record, body, head)

    def handle_echo(self, record, body, head):
        headers = {
            "X-Fixture-Method": self.command,
            "X-Fixture-Target": self.path,
            "X-Fixture-Body-SHA256": body_digest(body),
            "X-Fixture-Body-Length": len(body),
        }
        if self.command == "OPTIONS":
            headers["Allow"] = "GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS, TRACE"
            self.send_bytes(204, headers=headers, head=head)
        elif self.command == "TRACE":
            payload = f"{self.command} {self.path} HTTP/1.1\r\n\r\n".encode()
            self.send_bytes(200, payload, {**headers, "Content-Type": "message/http"}, head=head)
        elif self.command == "HEAD":
            self.send_bytes(200, b"recorded response", headers, head=True)
        elif self.command == "DELETE":
            self.send_bytes(204, headers=headers)
        else:
            self.send_json(200, record, headers, head)

    def handle_tus(self, path, body, head):
        common = {"Tus-Resumable": "1.0.0"}
        if self.command == "OPTIONS":
            self.send_bytes(204, headers={**common, "Tus-Version": "1.0.0",
                                          "Tus-Extension": "creation"})
            return
        if path == "/matrix/tus" and self.command == "POST":
            try:
                length = int(self.headers["Upload-Length"])
            except (KeyError, ValueError):
                self.send_bytes(400, b"Upload-Length required\n")
                return
            key = uuid.uuid4().hex
            with STATE.lock:
                STATE.tus[key] = {"length": length, "body": bytearray()}
            self.send_bytes(201, headers={**common, "Location": f"/matrix/tus/{key}",
                                          "Upload-Offset": "0"})
            return
        key = path.rsplit("/", 1)[-1]
        with STATE.lock:
            upload = STATE.tus.get(key)
            if upload is None:
                self.send_bytes(404, b"unknown upload\n")
                return
            if self.command == "HEAD":
                self.send_bytes(200, headers={**common,
                    "Upload-Offset": len(upload["body"]),
                    "Upload-Length": upload["length"]}, head=True)
                return
            if self.command == "PATCH":
                try:
                    offset = int(self.headers["Upload-Offset"])
                except (KeyError, ValueError):
                    self.send_bytes(400, b"Upload-Offset required\n")
                    return
                if (self.headers.get("Tus-Resumable") != "1.0.0" or
                        self.headers.get("Content-Type") != "application/offset+octet-stream"):
                    self.send_bytes(412, b"invalid TUS headers\n")
                    return
                if offset != len(upload["body"]):
                    self.send_bytes(409, headers={**common,
                                                  "Upload-Offset": len(upload["body"])})
                    return
                if len(upload["body"]) + len(body) > upload["length"]:
                    self.send_bytes(413, b"upload too large\n")
                    return
                upload["body"].extend(body)
                self.send_bytes(204, headers={**common,
                                              "Upload-Offset": len(upload["body"]),
                                              "X-Body-SHA256": body_digest(upload["body"])})
                return
            if self.command == "GET" and len(upload["body"]) == upload["length"]:
                self.send_bytes(200, bytes(upload["body"]),
                                {"X-Body-SHA256": body_digest(upload["body"])}, head=head)
                return
        self.send_bytes(405, b"unsupported TUS operation\n")

    def handle_content_range(self, path, body, head):
        key = path.rsplit("/", 1)[-1]
        with STATE.lock:
            upload = STATE.ranges.get(key)
            if self.command == "HEAD":
                if upload is None:
                    self.send_bytes(404, b"unknown upload\n", head=True)
                else:
                    self.send_bytes(204, headers={"Upload-Offset": len(upload["body"]),
                                                  "Upload-Length": upload["total"]}, head=True)
                return
            if self.command == "GET":
                if upload is None or len(upload["body"]) != upload["total"]:
                    self.send_bytes(404, b"upload incomplete\n")
                else:
                    self.send_bytes(200, bytes(upload["body"]),
                                    {"X-Body-SHA256": body_digest(upload["body"])}, head=head)
                return
            if self.command != "PUT":
                self.send_bytes(405, b"use PUT\n")
                return
            value = self.headers.get("Content-Range", "")
            try:
                unit, value = value.split(" ", 1)
                span, total_text = value.split("/", 1)
                start_text, end_text = span.split("-", 1)
                start, end, total = int(start_text), int(end_text), int(total_text)
                if unit != "bytes" or end < start or end - start + 1 != len(body):
                    raise ValueError
            except ValueError:
                self.send_bytes(400, b"invalid Content-Range\n")
                return
            if upload is None:
                upload = {"total": total, "body": bytearray()}
                STATE.ranges[key] = upload
            if upload["total"] != total or start != len(upload["body"]):
                self.send_bytes(409, headers={"Upload-Offset": len(upload["body"])})
                return
            if end >= total:
                self.send_bytes(416, b"range exceeds upload\n")
                return
            upload["body"].extend(body)
            complete = len(upload["body"]) == total
            self.send_bytes(201 if complete else 202,
                            headers={"Upload-Offset": len(upload["body"]),
                                     "X-Body-SHA256": body_digest(upload["body"])})

    def lock_allows(self, path):
        token = STATE.locks.get(path)
        return token is None or token in self.headers.get("If", "")

    def dav_multistatus(self, paths):
        root = ET.Element(f"{{{DAV}}}multistatus")
        for path in paths:
            response = ET.SubElement(root, f"{{{DAV}}}response")
            ET.SubElement(response, f"{{{DAV}}}href").text = path
            propstat = ET.SubElement(response, f"{{{DAV}}}propstat")
            prop = ET.SubElement(propstat, f"{{{DAV}}}prop")
            kind = "collection" if path in STATE.collections else "resource"
            ET.SubElement(prop, f"{{{DAV}}}resourcetype").text = kind
            for name, value in STATE.properties.get(path, {}).items():
                ET.SubElement(prop, name).text = value
            ET.SubElement(propstat, f"{{{DAV}}}status").text = "HTTP/1.1 200 OK"
        return ET.tostring(root, encoding="utf-8", xml_declaration=True)

    def handle_dav(self, path, body, head):
        with STATE.lock:
            exists = path in STATE.resources or path in STATE.collections
            if self.command == "OPTIONS":
                self.send_bytes(204, headers={
                    "DAV": "1, 2",
                    "Allow": ("OPTIONS, GET, HEAD, PUT, DELETE, PROPFIND, PROPPATCH, "
                              "MKCOL, COPY, MOVE, LOCK, UNLOCK"),
                })
                return
            if self.command == "MKCOL":
                collection = path if path.endswith("/") else path + "/"
                if body:
                    self.send_bytes(415, b"MKCOL body unsupported\n")
                elif collection in STATE.collections:
                    self.send_bytes(405, b"collection exists\n")
                elif parent_collection(collection) not in STATE.collections:
                    self.send_bytes(409, b"parent missing\n")
                else:
                    STATE.collections.add(collection)
                    self.send_bytes(201)
                return
            if self.command == "PUT":
                if parent_collection(path) not in STATE.collections:
                    self.send_bytes(409, b"parent missing\n")
                elif not self.lock_allows(path):
                    self.send_bytes(423, b"resource locked\n")
                else:
                    status = 204 if path in STATE.resources else 201
                    STATE.resources[path] = body
                    self.send_bytes(status, headers={"ETag": f'"{body_digest(body)}"'})
                return
            if self.command in ("GET", "HEAD"):
                if path not in STATE.resources:
                    self.send_bytes(404, b"missing resource\n", head=head)
                else:
                    value = STATE.resources[path]
                    self.send_bytes(200, value, {"ETag": f'"{body_digest(value)}"'}, head=head)
                return
            if self.command == "DELETE":
                if not exists:
                    self.send_bytes(404, b"missing resource\n")
                elif not self.lock_allows(path):
                    self.send_bytes(423, b"resource locked\n")
                else:
                    prefix = path if path.endswith("/") else path + "/"
                    STATE.resources = {key: value for key, value in STATE.resources.items()
                                       if key != path and not key.startswith(prefix)}
                    STATE.collections = {key for key in STATE.collections
                                         if key != path and not key.startswith(prefix)}
                    STATE.properties.pop(path, None)
                    STATE.locks.pop(path, None)
                    self.send_bytes(204)
                return
            if self.command == "PROPFIND":
                if not exists:
                    self.send_bytes(404, b"missing resource\n")
                    return
                depth = self.headers.get("Depth", "infinity")
                if depth not in ("0", "1"):
                    self.send_bytes(403, b"finite depth required\n")
                    return
                paths = [path]
                if depth == "1" and path in STATE.collections:
                    paths.extend(sorted(key for key in STATE.collections | set(STATE.resources)
                                        if key != path and parent_collection(key) == path))
                payload = self.dav_multistatus(paths)
                self.send_bytes(207, payload, {"Content-Type": "application/xml"}, head=head)
                return
            if self.command == "PROPPATCH":
                if not exists:
                    self.send_bytes(404, b"missing resource\n")
                    return
                try:
                    document = ET.fromstring(body)
                    values = STATE.properties.setdefault(path, {})
                    for action in document:
                        prop = action.find(f"{{{DAV}}}prop")
                        if prop is None:
                            continue
                        for item in prop:
                            if action.tag == f"{{{DAV}}}remove":
                                values.pop(item.tag, None)
                            else:
                                values[item.tag] = item.text or ""
                except ET.ParseError:
                    self.send_bytes(400, b"invalid property XML\n")
                    return
                payload = self.dav_multistatus([path])
                self.send_bytes(207, payload, {"Content-Type": "application/xml"})
                return
            if self.command in ("COPY", "MOVE"):
                destination = urlsplit(self.headers.get("Destination", "")).path
                if not exists or not destination.startswith("/matrix/dav/"):
                    self.send_bytes(400 if exists else 404, b"invalid destination\n")
                    return
                destination_exists = (destination in STATE.resources or
                                      destination in STATE.collections)
                if destination_exists and self.headers.get("Overwrite", "T").upper() == "F":
                    self.send_bytes(412, b"destination exists\n")
                    return
                if not self.lock_allows(path):
                    self.send_bytes(423, b"resource locked\n")
                    return
                if path in STATE.resources:
                    STATE.resources[destination] = STATE.resources[path]
                    if self.command == "MOVE":
                        del STATE.resources[path]
                else:
                    source = path if path.endswith("/") else path + "/"
                    target = destination if destination.endswith("/") else destination + "/"
                    STATE.collections.add(target)
                    for key, value in list(STATE.resources.items()):
                        if key.startswith(source):
                            STATE.resources[target + key[len(source):]] = value
                            if self.command == "MOVE":
                                del STATE.resources[key]
                    if self.command == "MOVE":
                        STATE.collections.discard(source)
                self.send_bytes(204 if destination_exists else 201)
                return
            if self.command == "LOCK":
                if not exists:
                    self.send_bytes(404, b"missing resource\n")
                    return
                token = STATE.locks.get(path) or f"opaquelocktoken:{uuid.uuid4()}"
                STATE.locks[path] = token
                payload = (f"<?xml version='1.0'?><D:prop xmlns:D='DAV:'><D:lockdiscovery>"
                           f"<D:activelock><D:locktoken><D:href>{token}</D:href></D:locktoken>"
                           f"</D:activelock></D:lockdiscovery></D:prop>").encode()
                self.send_bytes(200, payload, {"Content-Type": "application/xml",
                                               "Lock-Token": f"<{token}>"})
                return
            if self.command == "UNLOCK":
                token = self.headers.get("Lock-Token", "").strip("<>")
                if STATE.locks.get(path) != token:
                    self.send_bytes(409, b"lock token mismatch\n")
                else:
                    del STATE.locks[path]
                    self.send_bytes(204)
                return
        self.send_bytes(405, b"unsupported WebDAV operation\n")

    do_GET = dispatch
    do_HEAD = lambda self: self.dispatch(head=True)
    do_POST = dispatch
    do_PUT = dispatch
    do_PATCH = dispatch
    do_DELETE = dispatch
    do_OPTIONS = dispatch
    do_TRACE = dispatch
    do_PROPFIND = dispatch
    do_PROPPATCH = dispatch
    do_MKCOL = dispatch
    do_COPY = dispatch
    do_MOVE = dispatch
    do_LOCK = dispatch
    do_UNLOCK = dispatch


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8001)
    args = parser.parse_args()
    server = http.server.ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    server.serve_forever()


if __name__ == "__main__":
    main()
