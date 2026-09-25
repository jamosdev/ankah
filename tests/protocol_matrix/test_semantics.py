import hashlib
import json
import uuid
from urllib.parse import quote, urlsplit

import pytest

from clients import connect_request, raw_h1_request


def unique_path(label):
    return f"/matrix/{label}/{uuid.uuid4().hex}"


def record_count(client, path=None, target=None):
    name, value = ("target", target) if target is not None else ("path", path)
    response = client.request("GET", f"/matrix/_records?{name}={quote(value, safe='')}")
    assert response.status == 200
    return json.loads(response.body)["count"]


def test_advertises_public_h3_port(client, endpoint):
    if endpoint["protocol"] == "h3":
        pytest.skip("HTTP/3 discovery is checked on HTTP/1.1 and HTTP/2")
    response = client.request("GET", "/matrix/_ready")
    split = urlsplit(endpoint["url"])
    expected = split.port or 443
    assert f'h3=":{expected}"' in response.headers.get("alt-svc", "")


@pytest.mark.parametrize("method", [
    "GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "TRACE",
])
def test_core_methods(client, method):
    path = unique_path("methods") + "?first=1&second=two%20words"
    body = b"method-body\x00\xff" if method in ("POST", "PUT", "PATCH") else b""
    response = client.request(method, path, headers={"X-Matrix-Value": "kept"}, content=body)
    expected = 204 if method in ("DELETE", "OPTIONS") else 200
    assert response.status == expected
    assert response.headers["x-fixture-method"] == method
    assert response.headers["x-fixture-target"] == path
    assert response.headers["x-fixture-body-sha256"] == hashlib.sha256(body).hexdigest()
    if method not in ("HEAD", "DELETE", "OPTIONS", "TRACE"):
        recorded = json.loads(response.body)
        assert recorded["method"] == method
        assert recorded["target"] == path
        assert recorded["headers"]["x-matrix-value"] == "kept"


BODY_CASES = [
    ("empty", b"", {}),
    ("json", b'{"answer":42,"text":"hello"}', {"Content-Type": "application/json"}),
    ("urlencoded", b"first=one&second=two+words",
     {"Content-Type": "application/x-www-form-urlencoded"}),
    ("binary", bytes(range(256)) * 8, {"Content-Type": "application/octet-stream"}),
    ("fixed", b"fixed-length-body", {"Content-Type": "text/plain"}),
]


@pytest.mark.parametrize("name,body,headers", BODY_CASES,
                         ids=[item[0] for item in BODY_CASES])
def test_post_body_forms(client, name, body, headers):
    path = unique_path(name)
    response = client.request("POST", path, headers=headers, content=body)
    assert response.status == 200
    recorded = json.loads(response.body)
    assert recorded["body_length"] == len(body)
    assert recorded["body_sha256"] == hashlib.sha256(body).hexdigest()


def test_multipart_text_and_file(client):
    boundary = "ankah-matrix-boundary"
    body = (f"--{boundary}\r\nContent-Disposition: form-data; name=note\r\n\r\n"
            f"hello\r\n--{boundary}\r\nContent-Disposition: form-data; name=file; "
            f"filename=data.bin\r\nContent-Type: application/octet-stream\r\n\r\n").encode()
    body += b"\x00binary\xffdata"
    body += f"\r\n--{boundary}--\r\n".encode()
    response = client.request("POST", unique_path("multipart"), headers={
        "Content-Type": f"multipart/form-data; boundary={boundary}",
        "Content-Length": str(len(body)),
    }, content=body)
    assert response.status == 200
    assert json.loads(response.body)["body_sha256"] == hashlib.sha256(body).hexdigest()


def test_streamed_declared_length(client):
    chunks = [b"stream-", b"split-", b"body\x00\xff"]
    expected = b"".join(chunks)
    response = client.request("POST", unique_path("streamed"), headers={
        "Content-Type": "application/octet-stream",
        "Content-Length": str(len(expected)),
    }, content=iter(chunks))
    assert response.status == 200
    assert json.loads(response.body)["body_sha256"] == hashlib.sha256(expected).hexdigest()


def test_connect_is_rejected_without_forwarding(client, endpoint):
    authority = f"connect-{uuid.uuid4().hex}.invalid:443"
    before = record_count(client, target=authority)
    response = connect_request(endpoint["url"], endpoint["protocol"],
                               endpoint["ca_file"], authority)
    assert 400 <= response.status < 500
    assert record_count(client, target=authority) == before


def test_expect_100_continue(endpoint):
    if endpoint["protocol"] != "h1":
        pytest.skip("interim response is an HTTP/1.1 framing test")
    split = urlsplit(endpoint["url"])
    path = unique_path("expect")
    body = b"continue-body\x00\xff"
    head = (f"POST {path} HTTP/1.1\r\nHost: {split.netloc}\r\n"
            f"Content-Length: {len(body)}\r\nExpect: 100-continue\r\n"
            f"Content-Type: application/octet-stream\r\nConnection: close\r\n\r\n").encode()
    response = raw_h1_request(endpoint["url"], endpoint["ca_file"], head, body,
                              wait_for_continue=True)
    assert response.status == 200
    assert json.loads(response.body)["body_sha256"] == hashlib.sha256(body).hexdigest()


def test_http1_chunked_framing(endpoint):
    if endpoint["protocol"] != "h1":
        pytest.skip("chunked transfer coding exists only in HTTP/1.1")
    split = urlsplit(endpoint["url"])
    path = unique_path("chunked")
    expected = b"Wikipedia\x00\xff"
    wire = (b"4;part=one\r\nWiki\r\n5\r\npedia\r\n2\r\n\x00\xff\r\n"
            b"0\r\nX-Chunk-Result: complete\r\n\r\n")
    head = (f"POST {path} HTTP/1.1\r\nHost: {split.netloc}\r\n"
            "Transfer-Encoding: chunked\r\nTrailer: X-Chunk-Result\r\n"
            "Content-Type: application/octet-stream\r\nConnection: close\r\n\r\n").encode()
    response = raw_h1_request(endpoint["url"], endpoint["ca_file"], head, wire)
    assert response.status == 200
    assert json.loads(response.body)["body_sha256"] == hashlib.sha256(expected).hexdigest()
