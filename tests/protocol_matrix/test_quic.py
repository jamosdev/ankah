import hashlib
from types import SimpleNamespace

import pytest

from clients import H3_ALPN, _h3_negotiation_unavailable


@pytest.mark.parametrize(("alpn", "code", "reason", "expected"), [
    (None, 0x1, "Idle timeout", True),
    (None, 0x178, "no application protocol", True),
    ("not-h3", None, None, True),
    (None, 0x12A, "certificate required", False),
    (H3_ALPN[0], 0x1, "Idle timeout", False),
])
def test_h3_unavailable_is_limited_to_negotiation(alpn, code, reason, expected):
    termination = None if code is None else SimpleNamespace(
        error_code=code, reason_phrase=reason)
    protocol = SimpleNamespace(alpn=alpn, termination=termination)
    assert _h3_negotiation_unavailable(protocol) is expected
    assert not _h3_negotiation_unavailable(None)


@pytest.mark.quic
def test_quic_independent_concurrent_streams(client, endpoint):
    if endpoint["protocol"] != "h3":
        pytest.skip("QUIC transport test")
    requests = [("GET", f"/matrix/quic/stream-{number}?value={number}",
                 {"x-stream-number": str(number)}, b"") for number in range(8)]
    responses = client.concurrent(requests)
    assert len(responses) == len(requests)
    for number, response in enumerate(responses):
        assert response.version == "HTTP/3"
        assert response.status == 200
        assert response.headers["x-fixture-target"].endswith(f"?value={number}")


@pytest.mark.quic
def test_native_h3_upload_windows_and_unknown_length_limit(client, endpoint):
    if endpoint["profile"] != "native" or endpoint["protocol"] != "h3":
        pytest.skip("native HTTP/3 upload flow control test")

    def create_upload(length):
        response = client.request("POST", "/matrix/tus", headers={
            "Tus-Resumable": "1.0.0", "Upload-Length": str(length),
        })
        assert response.status == 201
        return response.headers["location"]

    declared = 17 * 1024 * 1024
    location = create_upload(declared)
    response = client.request("PATCH", location, headers={
        "Tus-Resumable": "1.0.0",
        "Upload-Offset": "0",
        "Content-Type": "application/offset+octet-stream",
        "Content-Length": str(declared),
    }, content=b"x" * declared)
    assert response.status == 204
    assert response.headers["upload-offset"] == str(declared)
    download = client.request("GET", location)
    assert download.status == 200
    assert len(download.body) == declared
    assert hashlib.sha256(download.body).hexdigest() == hashlib.sha256(
        b"x" * declared).hexdigest()

    unknown = 1024 * 1024
    location = create_upload(unknown)
    response = client.request("PATCH", location, headers={
        "Tus-Resumable": "1.0.0",
        "Upload-Offset": "0",
        "Content-Type": "application/offset+octet-stream",
    }, content=b"x" * unknown)
    assert response.status == 204
    assert response.headers["upload-offset"] == str(unknown)

    response = client.request("POST", "/matrix/h3/unknown-limit",
                              content=b"x" * declared)
    assert response.status == 413


@pytest.mark.quic
def test_native_h3_response_trailers(client, endpoint):
    if endpoint["profile"] != "native" or endpoint["protocol"] != "h3":
        pytest.skip("native HTTP/3 trailer test")
    response = client.request("GET", "/matrix/_trailers")
    assert response.status == 200
    assert response.body == b"hello"
    assert response.headers["x-matrix-trailer"] == "complete"
