import hashlib
import json
import re
import uuid


STATIC_BODY = bytes(range(256)) * 1024


def test_static_ranges_and_reassembly(client):
    path = "/static/range.bin"
    full = client.request("GET", path, headers={"Accept-Encoding": "identity"})
    assert full.status == 200 and full.body == STATIC_BODY
    assert full.headers["accept-ranges"] == "bytes"
    etag = full.headers["etag"]

    single = client.request("GET", path, headers={"Range": "bytes=10-39",
                                                   "Accept-Encoding": "identity"})
    assert single.status == 206 and single.body == STATIC_BODY[10:40]
    assert single.headers["content-range"] == f"bytes 10-39/{len(STATIC_BODY)}"
    opened = client.request("GET", path, headers={"Range": "bytes=100-",
                                                   "Accept-Encoding": "identity"})
    assert opened.status == 206 and opened.body == STATIC_BODY[100:]
    suffix = client.request("GET", path, headers={"Range": "bytes=-73",
                                                   "Accept-Encoding": "identity"})
    assert suffix.status == 206 and suffix.body == STATIC_BODY[-73:]
    merged = client.request("GET", path, headers={"Range": "bytes=0-9,5-19",
                                                   "Accept-Encoding": "identity"})
    assert merged.status == 206 and merged.body == STATIC_BODY[:20]

    multiple = client.request("GET", path, headers={"Range": "bytes=0-9,30-39",
                                                     "Accept-Encoding": "identity"})
    assert multiple.status == 206
    assert multiple.headers["content-type"].startswith("multipart/byteranges")
    assert STATIC_BODY[:10] in multiple.body and STATIC_BODY[30:40] in multiple.body

    matching = client.request("GET", path, headers={"Range": "bytes=0-9",
                                                     "If-Range": etag,
                                                     "Accept-Encoding": "identity"})
    assert matching.status == 206 and matching.body == STATIC_BODY[:10]
    stale = client.request("GET", path, headers={"Range": "bytes=0-9",
                                                  "If-Range": '"stale"',
                                                  "Accept-Encoding": "identity"})
    assert stale.status == 200 and stale.body == STATIC_BODY
    assert stale.headers["etag"] == etag
    invalid = client.request("GET", path, headers={"Range": "bytes=999999-1000000",
                                                    "Accept-Encoding": "identity"})
    assert invalid.status == 416
    assert invalid.headers["content-range"] == f"bytes */{len(STATIC_BODY)}"

    parts = []
    step = len(STATIC_BODY) // 4
    for start in range(0, len(STATIC_BODY), step):
        end = min(start + step, len(STATIC_BODY)) - 1
        response = client.request("GET", path, headers={
            "Range": f"bytes={start}-{end}", "Accept-Encoding": "identity"})
        assert response.status == 206
        parts.append(response.body)
    assert hashlib.sha256(b"".join(parts)).digest() == hashlib.sha256(STATIC_BODY).digest()

    records = client.request("GET", "/matrix/_records?path=%2Fstatic%2Frange.bin")
    assert json.loads(records.body)["count"] == 0


def test_tus_resume_and_digest(client):
    payload = bytes(range(251)) * 257
    options = client.request("OPTIONS", "/matrix/tus")
    assert options.status == 204 and options.headers["tus-version"] == "1.0.0"
    created = client.request("POST", "/matrix/tus", headers={
        "Tus-Resumable": "1.0.0", "Upload-Length": str(len(payload))})
    assert created.status == 201
    location = created.headers["location"]
    first = payload[:17001]
    response = client.request("PATCH", location, headers={
        "Tus-Resumable": "1.0.0", "Upload-Offset": "0",
        "Content-Type": "application/offset+octet-stream",
        "Content-Length": str(len(first))}, content=first)
    assert response.status == 204 and int(response.headers["upload-offset"]) == len(first)
    progress = client.request("HEAD", location, headers={"Tus-Resumable": "1.0.0"})
    assert progress.status == 200 and int(progress.headers["upload-offset"]) == len(first)
    wrong = client.request("PATCH", location, headers={
        "Tus-Resumable": "1.0.0", "Upload-Offset": "1",
        "Content-Type": "application/offset+octet-stream"}, content=b"wrong")
    assert wrong.status == 409 and int(wrong.headers["upload-offset"]) == len(first)
    rest = payload[len(first):]
    resumed = client.request("PATCH", location, headers={
        "Tus-Resumable": "1.0.0", "Upload-Offset": str(len(first)),
        "Content-Type": "application/offset+octet-stream",
        "Content-Length": str(len(rest))}, content=iter([rest[:5000], rest[5000:]]))
    assert resumed.status == 204 and int(resumed.headers["upload-offset"]) == len(payload)
    final = client.request("GET", location)
    assert final.status == 200 and hashlib.sha256(final.body).digest() == hashlib.sha256(payload).digest()


def test_content_range_contract(client):
    payload = bytes(range(199)) * 97
    path = f"/matrix/content-range/{uuid.uuid4().hex}"
    first = payload[:4096]
    response = client.request("PUT", path, headers={
        "Content-Range": f"bytes 0-{len(first) - 1}/{len(payload)}"}, content=first)
    assert response.status == 202 and int(response.headers["upload-offset"]) == len(first)
    duplicate = client.request("PUT", path, headers={
        "Content-Range": f"bytes 0-{len(first) - 1}/{len(payload)}"}, content=first)
    assert duplicate.status == 409
    out_of_order = client.request("PUT", path, headers={
        "Content-Range": f"bytes 5000-5002/{len(payload)}"}, content=b"bad")
    assert out_of_order.status == 409
    progress = client.request("HEAD", path)
    assert progress.status == 204 and int(progress.headers["upload-offset"]) == len(first)
    rest = payload[len(first):]
    final = client.request("PUT", path, headers={
        "Content-Range": f"bytes {len(first)}-{len(payload) - 1}/{len(payload)}"},
        content=rest)
    assert final.status == 201 and int(final.headers["upload-offset"]) == len(payload)
    result = client.request("GET", path)
    assert result.status == 200 and result.body == payload
    assert result.headers["x-body-sha256"] == hashlib.sha256(payload).hexdigest()


def test_webdav_state_transitions(client, endpoint):
    namespace = f"/matrix/dav/{uuid.uuid4().hex}/"
    source = namespace + "source.bin"
    copied = namespace + "copied.bin"
    moved = namespace + "moved.bin"
    options = client.request("OPTIONS", namespace)
    assert options.status == 204
    assert {item.strip() for item in options.headers["dav"].split(",")} == {"1", "2"}
    assert {item.strip() for item in options.headers["allow"].split(",")} == {
        "OPTIONS", "GET", "HEAD", "PUT", "DELETE", "PROPFIND", "PROPPATCH",
        "MKCOL", "COPY", "MOVE", "LOCK", "UNLOCK",
    }
    assert client.request("MKCOL", namespace).status == 201
    payload = b"webdav\x00payload\xff"
    assert client.request("PUT", source, content=payload).status == 201
    fetched = client.request("GET", source)
    assert fetched.status == 200 and fetched.body == payload
    headed = client.request("HEAD", source)
    assert headed.status == 200 and not headed.body

    depth_zero = client.request("PROPFIND", source, headers={"Depth": "0"})
    assert depth_zero.status == 207 and source.encode() in depth_zero.body
    depth_one = client.request("PROPFIND", namespace, headers={"Depth": "1"})
    assert depth_one.status == 207 and source.encode() in depth_one.body
    assert client.request("PROPFIND", namespace, headers={"Depth": "infinity"}).status == 403

    property_body = (b"<?xml version='1.0'?><D:propertyupdate xmlns:D='DAV:' "
                     b"xmlns:T='urn:ankah:test'><D:set><D:prop><T:color>blue</T:color>"
                     b"</D:prop></D:set></D:propertyupdate>")
    changed = client.request("PROPPATCH", source, headers={"Content-Type": "application/xml"},
                             content=property_body)
    assert changed.status == 207
    assert b"blue" in client.request("PROPFIND", source, headers={"Depth": "0"}).body
    removal_body = (b"<?xml version='1.0'?><D:propertyupdate xmlns:D='DAV:' "
                    b"xmlns:T='urn:ankah:test'><D:remove><D:prop><T:color/>"
                    b"</D:prop></D:remove></D:propertyupdate>")
    removed = client.request("PROPPATCH", source,
                             headers={"Content-Type": "application/xml"},
                             content=removal_body)
    assert removed.status == 207
    properties = client.request("PROPFIND", source, headers={"Depth": "0"})
    assert properties.status == 207 and b"color" not in properties.body

    destination = endpoint["url"] + copied
    assert client.request("COPY", source, headers={"Destination": destination}).status == 201
    assert client.request("COPY", source, headers={"Destination": destination,
                                                    "Overwrite": "F"}).status == 412
    moved_destination = endpoint["url"] + moved
    assert client.request("MOVE", copied, headers={"Destination": moved_destination}).status == 201
    assert client.request("GET", moved).body == payload

    locked = client.request("LOCK", moved, headers={"Timeout": "Second-3600"}, content=(
        b"<D:lockinfo xmlns:D='DAV:'><D:lockscope><D:exclusive/></D:lockscope>"
        b"<D:locktype><D:write/></D:locktype></D:lockinfo>"))
    assert locked.status == 200
    token = locked.headers["lock-token"]
    assert client.request("PUT", moved, content=b"blocked").status == 423
    assert client.request("PUT", moved, headers={"If": f"({token})"}, content=b"updated").status == 204
    assert client.request("UNLOCK", moved, headers={"Lock-Token": "<wrong>"}).status == 409
    assert client.request("UNLOCK", moved, headers={"Lock-Token": token}).status == 204
    assert client.request("DELETE", namespace).status == 204
