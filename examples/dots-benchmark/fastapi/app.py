import time

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from common.metrics import REQUESTS, SECONDS
from common.pi import MAX_N, client_class, compute_pi, parse_n

BACKEND = "fastapi"
app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)


@app.get("/healthz")
def healthz():
    return {"backend": BACKEND, "status": "ok"}


# A plain def endpoint runs in the worker's thread pool, as a sync Django
# view runs in its worker; the computation holds the GIL either way.
@app.get("/pi")
def pi(request: Request):
    client = client_class(request.headers.get("user-agent"))
    n = parse_n(request.query_params.get("n"))
    if n is None:
        REQUESTS.labels(BACKEND, client, "400").inc()
        return JSONResponse({"backend": BACKEND, "error": f"n must be 1..{MAX_N}"},
                            status_code=400)
    started = time.perf_counter()
    value = compute_pi(n)
    elapsed = time.perf_counter() - started
    SECONDS.labels(BACKEND, client).observe(elapsed)
    REQUESTS.labels(BACKEND, client, "200").inc()
    return {"backend": BACKEND, "n": n, "pi": value, "elapsed_ms": round(elapsed * 1000, 3)}
