import os
import time

from django.conf import settings
from django.core.wsgi import get_wsgi_application
from django.http import JsonResponse
from django.urls import path

from common.metrics import REQUESTS, SECONDS
from common.pi import MAX_N, client_class, compute_pi, parse_n

BACKEND = "django"
settings.configure(
    DEBUG=False,
    SECRET_KEY=os.environ.get("DJANGO_SECRET_KEY", "dots-demo-only-key"),
    ALLOWED_HOSTS=["ankah.test", "django", "localhost"],
    ROOT_URLCONF=__name__,
    MIDDLEWARE=[],
    INSTALLED_APPS=[],
)


def healthz(request):
    return JsonResponse({"backend": BACKEND, "status": "ok"})


def pi(request):
    client = client_class(request.headers.get("User-Agent"))
    n = parse_n(request.GET.get("n"))
    if n is None:
        REQUESTS.labels(BACKEND, client, "400").inc()
        return JsonResponse({"backend": BACKEND, "error": f"n must be 1..{MAX_N}"}, status=400)
    started = time.perf_counter()
    value = compute_pi(n)
    elapsed = time.perf_counter() - started
    SECONDS.labels(BACKEND, client).observe(elapsed)
    REQUESTS.labels(BACKEND, client, "200").inc()
    return JsonResponse({"backend": BACKEND, "n": n, "pi": value,
                         "elapsed_ms": round(elapsed * 1000, 3)})


urlpatterns = [path("healthz", healthz), path("pi", pi)]
application = get_wsgi_application()
