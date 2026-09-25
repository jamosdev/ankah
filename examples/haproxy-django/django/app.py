import os
from django.conf import settings
from django.core.wsgi import get_wsgi_application
from django.http import HttpResponse
from django.urls import path

settings.configure(
    DEBUG=False,
    SECRET_KEY=os.environ.get("DJANGO_SECRET_KEY", "example-only-key"),
    ALLOWED_HOSTS=["localhost", "ankah"],
    ROOT_URLCONF=__name__,
)


def index(request):
    return HttpResponse("Django through Ankah and HAProxy\n")


def upload(request):
    return HttpResponse(f"received {len(request.body)} bytes\n")


urlpatterns = [path("", index), path("health", index), path("upload", upload)]
application = get_wsgi_application()
