# Build context is the example root so the shared common/ package is copied
# into both backend images unchanged.
FROM python:3.13.15-slim-trixie@sha256:8d9d0b8bcf6506481eae4907c18f5e3e7902e629f5f6d684f9e7c32e85e3ddf0
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 HOME=/tmp
COPY django/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt
COPY common /app/common
COPY django/app.py /app/app.py
WORKDIR /app
USER nobody
HEALTHCHECK --interval=3s --timeout=3s --retries=40 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=2)"
ENTRYPOINT ["/app/common/entrypoint.sh"]
CMD ["gunicorn", "app:application", "--bind", "0.0.0.0:8000", "--workers", "2", "--worker-class", "sync"]
