FROM python:3.12-alpine
RUN pip install --no-cache-dir Django==6.1.1 gunicorn==26.2.0
WORKDIR /app
COPY . .
CMD ["gunicorn", "app:application", "--bind", "0.0.0.0:8000", "--workers", "1"]
