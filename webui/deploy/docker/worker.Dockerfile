FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app/webui \
    DAKSH_NON_INTERACTIVE=1

WORKDIR /app

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY . /app

CMD ["celery", "-A", "worker.tasks.celery_app", "worker", "--loglevel=INFO", "--concurrency=1"]
