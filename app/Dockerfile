FROM python:3.12-slim

WORKDIR /service
ENV PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY pin_manager /service/pin_manager

ENV LISTEN_PORT=8080
EXPOSE 8080 80
CMD ["sh", "-c", "uvicorn pin_manager.main:app --host 0.0.0.0 --port ${LISTEN_PORT:-8080}"]
