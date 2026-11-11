FROM python:3.12-slim

WORKDIR /service
ENV PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    openssl \
    iproute2 \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY pin_manager /service/pin_manager
COPY docker-entrypoint.sh /docker-entrypoint.sh
RUN chmod +x /docker-entrypoint.sh

ENV LISTEN_PORT=8080
EXPOSE 8080 80
ENTRYPOINT ["/docker-entrypoint.sh"]
