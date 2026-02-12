FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

EXPOSE 8080

CMD ["python", "-c", "print('Hello from a vulnerable container!')"]
