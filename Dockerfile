FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
RUN mkdir -p /var/run/resilience-pki /var/run/resilience-keys/private /var/run/resilience-keys/public /var/lib/resilience/state \
    && chown -R 10001:10001 /var/run/resilience-pki /var/run/resilience-keys /var/lib/resilience
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY resilience ./resilience
COPY docs ./docs
COPY README.md ./README.md
USER 10001:10001
EXPOSE 8766 8080
ENTRYPOINT ["python", "-m", "resilience.cli"]
