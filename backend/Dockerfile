FROM python:3.12-slim

WORKDIR /app
ENV PYTHONUNBUFFERED=1

# Install build dependencies, install Python packages, then remove build dependencies
COPY requirements.txt /app/requirements.txt
RUN apt-get update && \
    apt-get install -y --no-install-recommends gcc libssl-dev && \
    pip install --no-cache-dir -r /app/requirements.txt && \
    apt-get purge -y --auto-remove gcc libssl-dev && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

COPY app /app/app

# EXPOSE 8080
# Update the port below if your application listens on a different port


CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080", "--log-level", "debug"]







