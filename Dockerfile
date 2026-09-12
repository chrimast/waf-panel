FROM python:3.11-slim
WORKDIR /app
RUN apt-get update \
    && apt-get install -y --no-install-recommends docker.io fail2ban ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
ENV WAF_PANEL_HOME=/app \
    PYTHONUNBUFFERED=1
EXPOSE 18081
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "18081"]
