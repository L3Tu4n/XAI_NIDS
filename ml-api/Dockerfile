FROM python:3.11-slim

WORKDIR /app

# Cài đặt dependencies hệ thống
RUN apt-get update && apt-get install -y \
    curl \
    libgomp1 \
    && rm -rf /var/lib/apt/lists/*

# Copy và cài đặt Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY app.py .
COPY gunicorn_config.py .

# Expose port
EXPOSE 5000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD curl -f http://localhost:5000/health || exit 1

# ⭐️ SỬA LỖI: Dùng gunicorn config file
CMD ["gunicorn", "-c", "gunicorn_config.py", "app:app"]