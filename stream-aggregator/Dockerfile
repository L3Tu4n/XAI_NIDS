FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    librdkafka-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# --- SỬA ĐOẠN NÀY ---
# Copy đúng tên file feature_engineer.py
COPY aggregator.py .
COPY feature_engineer.py . 
# --------------------

CMD ["python", "-u", "aggregator.py"]