FROM python:3.10-slim

WORKDIR /opt/es-consumer

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY consumer.py .

# Run consumer
CMD ["python", "-u", "consumer.py"]