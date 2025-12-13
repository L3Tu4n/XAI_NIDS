# Sử dụng python slim để nhẹ, nhưng cần cài thêm libgomp1
FROM python:3.11-slim

WORKDIR /app

# ⭐️ CÀI ĐẶT THƯ VIỆN HỆ THỐNG CẦN THIẾT (FIX LỖI LIBGOMP)
RUN apt-get update && apt-get install -y \
    libgomp1 \
    && rm -rf /var/lib/apt/lists/*

# Copy và cài đặt requirements
COPY requirements.txt .
# Nâng cấp pip để tránh lỗi build
RUN pip install --upgrade pip
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code
COPY . .

# Chạy service
CMD ["python", "-u", "xai_llm.py"]