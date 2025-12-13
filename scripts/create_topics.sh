#!/bin/bash

# Cấu hình
CONTAINER_NAME="kafka"
KAFKA_BIN="/opt/kafka/bin" # Đường dẫn mặc định trong image apache/kafka
BOOTSTRAP_SERVER="localhost:9092"

echo "⏳ Đang đợi Kafka khởi động..."
# Sleep nhẹ để đảm bảo Kafka đã up nếu chạy ngay sau docker-compose up
sleep 5

# Hàm tạo topic
create_topic() {
    local topic_name=$1
    local partitions=$2
    local retention_ms=$3 # 86400000 ms = 1 ngày

    echo "🚀 Đang tạo topic: $topic_name..."
    
    docker exec $CONTAINER_NAME $KAFKA_BIN/kafka-topics.sh \
        --create \
        --if-not-exists \
        --bootstrap-server $BOOTSTRAP_SERVER \
        --topic $topic_name \
        --partitions $partitions \
        --replication-factor 1 \
        --config retention.ms=$retention_ms

    if [ $? -eq 0 ]; then
        echo "✅ Topic '$topic_name' đã sẵn sàng."
    else
        echo "❌ Lỗi khi tạo topic '$topic_name'."
    fi
}

echo "============================================"
echo "KHỞI TẠO KAFKA TOPICS CHO NIDS SYSTEM"
echo "============================================"

# 1. Topic: zeek-logs (Input đầu vào từ Filebeat)
# - Partitions: 3 (Để Stream Aggregator có thể chạy song song nhiều worker nếu cần)
# - Retention: 24 giờ (86400000 ms) - Log thô rất nặng, chỉ lưu ngắn hạn để xử lý
create_topic "zeek-conn" 3 86400000

# 2. Topic: ml-predictions (Output đầu ra chứa cảnh báo)
# - Partitions: 1 (Lượng dữ liệu cảnh báo ít hơn nhiều, 1 partition là đủ)
# - Retention: 7 ngày (604800000 ms) - Cần lưu lâu hơn để trace lại
create_topic "ml-predictions" 1 604800000
create_topic "xai-queue" 1 604800000
echo "============================================"
echo "DANH SÁCH TOPICS HIỆN CÓ:"
docker exec $CONTAINER_NAME $KAFKA_BIN/kafka-topics.sh --list --bootstrap-server $BOOTSTRAP_SERVER
echo "============================================"