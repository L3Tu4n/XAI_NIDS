# XAI_NIDS – Explainable AI-based Network Intrusion Detection System

## 1. Giới thiệu

**XAI_NIDS** là hệ thống phát hiện xâm nhập mạng (NIDS) ứng dụng Machine Learning kết hợp **Explainable AI (XAI)** và **Large Language Model (LLM)** nhằm:

* Phát hiện các hành vi tấn công mạng (ví dụ: SSH brute-force, scanning, DoS, botnet…)
* Giải thích *tại sao* mô hình ML đưa ra cảnh báo (SHAP)
* Sinh diễn giải ngôn ngữ tự nhiên và gợi ý rule IDS (Gemini/OpenAI)

Hệ thống được thiết kế theo kiến trúc **streaming – microservices**, phù hợp cho nghiên cứu và triển khai thử nghiệm SOC.

---

## 2. Kiến trúc tổng thể

```
Traffic → Zeek → Kafka → Stream Aggregator → ML Inference
                                       ↓
                                  XAI + LLM
                                       ↓
                                Elasticsearch → Kibana
```

### Các thành phần chính

* **Zeek**: Thu thập log mạng (conn.log, http.log, dns.log…)
* **Kafka**: Message bus cho pipeline streaming
* **Stream Aggregator**: Tổng hợp flow + feature engineering
* **ML API**: Suy luận mô hình ML (LightGBM – Tri-Training)
* **XAI + LLM Service**:

  * SHAP: giải thích feature
  * Gemini/OpenAI: diễn giải cho SOC analyst
* **Elasticsearch + Kibana**: Lưu trữ & hiển thị cảnh báo

---

## 3. Yêu cầu hệ thống

### Phần mềm

* Docker >= 24.x
* Docker Compose v2
* Linux (Ubuntu 20.04 / 22.04 khuyến nghị)

### Phần cứng (khuyến nghị)

* CPU: ≥ 4 cores
* RAM: ≥ 8 GB (12–16 GB tốt hơn cho Elastic + ML)

---

## 4. Cấu trúc thư mục

```
ml-nids-project/
├── docker-compose.yml
├── models/                 # Model & metadata đã train
├── stream-aggregator/      # Kafka stream + feature engineering
├── ml-api/                 # ML inference service
├── xai_llm_service/        # SHAP + LLM explanation
├── es-consumer/            # Ghi prediction vào Elasticsearch
├── Train-ML/               # Code huấn luyện & đánh giá (offline)
├── scripts/                # Script tiện ích (test, create topic)
└── README.md
```

---

## 5. Chuẩn bị trước khi chạy

### 5.1. Tạo file biến môi trường (.env)

Tùy chỉnh lại các trường Liên quan đến biến môi trường, IP các thành phần trong hệ thống

```env
# Kafka
KAFKA_BOOTSTRAP_SERVERS=kafka:9092

# Elasticsearch
ES_HOSTS=https://elasticsearch:9200
ES_USERNAME=elastic
ES_PASSWORD=changeme

# LLM (chọn 1 trong 2)
LLM_PROVIDER=gemini
GEMINI_API_KEY=YOUR_GEMINI_API_KEY

# OPENAI_API_KEY=YOUR_OPENAI_API_KEY
```

⚠️ **Không commit file `.env` lên GitHub**.

---
### 5.2. Cấu hình và tạo service filebeat-kafka

Trên máy chạy Zeek, tiến hành cấu hình Filebeat để gửi log Zeek vào Kafka.

5.2.1. Tạo thư mục và file cấu hình Filebeat
sudo mkdir -p /etc/filebeat-kafka
sudo nano /etc/filebeat-kafka/filebeat.yml


Sao chép nội dung cấu hình từ repository:

Zeek_file/filebeat.yml


vào file:

/etc/filebeat-kafka/filebeat.yml

5.2.2. Tạo systemd service cho Filebeat

Tạo file service:

sudo nano /etc/systemd/system/filebeat-kafka.service


Nội dung file:

[Unit]
Description=Filebeat Kafka for Zeek Logs
After=network.target

[Service]
Type=simple
ExecStart=/usr/share/filebeat/filebeat \
  -c /etc/filebeat-kafka/filebeat.yml \
  -path.home /usr/share/filebeat \
  -path.config /etc/filebeat-kafka \
  -path.data /var/lib/filebeat-kafka \
  -path.logs /var/log/filebeat-kafka
Restart=always
User=root

[Install]
WantedBy=multi-user.target

5.2.3. Reload systemd và khởi động service
sudo systemctl daemon-reexec
sudo systemctl daemon-reload
sudo systemctl enable filebeat-kafka
sudo systemctl start filebeat-kafka


Kiểm tra trạng thái:

sudo systemctl status filebeat-kafka

5.2.4. Kiểm tra log Filebeat
journalctl -u filebeat-kafka -f


Nếu cấu hình đúng, Filebeat sẽ gửi log Zeek (conn.log, http.log, dns.log) vào Kafka topic tương ứng.
## 6. Khởi động hệ thống

### 6.1. Build & chạy toàn bộ services

```bash
docker compose up -d --build
```
Chạy script tạo topic:
```bash
./scripts/test_pipeline.sh
```
Khởi động lại docker
```bash
docker compose up -d 
```
Kiểm tra trạng thái:

```bash
docker compose ps
```

---

## 7. Mô phỏng tấn công (Demo SSH Brute Force)

### 7.1. Bật SSH server (máy target)

```bash
sudo systemctl enable ssh
sudo systemctl start ssh
```

### 7.2. Giả lập tấn công brute force (máy attacker)

Ví dụ dùng `hydra`:

```bash
hydra -l root -P password.txt ssh://<TARGET_IP>
```

Hoặc dùng script test:

```bash
bash scripts/test_pipeline.sh
```

---

## 8. Theo dõi kết quả

### 8.1. Log services

```bash
docker compose logs -f stream-aggregator
docker compose logs -f es-consumer
docker compose logs -f ml-api
docker compose logs -f xai_llm_service
```

### 8.2. Elasticsearch

* Index: `ml-nids-alerts`
* Trường XAI:

  * `xai_shap.top_features`
  * `xai_explanation`
  * `xai_detection_rule`

Truy cập Kibana:

```
http://[IP Kibana]:5601
```

---

## 9. Huấn luyện lại mô hình (tuỳ chọn)

```bash
cd Train-ML/scripts
python train_lgbm_tri_training.py
```

Sau khi train xong, copy model & metadata sang thư mục `models/`.

---

## 10. Ý nghĩa học thuật

Đồ án tập trung vào:

* Ứng dụng **Explainable AI (SHAP)** cho NIDS
* Kết hợp **ML + LLM** để tăng khả năng diễn giải cho SOC
* Kiến trúc streaming thực tế (Zeek → Kafka → Elastic)

Phù hợp cho:

* Khoá luận tốt nghiệp
* Nghiên cứu SOC / Blue Team
* Demo XAI trong an ninh mạng

---

## 11. Tác giả

* **L3Tu4n**
* **NTTGon**
* Project: *Applying artificial intelligence to enhance automated cyberattack detection and response and integrating Blockchain to ensure log integrity*
* > A Streaming ML + XAI + LLM Pipeline for Network Security Monitoring

---

## 12. License

MIT License (cho mục đích học tập & nghiên cứu)
