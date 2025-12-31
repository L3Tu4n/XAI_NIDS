#!/bin/bash
DNSMASQ_LOG="/var/log/dnsmasq.log"
DOMAIN="example.com"
OUTPUT_FILE="received_data.txt"

# Đọc log và thu thập các đoạn dữ liệu
declare -A chunks
while read -r line; do
    if echo "$line" | grep -q "query\[A\] .*\.$DOMAIN"; then
        subdomain=$(echo "$line" | awk '{print $6}' | cut -d'.' -f1-2)
        chunk=$(echo "$subdomain" | cut -d'.' -f1)
        index=$(echo "$subdomain" | cut -d'.' -f2)
        # Kiểm tra index là số và chunk là chuỗi hex
        if [[ "$index" =~ ^[0-9]+$ ]] && [[ "$chunk" =~ ^[0-9a-fA-F]+$ ]]; then
            chunks[$index]=$chunk
        fi
    fi
done < "$DNSMASQ_LOG"

# Ghép các đoạn dữ liệu
encoded=""
for i in $(for key in "${!chunks[@]}"; do echo $key; done | sort -n); do
    encoded="$encoded${chunks[$i]}"
done

# Giải mã hex và lưu dữ liệu
echo "$encoded" | xxd -r -p > "$OUTPUT_FILE" 2>/dev/null
echo "Dữ liệu đã lưu tại $OUTPUT_FILE"