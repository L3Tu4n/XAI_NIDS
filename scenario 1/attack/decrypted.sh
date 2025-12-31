#!/bin/bash

KEY="a1b2c3d4e5f6..."  # Thay bằng KEY thực tế
IV="1a2b3c4d5e6..."   # Thay bằng IV thực tế
TARGET_DIR="$HOME/Documents"

for file in "$TARGET_DIR"/*.enc; do
    if [ -f "$file" ]; then
        filename=$(basename "$file" .enc)
        echo "Đang giải mã $file thành $filename..."
        openssl enc -aes-256-cbc -d -in "$file" -out "$TARGET_DIR/$filename" -K "$KEY" -iv "$IV"
        if [ $? -eq 0 ]; then
            echo "Giải mã thành công $filename"
            rm "$file"  # Xóa tệp .enc sau khi giải mã
        else
            echo "Giải mã thất bại cho $filename"
        fi
    fi
done

echo "Quá trình giải mã hoàn tất."