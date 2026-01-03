**Mô tả:** Kiểm tra toàn bộ dải mạng nội bộ để xác định những địa chỉ IP nào đang hoạt động.

**Câu lệnh thực thi:**
```bash
nmap -sn 192.168.63.0/24
```
- `-sn`: Chế độ **Ping Scan**. Nmap sẽ gửi các gói tin thăm dò (như ICMP Echo Request) để xác định vật chủ đang hoạt động nhưng bỏ qua bước quét cổng nhằm tăng tốc độ và tránh bị phát hiện.
- `<network-range>`: Dải địa chỉ IP của mạng mục tiêu cần rà soát.

**Mô tả**: Sau khi xác định được máy mục tiêu đang hoạt động, thực hiện rà soát chuyên sâu để liệt kê các cổng dịch vụ đang mở và thông tin phiên bản phần mềm nhằm xác định bề mặt tấn công của hệ thống.

**Câu lệnh thực thi:**
```bash
nmap -sV 192.168.63.130
```
- `-sB`: **Version Detection**. Nmap sẽ gửi các gói tin thăm dò đến các cổng mở để phân tích phản hồi, từ đó xác định dịch vụ đang mở và phiên bản phần mềm.
- `<ip-target>`: Địa chỉ IP của mục tiêu.