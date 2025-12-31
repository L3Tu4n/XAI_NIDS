#!/usr/bin/env python3
"""
Script để convert PCAP files sang Zeek logs
Cấu phần trong quy trình tiền xử lý dữ liệu của hệ thống ML-NIDS
"""
import os
import subprocess
from pathlib import Path

class PcapToZeekProcessor:
    def __init__(self, pcap_dir, output_dir):
        """
        Khởi tạo bộ xử lý chuyển đổi PCAP sang Zeek log.
        
        Args:
            pcap_dir: Thư mục chứa các tệp PCAP đầu vào.
            output_dir: Thư mục lưu trữ kết quả Zeek logs.
        """
        self.pcap_dir = Path(pcap_dir)
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
    def process_single_pcap(self, pcap_path):
        """
        Sử dụng công cụ Zeek để trích xuất log từ một tệp PCAP.
        """
        pcap_name = Path(pcap_path).stem
        output_subdir = self.output_dir / pcap_name
        output_subdir.mkdir(parents=True, exist_ok=True)
        
        print(f"[*] Processing: {pcap_path}")
        print(f"[*] Output directory: {output_subdir}")
        
        # Cấu hình lệnh thực thi Zeek:
        # -r: Đọc tệp pcap đầu vào
        # -C: Bỏ qua lỗi checksum (quan trọng khi xử lý dataset thực nghiệm)
        # LogAscii::use_json=T: Xuất log định dạng JSON Lines cho các bước Parser tiếp theo
        cmd = [
            'zeek',
            '-r', str(pcap_path),
            '-C', 
            'local',
            'LogAscii::use_json=T',
            f'Log::default_logdir={output_subdir}'
        ]
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=3600  # Giới hạn thời gian xử lý tối đa 1 giờ cho mỗi tệp
            )
            
            if result.returncode == 0:
                print(f"[✓] Successfully processed {pcap_name}")
                self._list_generated_logs(output_subdir)
            else:
                print(f"[✗] Error processing {pcap_name}")
                print(f"Error Detail: {result.stderr}")
                
        except subprocess.TimeoutExpired:
            print(f"[✗] Timeout processing {pcap_name}")
        except Exception as e:
            print(f"[✗] Exception occurred: {e}")
    
    def _list_generated_logs(self, log_dir):
        """Liệt kê các tệp log được tạo ra và kích thước tương ứng"""
        log_files = list(log_dir.glob("*.log"))
        print(f"    Generated {len(log_files)} log files:")
        for log_file in sorted(log_files):
            size_mb = log_file.stat().st_size / (1024 * 1024)
            print(f"    - {log_file.name} ({size_mb:.2f} MB)")
    
    def process_all_pcaps(self):
        """Quét và xử lý tất cả tệp .pcap có trong thư mục cấu hình"""
        pcap_files = list(self.pcap_dir.glob("*.pcap"))
        
        if not pcap_files:
            print(f"[!] No PCAP files found in {self.pcap_dir}")
            return
        
        print(f"[*] Found {len(pcap_files)} PCAP files")
        print("="*60)
        
        for i, pcap_path in enumerate(pcap_files, 1):
            print(f"\n[{i}/{len(pcap_files)}] Processing {pcap_path.name}")
            self.process_single_pcap(pcap_path)
            print("-"*60)
        
        print("\n[✓] All PCAP files processed successfully!")
        print(f"[*] Zeek logs saved to: {self.output_dir}")


if __name__ == "__main__":
    # Cấu hình đường dẫn hệ thống
    PCAP_DIR = "./CIC-IDS-2017/PCAPs" 
    OUTPUT_DIR = "./CIC-IDS-2017/ZeekLogs" 
    
    # Thực thi quy trình chuyển đổi
    processor = PcapToZeekProcessor(PCAP_DIR, OUTPUT_DIR)
    processor.process_all_pcaps()
    
    print("\n" + "="*60)
    print("NEXT STEPS:")
    print("1. Verify Zeek logs are generated correctly (check JSON format)")
    print("2. Focus on: conn.log, dns.log, and http.log for ML features")
    print("3. Execute parse_zeek_logs.py for further data processing")
    print("="*60)