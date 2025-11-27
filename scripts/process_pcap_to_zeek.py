#ML-NIDS-PROJECT/Train-ML/scripts/process_pcap_to_zeek.py
#!/usr/bin/env python3
"""
Script để convert PCAP files sang Zeek logs
"""
import os
import subprocess
import glob
from pathlib import Path

class PcapToZeekProcessor:
    def __init__(self, pcap_dir, output_dir):
        """
        Args:
            pcap_dir: Thư mục chứa PCAP files
            output_dir: Thư mục output cho Zeek logs
        """
        self.pcap_dir = Path(pcap_dir)
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
    def process_single_pcap(self, pcap_path):
        """
        Process một PCAP file thành Zeek logs
        """
        pcap_name = Path(pcap_path).stem
        output_subdir = self.output_dir / pcap_name
        output_subdir.mkdir(parents=True, exist_ok=True)
        
        print(f"[*] Processing {pcap_path}")
        print(f"[*] Output dir: {output_subdir}")
        
        # Chạy Zeek với options:
        # -r: read from pcap
        # -C: ignore checksum errors
        # -e: set logging dir
        cmd = [
            'zeek',
            '-r', str(pcap_path),
            '-C',  # Ignore checksums (quan trọng cho PCAP files)
            'local',
            'LogAscii::use_json=T',
            f'Log::default_logdir={output_subdir}'
        ]
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=3600  # 1 hour timeout
            )
            
            if result.returncode == 0:
                print(f"[✓] Successfully processed {pcap_name}")
                self._list_generated_logs(output_subdir)
            else:
                print(f"[✗] Error processing {pcap_name}")
                print(f"Error: {result.stderr}")
                
        except subprocess.TimeoutExpired:
            print(f"[✗] Timeout processing {pcap_name}")
        except Exception as e:
            print(f"[✗] Exception: {e}")
    
    def _list_generated_logs(self, log_dir):
        """List các log files được tạo ra"""
        log_files = list(log_dir.glob("*.log"))
        print(f"    Generated {len(log_files)} log files:")
        for log_file in sorted(log_files):
            size_mb = log_file.stat().st_size / (1024 * 1024)
            print(f"    - {log_file.name} ({size_mb:.2f} MB)")
    
    def process_all_pcaps(self):
        """Process tất cả PCAP files trong thư mục"""
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
        
        print("\n[✓] All PCAP files processed!")
        print(f"[*] Zeek logs saved to: {self.output_dir}")


if __name__ == "__main__":
    # Cấu hình paths
    PCAP_DIR = "./CIC-IDS-2017/PCAPs"  # Thư mục chứa PCAP files
    OUTPUT_DIR = "./CIC-IDS-2017/ZeekLogs"  # Output directory
    
    # Process
    processor = PcapToZeekProcessor(PCAP_DIR, OUTPUT_DIR)
    processor.process_all_pcaps()
    
    print("\n" + "="*60)
    print("NEXT STEPS:")
    print("1. Verify Zeek logs được tạo đúng")
    print("2. Check conn.log, dns.log, http.log files")
    print("3. Run parse_zeek_logs.py để extract features")
    print("="*60)