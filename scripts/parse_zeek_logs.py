#ML-NIDS-PROJECT/Train-ML/scripts/parse_zeek_logs.py
#!/usr/bin/env python3
"""Parser cho Zeek logs (JSON Lines format) -> Pandas DataFrame"""

import pandas as pd
import numpy as np
from pathlib import Path
import json
import gzip

class ZeekLogParser:
    """Parse Zeek logs (JSON Lines) thành Pandas DataFrame"""

    def parse_log_file(self, log_path):
        """
        Parse một Zeek log file (dưới định dạng JSON Lines).
        Hỗ trợ file nén .gz.

        Args:
            log_path: Path tới .log hoặc .log.gz file

        Returns:
            pandas.DataFrame
        """
        log_path = Path(log_path)

        if not log_path.exists():
            print(f"[!] Log file not found: {log_path}")
            return pd.DataFrame()

        data = []
        
        # Mở file: Dùng gzip.open nếu là file .gz, ngược lại dùng open()
        try:
            if log_path.suffix == '.gz':
                # Đọc file nén Gzip
                f = gzip.open(log_path, 'rt', encoding='utf-8')
            else:
                # Đọc file văn bản thường
                f = open(log_path, 'r', encoding='utf-8')
            
            with f:
                for line in f:
                    # Bỏ qua dòng trống và dòng comment (nếu có)
                    if line.strip() and not line.startswith('#'):
                        try:
                            # Parse JSON từ mỗi dòng
                            data.append(json.loads(line))
                        except json.JSONDecodeError as e:
                            print(f"[✗] Lỗi JSON Decode ở {log_path}: {e}")
                            continue # Bỏ qua dòng bị lỗi

        except Exception as e:
            print(f"[✗] Lỗi đọc file {log_path}: {e}")
            return pd.DataFrame()

        # Tạo DataFrame từ list các dictionary
        df = pd.DataFrame(data)
        
        return df

    # --- Các phương thức xử lý log cụ thể ---

    def parse_conn_log(self, conn_log_path):
        """
        Parse conn.log với xử lý đặc biệt.

        Trả về DataFrame với các columns quan trọng cho ML
        """
        df = self.parse_log_file(conn_log_path)
        
        if df.empty:
            print(f"[!] conn.log trống hoặc không thể parse.")
            return df
        
        # Convert timestamp
        if 'ts' in df.columns:
            # Zeek JSON logs sử dụng timestamp UNIX (giây)
            df['ts'] = pd.to_datetime(df['ts'], unit='s')

        # Convert numeric columns
        numeric_cols = ['duration', 'orig_bytes', 'resp_bytes','missed_bytes', 'orig_pkts', 'orig_ip_bytes','resp_pkts', 'resp_ip_bytes']

        for col in numeric_cols:
            if col in df.columns:
                # Chuyển sang kiểu số, lỗi chuyển đổi thì là NaN, sau đó điền 0
                df[col] = pd.to_numeric(df[col], errors='coerce').fillna(0)

        # Add source identifier (Lấy tên thư mục cha)
        df['pcap_source'] = Path(conn_log_path).parent.name

        
        print(f"[✓] Parsed conn.log: {len(df)} records")
        
        return df

    def parse_dns_log(self, dns_log_path):
        """Parse dns.log"""
        df = self.parse_log_file(dns_log_path)
        if 'ts' in df.columns:
            df['ts'] = pd.to_datetime(df['ts'], unit='s')
        print(f"[✓] Parsed dns.log: {len(df)} records")
        return df

    def parse_http_log(self, http_log_path):
        """Parse http.log"""
        df = self.parse_log_file(http_log_path)
        if 'ts' in df.columns:
            df['ts'] = pd.to_datetime(df['ts'], unit='s')
        print(f"[✓] Parsed http.log: {len(df)} records")
        return df

    # --- Các phương thức quản lý thư mục và kết hợp ---

    def parse_directory(self, zeek_dir):
        """
        Parse tất cả Zeek logs trong một directory.
        Ưu tiên tìm file .log (hoặc .log.gz nếu có).
        """
        zeek_dir = Path(zeek_dir)
        results = {}
        
        # Hàm trợ giúp để tìm file log (có thể là .log hoặc .log.gz)
        def find_log_file(name):
            log_path = zeek_dir / name
            if log_path.exists():
                return log_path
            # Zeek JSON logs thường không được nén mặc định trừ khi cấu hình
            # Nhưng ta vẫn kiểm tra .gz để đảm bảo tương thích
            log_gz_path = zeek_dir / f"{name}.gz"
            if log_gz_path.exists():
                return log_gz_path
            return None

        # Parse conn.log
        conn_log_path = find_log_file('conn.log')
        if conn_log_path:
            results['conn'] = self.parse_conn_log(conn_log_path)

        # Parse dns.log
        dns_log_path = find_log_file('dns.log')
        if dns_log_path:
            results['dns'] = self.parse_dns_log(dns_log_path)

        # Parse http.log
        http_log_path = find_log_file('http.log')
        if http_log_path:
            results['http'] = self.parse_http_log(http_log_path)

        return results

    def parse_all_subdirs(self, base_dir):
        """
        Parse tất cả subdirectories (mỗi PCAP tạo một subdir).
        """
        base_dir = Path(base_dir)
        all_results = {}

        # Chỉ lấy các thư mục con (bỏ qua file)
        subdirs = [d for d in base_dir.iterdir() if d.is_dir()]

        print(f"[*] Found {len(subdirs)} subdirectories")
        print("="*60)

        for subdir in subdirs:
            print(f"\n[*] Processing {subdir.name}")
            try:
                results = self.parse_directory(subdir)
                # Chỉ lưu kết quả nếu có log được parse thành công
                if results:
                    all_results[subdir.name] = results
                    print(f"[✓] Parsed {len(results)} log types from {subdir.name}")
                else:
                    print(f"[!] No logs found/parsed in {subdir.name}")
            except Exception as e:
                print(f"[✗] Error parsing {subdir.name}: {e}")

        return all_results

    def combine_conn_logs(self, all_results):
        """
        Combine tất cả conn.log DataFrames thành một.
        """
        conn_dfs = []

        for subdir_name, logs in all_results.items():
            if 'conn' in logs and not logs['conn'].empty:
                df = logs['conn'].copy()
                # Tên cột đã được thêm trong parse_conn_log, chỉ cần append
                conn_dfs.append(df)

        if not conn_dfs:
            raise ValueError("No conn.log data found!")

        combined = pd.concat(conn_dfs, ignore_index=True)
        print(f"\n[✓] Combined conn.log: {len(combined)} total records")
        print(f"    From {len(conn_dfs)} PCAP files")

        return combined

if __name__ == "__main__":
    # Cấu hình ví dụ
    ZEEK_LOGS_DIR = "./CIC-IDS-2017/ZeekLogs"  # Thư mục output từ script PCAP -> Zeek
    OUTPUT_FILE = "./CIC-IDS-2017/processed_conn_logs.parquet"

    parser = ZeekLogParser()

    print("[*] Parsing all Zeek logs...")
    all_results = parser.parse_all_subdirs(ZEEK_LOGS_DIR)

    if all_results:
        # Combine conn.log
        print("\n[*] Combining conn.log files...")
        try:
            conn_df = parser.combine_conn_logs(all_results)

            # Save to parquet (định dạng hiệu quả cho ML)
            print(f"\n[*] Saving to {OUTPUT_FILE}")
            conn_df.to_parquet(OUTPUT_FILE, index=False, compression='snappy')

            print(f"[✓] Saved! File size: {Path(OUTPUT_FILE).stat().st_size / (1024**2):.2f} MB")

            # Show sample
            print("\n" + "="*60)
            print("SAMPLE DATA (CONN LOG):")
            print(conn_df[['ts', 'id.orig_h', 'id.resp_h', 'proto', 'duration', 'orig_bytes', 'resp_bytes']].head())
            print("\n" + "="*60)
            print("DATA TYPES:")
            print(conn_df.dtypes)
            print("="*60)
        except ValueError as e:
            print(f"[!] Lỗi kết hợp logs: {e}")
    else:
        print("[!] Không có kết quả nào được parse.")