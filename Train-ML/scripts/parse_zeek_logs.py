#!/usr/bin/env python3
"""Parser cho Zeek logs (JSON Lines format) -> Pandas DataFrame"""

import pandas as pd
import numpy as np
from pathlib import Path
import json
import gzip
import warnings

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
        error_count = 0
        
        # Mở file: Dùng gzip.open nếu là file .gz, ngược lại dùng open()
        try:
            if log_path.suffix == '.gz':
                f = gzip.open(log_path, 'rt', encoding='utf-8')
            else:
                f = open(log_path, 'r', encoding='utf-8')
            
            with f:
                for line_num, line in enumerate(f, 1):
                    # Bỏ qua dòng trống và dòng comment
                    if line.strip() and not line.startswith('#'):
                        try:
                            data.append(json.loads(line))
                        except json.JSONDecodeError as e:
                            error_count += 1
                            if error_count <= 5:  # Chỉ hiển thị 5 lỗi đầu tiên
                                print(f"[✗] JSON Decode error at line {line_num} in {log_path.name}: {e}")
                            continue

        except PermissionError:
            print(f"[✗] Permission denied: {log_path}")
            return pd.DataFrame()
        except Exception as e:
            print(f"[✗] Error reading file {log_path}: {e}")
            return pd.DataFrame()

        if error_count > 5:
            print(f"[!] Total {error_count} JSON decode errors in {log_path.name}")

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
            print(f"[!] conn.log trống hoặc không thể parse: {conn_log_path}")
            return df
        
        # Convert timestamp
        if 'ts' in df.columns:
            df['ts'] = pd.to_datetime(df['ts'], unit='s', errors='coerce')

        # Convert numeric columns
        numeric_cols = ['duration', 'orig_bytes', 'resp_bytes','missed_bytes', 
                       'orig_pkts', 'orig_ip_bytes','resp_pkts', 'resp_ip_bytes']

        for col in numeric_cols:
            if col in df.columns:
                df[col] = pd.to_numeric(df[col], errors='coerce').fillna(0)

        # Add source identifier (Lấy tên thư mục cha)
        df['pcap_source'] = Path(conn_log_path).parent.name

        print(f"[✓] Parsed conn.log: {len(df)} records from {df['pcap_source'].iloc[0]}")
        
        return df

    def parse_dns_log(self, dns_log_path):
        """Parse dns.log"""
        df = self.parse_log_file(dns_log_path)
        if df.empty:
            return df
            
        if 'ts' in df.columns:
            df['ts'] = pd.to_datetime(df['ts'], unit='s', errors='coerce')
        print(f"[✓] Parsed dns.log: {len(df)} records")
        return df

    def parse_http_log(self, http_log_path):
        """Parse http.log"""
        df = self.parse_log_file(http_log_path)
        if df.empty:
            return df
            
        if 'ts' in df.columns:
            df['ts'] = pd.to_datetime(df['ts'], unit='s', errors='coerce')
        print(f"[✓] Parsed http.log: {len(df)} records")
        return df

    def _merge_dns_into_conn(self, conn_df, dns_df):
        """
        Gộp thông tin query từ DNS log vào Conn log dựa trên UID.
        Xử lý trường hợp 1 UID có nhiều Query -> Gom thành chuỗi duy nhất.
        """
        if dns_df.empty or 'uid' not in dns_df.columns or 'query' not in dns_df.columns:
            conn_df['query'] = ""
            return conn_df

        print(f"    ... Merging DNS info ({len(dns_df)} records) into Conn log...")

        # BƯỚC 1: Chọn các cột cần thiết và lọc bỏ bản ghi không có query
        dns_subset = dns_df[['uid', 'query']].dropna(subset=['query'])
        
        # BƯỚC 2: Gom nhóm theo UID (Aggregation)
        dns_agg = dns_subset.groupby('uid')['query'].apply(
            lambda x: ' '.join(x.astype(str).unique())  # Loại bỏ duplicate queries
        ).reset_index()
        
        # BƯỚC 3: Merge vào conn_df (Left Join)
        # XÓA cột query cũ nếu có để tránh conflict
        if 'query' in conn_df.columns:
            conn_df = conn_df.drop(columns=['query'])
            
        merged_df = pd.merge(conn_df, dns_agg, on='uid', how='left')
        
        # BƯỚC 4: Fill NaN
        merged_df['query'] = merged_df['query'].fillna("")
        
        return merged_df

    def parse_directory(self, zeek_dir):
        """
        Parse và MERGE conn.log + dns.log trong cùng 1 thư mục
        """
        zeek_dir = Path(zeek_dir)
        
        # 1. Parse conn.log (thử cả .log và .log.gz)
        conn_path = zeek_dir / 'conn.log'
        if not conn_path.exists():
            conn_path = zeek_dir / 'conn.log.gz'
            
        if not conn_path.exists():
            print(f"[!] No conn.log found in {zeek_dir.name}")
            return None

        conn_df = self.parse_conn_log(conn_path)
        if conn_df.empty:
            return None

        # 2. Parse dns.log (nếu có)
        dns_path = zeek_dir / 'dns.log'
        if not dns_path.exists():
            dns_path = zeek_dir / 'dns.log.gz'
        
        if dns_path.exists():
            dns_df = self.parse_dns_log(dns_path)
            conn_df = self._merge_dns_into_conn(conn_df, dns_df)
        else:
            conn_df['query'] = ""

        return {'conn': conn_df}

    def parse_all_subdirs(self, base_dir):
        """
        Parse tất cả subdirectories (mỗi PCAP tạo một subdir).
        """
        base_dir = Path(base_dir)
        
        if not base_dir.exists():
            raise FileNotFoundError(f"Directory not found: {base_dir}")
            
        all_results = {}

        # Chỉ lấy các thư mục con
        subdirs = [d for d in base_dir.iterdir() if d.is_dir()]

        if not subdirs:
            print(f"[!] No subdirectories found in {base_dir}")
            return all_results

        print(f"[*] Found {len(subdirs)} subdirectories")
        print("="*60)

        for subdir in subdirs:
            print(f"\n[*] Processing {subdir.name}")
            try:
                results = self.parse_directory(subdir)
                if results and isinstance(results, dict):
                    all_results[subdir.name] = results
                    print(f"[✓] Successfully parsed {subdir.name}")
                else:
                    print(f"[!] No valid logs parsed in {subdir.name}")
            except Exception as e:
                print(f"[✗] Error parsing {subdir.name}: {type(e).__name__}: {e}")

        return all_results

    def combine_conn_logs(self, all_results):
        """
        Combine tất cả conn.log DataFrames thành một.
        """
        conn_dfs = []

        for subdir_name, logs in all_results.items():
            if 'conn' in logs and not logs['conn'].empty:
                conn_dfs.append(logs['conn'].copy())

        if not conn_dfs:
            raise ValueError("No conn.log data found to combine!")

        combined = pd.concat(conn_dfs, ignore_index=True)
        print(f"\n[✓] Combined conn.log: {len(combined)} total records")
        print(f"    From {len(conn_dfs)} PCAP sources")

        return combined

    def split_conn_logs_by_source(self, all_results, normal_keywords=None):
        """
        Tách conn.log thành:
        - normal traffic (train IF)
        - non-normal traffic (CICIDS - train supervised)

        Args:
            normal_keywords: list keyword để nhận diện normal traffic folder
        """
        if normal_keywords is None:
            normal_keywords = ["normal"]

        normal_dfs = []
        other_dfs = []

        for source, logs in all_results.items():
            if 'conn' not in logs or logs['conn'].empty:
                continue

            df = logs['conn'].copy()

            # Check nếu source name chứa keyword của normal traffic
            is_normal = any(k.lower() in source.lower() for k in normal_keywords)
            
            if is_normal:
                normal_dfs.append(df)
                print(f"    → {source}: NORMAL traffic ({len(df)} records)")
            else:
                other_dfs.append(df)
                print(f"    → {source}: ATTACK traffic ({len(df)} records)")

        normal_combined = pd.concat(normal_dfs, ignore_index=True) if normal_dfs else pd.DataFrame()
        other_combined = pd.concat(other_dfs, ignore_index=True) if other_dfs else pd.DataFrame()

        print(f"\n[✓] Split complete:")
        print(f"    - Normal traffic: {len(normal_combined)} records from {len(normal_dfs)} sources")
        print(f"    - Attack traffic: {len(other_combined)} records from {len(other_dfs)} sources")

        return {
            "normal": normal_combined,
            "other": other_combined
        }


if __name__ == "__main__":
    # Cấu hình
    ZEEK_LOGS_DIR = "./CIC-IDS-2017/ZeekLogs"
    OUTPUT_DIR = Path("./CIC-IDS-2017")
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    parser = ZeekLogParser()

    print("[*] Starting Zeek log parsing...")
    print("="*60)
    
    try:
        # BƯỚC 1: Parse tất cả logs
        all_results = parser.parse_all_subdirs(ZEEK_LOGS_DIR)

        if not all_results:
            print("[!] No logs were successfully parsed. Exiting.")
            exit(1)

        # BƯỚC 2: Split theo traffic type
        print("\n[*] Splitting logs by traffic type...")
        print("="*60)
        
        splits = parser.split_conn_logs_by_source(
            all_results,
            normal_keywords=["normal_traffic", "benign"]
        )

        normal_df = splits["normal"]
        other_df = splits["other"]

        # BƯỚC 3: Save files
        print("\n[*] Saving processed data...")
        print("="*60)
        
        if not normal_df.empty:
            normal_out = OUTPUT_DIR / "conn_normal_only.parquet"
            normal_df.to_parquet(normal_out, index=False)
            print(f"[✓] Normal traffic saved: {normal_out}")
            print(f"    → {len(normal_df)} records, {normal_df.memory_usage(deep=True).sum() / 1024**2:.2f} MB")
            
            # Save schema
            normal_df.dtypes.to_csv(OUTPUT_DIR / "schema_if.csv")
        else:
            print("[!] No normal traffic data to save")

        if not other_df.empty:
            other_out = OUTPUT_DIR / "conn_for_semi_supervised.parquet"
            other_df.to_parquet(other_out, index=False)
            print(f"[✓] Attack traffic saved: {other_out}")
            print(f"    → {len(other_df)} records, {other_df.memory_usage(deep=True).sum() / 1024**2:.2f} MB")
            
            # Save schema
            other_df.dtypes.to_csv(OUTPUT_DIR / "schema_semi_supervised.csv")
        else:
            print("[!] No attack traffic data to save")

        # BƯỚC 4: Show summary
        if not other_df.empty:
            print("\n" + "="*60)
            print("SAMPLE DATA (ATTACK TRAFFIC - First 5 records):")
            print("="*60)
            sample_cols = ['ts', 'id.orig_h', 'id.resp_h', 'proto', 'duration', 
                          'orig_bytes', 'resp_bytes', 'pcap_source']
            available_cols = [col for col in sample_cols if col in other_df.columns]
            print(other_df[available_cols].head())
            
            print("\n" + "="*60)
            print("DATA STATISTICS:")
            print("="*60)
            print(other_df[['duration', 'orig_bytes', 'resp_bytes']].describe())
            
            print("\n" + "="*60)
            print("TRAFFIC SOURCES:")
            print("="*60)
            print(other_df['pcap_source'].value_counts())

        print("\n" + "="*60)
        print("[✓] Processing complete!")
        print("="*60)

    except FileNotFoundError as e:
        print(f"[✗] Error: {e}")
        exit(1)
    except ValueError as e:
        print(f"[✗] Data error: {e}")
        exit(1)
    except Exception as e:
        print(f"[✗] Unexpected error: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()
        exit(1)