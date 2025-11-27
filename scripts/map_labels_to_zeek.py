#!/usr/bin/env python3
"""
Map CIC-IDS2017 labels tới Zeek logs (SỬA ĐỔI ĐỂ GỘP NHIỀU CSV)
"""
import pandas as pd
import numpy as np
from pathlib import Path
from datetime import datetime

class CICIDSLabelMapper:
    """
    Map labels từ CIC-IDS2017 CSV files sang Zeek conn.log
    """
    
    # Mapping giữa tên file PCAP và tên file CSV (Friday-WorkingHours đã là list)
    PCAP_TO_CSV_MAP = {
        'Monday-WorkingHours': 'Monday-WorkingHours.pcap_ISCX.csv',
        'Tuesday-WorkingHours': 'Tuesday-WorkingHours.pcap_ISCX.csv',
        'Wednesday-workingHours': 'Wednesday-workingHours.pcap_ISCX.csv',
        'Thursday-WorkingHours': [
            'Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv',
            'Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv'
        ],
        'Friday-WorkingHours': [ 
            'Friday-WorkingHours-Morning.pcap_ISCX.csv',
            'Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv',
            'Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv'
        ]
    }
    
# Label encoding (CẬP NHẬT: Thêm biến thể 2 khoảng trắng để khớp với log thực tế)
    LABEL_ENCODING = {
        'BENIGN': 0,
        'DoS Hulk': 1,
        'PortScan': 2,
        'DDoS': 3,
        'DoS GoldenEye': 4,
        'FTP-Patator': 5,
        'SSH-Patator': 6,
        'DoS slowloris': 7,
        'DoS Slowhttptest': 8,
        'Bot': 9,
        
        # --- BẮT MỌI BIẾN THỂ CỦA WEB ATTACK ---
        'Web Attack – Brute Force': 10,   # En-dash
        'Web Attack - Brute Force': 10,   # Hyphen
        'Web Attack  Brute Force': 10,    # <--- KHỚP VỚI LOG CỦA BẠN (Double Space)
        'Web Attack \x96 Brute Force': 10,
        
        'Web Attack – XSS': 11,
        'Web Attack - XSS': 11,
        'Web Attack  XSS': 11,            # <--- KHỚP VỚI LOG CỦA BẠN
        'Web Attack \x96 XSS': 11,
        
        'Web Attack – Sql Injection': 12,
        'Web Attack - Sql Injection': 12,
        'Web Attack  Sql Injection': 12,  # <--- KHỚP VỚI LOG CỦA BẠN
        'Web Attack \x96 Sql Injection': 12,
        # ----------------------------------------

        'Infiltration': 13,
        'Heartbleed': 14
    }
    
    def __init__(self, csv_dir):
        """
        Args:
            csv_dir: Directory chứa CIC-IDS CSV files
        """
        self.csv_dir = Path(csv_dir)
        
    def load_cic_csv(self, csv_path):
        """Load CIC-IDS CSV file"""
        print(f"[*] Loading {csv_path.name}...")
        
        # CIC-IDS CSVs có encoding issues
        try:
            df = pd.read_csv(csv_path, encoding='utf-8')
        except:
            df = pd.read_csv(csv_path, encoding='latin-1')
        
        # Clean column names (có spaces và special chars)
        df.columns = df.columns.str.strip()
        
        # Rename Label column nếu cần
        if 'Label' not in df.columns and ' Label' in df.columns:
            df.rename(columns={' Label': 'Label'}, inplace=True)
        
        print(f"    Loaded {len(df)} records")
        print(f"    Columns: {list(df.columns[:])}...")
        
        if 'Label' in df.columns:
            print(f"    Labels: {df['Label'].value_counts().to_dict()}")
        
        return df

    # ---> HÀM MỚI: KẾT HỢP NHIỀU CSV <---
    def combine_cic_csvs(self, csv_file_list):
        """
        Load và combine nhiều CIC-IDS CSV files thành một DataFrame duy nhất.
        Thứ tự load quan trọng để đảm bảo nhãn tấn công ghi đè nhãn BENIGN.
        """
        combined_df_list = []
        
        # Sắp xếp để đảm bảo các file tấn công (có PortScan/DDoS) được load sau Morning (BENIGN)
        # Mục tiêu: Đảm bảo nhãn tấn công ghi đè lên nhãn BENIGN cho cùng một Connection Key
        
        # Ưu tiên load Morning trước, sau đó là PortScan, cuối cùng là DDoS
        priority = {
            'Morning': 1,
            'PortScan': 2,
            'DDoS': 3
        }
        
        # Sắp xếp file theo độ ưu tiên tấn công
        def get_priority(filename):
            if 'DDoS' in filename: return priority['DDoS']
            if 'PortScan' in filename: return priority['PortScan']
            if 'Morning' in filename: return priority['Morning']
            return 0 # Mặc định
        
        sorted_list = sorted(csv_file_list, key=get_priority)

        for filename in sorted_list:
            csv_path = self.csv_dir / filename
            if csv_path.exists():
                df = self.load_cic_csv(csv_path)
                combined_df_list.append(df)
            else:
                print(f"[!] CSV file không tìm thấy: {csv_path}")

        if not combined_df_list:
            return None

        # Concatenate tất cả DataFrame lại
        final_df = pd.concat(combined_df_list, ignore_index=True)
        print(f"[✓] Đã kết hợp {len(csv_file_list)} CSVs, tổng cộng {len(final_df)} bản ghi.")
        return final_df
    # ---------------------------------------
    
    def create_connection_key(self, df, prefix=''):
        """
        [FIXED] Tạo connection key với ép kiểu PORT và PROTOCOL chặt chẽ
        """
        df.columns = df.columns.str.strip()
        
        src_ip_col = f'{prefix}Source IP' if f'{prefix}Source IP' in df.columns else 'Source IP'
        dst_ip_col = f'{prefix}Destination IP' if f'{prefix}Destination IP' in df.columns else 'Destination IP'
        src_port_col = f'{prefix}Source Port' if f'{prefix}Source Port' in df.columns else 'Source Port'
        dst_port_col = f'{prefix}Destination Port' if f'{prefix}Destination Port' in df.columns else 'Destination Port'
        
        # [FIX 2] Ép kiểu PORT về Int để loại bỏ ".0"
        src_port = pd.to_numeric(df[src_port_col], errors='coerce').fillna(0).astype(int).astype(str)
        dst_port = pd.to_numeric(df[dst_port_col], errors='coerce').fillna(0).astype(int).astype(str)
        
        # Ép kiểu Protocol
        proto_col = df['Protocol']
        proto_str = pd.to_numeric(proto_col, errors='coerce').fillna(0).astype(int).astype(str)
        
        # Tạo key
        df['conn_key'] = (
            df[src_ip_col].astype(str) + ':' +
            src_port + ':' +
            df[dst_ip_col].astype(str) + ':' +
            dst_port + ':' +
            proto_str
        )
        
        # Tạo Reverse Key
        df['rev_conn_key'] = (
            df[dst_ip_col].astype(str) + ':' +
            dst_port + ':' +
            df[src_ip_col].astype(str) + ':' +
            src_port + ':' +
            proto_str
        )
        
        return df
    
    def create_zeek_connection_key(self, zeek_df):
        """
        [FIXED] Tạo Zeek key chuẩn hóa
        """
        # [QUAN TRỌNG] Ép kiểu ip_proto về Int giống hệt bên CIC
        if 'ip_proto' in zeek_df.columns:
            proto_str = pd.to_numeric(zeek_df['ip_proto'], errors='coerce').fillna(0).astype(int).astype(str)
        else:
            # Fallback nếu không có cột ip_proto (dùng map string tcp->6)
            proto_map = {'tcp': '6', 'udp': '17', 'icmp': '1'}
            proto_str = zeek_df['proto'].str.lower().map(proto_map).fillna('0')

        zeek_df['conn_key'] = (
            zeek_df['id.orig_h'].astype(str) + ':' +
            zeek_df['id.orig_p'].astype(str) + ':' +
            zeek_df['id.resp_h'].astype(str) + ':' +
            zeek_df['id.resp_p'].astype(str) + ':' +
            proto_str
        )
        
        return zeek_df
    
    def map_labels_simple(self, zeek_df, cic_df):
        """
        [FIXED] Mapping 2 chiều (Forward & Reverse) và Debugging
        """
        print("[*] Mapping labels...")
        
        # 1. Tạo keys
        zeek_df = self.create_zeek_connection_key(zeek_df)
        cic_df = self.create_connection_key(cic_df)
        
        # --- DEBUG: In ra mẫu key để so sánh ---
        print("\n[DEBUG] Sample Keys Check:")
        print(f"  Zeek Key: {zeek_df['conn_key'].iloc[0]}")
        print(f"  CIC Key : {cic_df['conn_key'].iloc[0]}")
        # ---------------------------------------

        # 2. Tạo Dictionary Lookup
        # Forward Map: Key -> Label
        fwd_map = cic_df.set_index('conn_key')['Label'].to_dict()
        # Reverse Map: Rev_Key -> Label (Xử lý trường hợp Zeek và CIC ngược chiều Source/Dest)
        rev_map = cic_df.set_index('rev_conn_key')['Label'].to_dict()
        
        # 3. Thực hiện Map
        # Bước 1: Map xuôi
        zeek_df['attack_type'] = zeek_df['conn_key'].map(fwd_map)
        
        # Bước 2: Với những dòng chưa map được (NaN), thử map ngược
        mask_missing = zeek_df['attack_type'].isna()
        if mask_missing.any():
            print(f"  [Info] Trying reverse mapping for {mask_missing.sum()} records...")
            zeek_df.loc[mask_missing, 'attack_type'] = zeek_df.loc[mask_missing, 'conn_key'].map(rev_map)
            
        # 4. Fill BENIGN cho những cái vẫn không tìm thấy
        missing_count = zeek_df['attack_type'].isna().sum()
        total_count = len(zeek_df)
        match_rate = (total_count - missing_count) / total_count * 100
        
        print(f"  [DEBUG] Match Rate: {match_rate:.2f}% ({total_count - missing_count}/{total_count})")
        
        if match_rate < 5.0:
            print("  [WARNING] Tỷ lệ map quá thấp! Kiểm tra lại IP version hoặc Timezone.")

        zeek_df['attack_type'].fillna('BENIGN', inplace=True)
        
        # 5. Encode Labels
        zeek_df['label'] = zeek_df['attack_type'].map(self.LABEL_ENCODING)
        zeek_df['label'].fillna(0, inplace=True)
        zeek_df['label'] = zeek_df['label'].astype(int)
        
        # 6. Report Distribution
        print(f"[✓] Mapped {len(zeek_df)} records")
        print(f"    Label distribution:")
        for attack, count in zeek_df['attack_type'].value_counts().items():
            pct = count / len(zeek_df) * 100
            print(f"      {attack}: {count} ({pct:.2f}%)")
            
        return zeek_df
    
    # ---> SỬA ĐỔI map_labels_for_pcap <---
    def map_labels_for_pcap(self, zeek_df, pcap_name):
        """
        Map labels cho một PCAP cụ thể, hỗ trợ cả 1 CSV và List CSV
        """
        csv_info = self.PCAP_TO_CSV_MAP.get(pcap_name)
        cic_df = None
        
        if isinstance(csv_info, list):
            # Xử lý trường hợp có nhiều CSV cần kết hợp (ví dụ: ngày Thứ Sáu)
            cic_df = self.combine_cic_csvs(csv_info)
            if cic_df is None:
                 print(f"[!] Không thể load/combine CSV cho {pcap_name}. Gán nhãn BENIGN.")
        elif isinstance(csv_info, str):
            # Xử lý trường hợp CSV đơn lẻ
            csv_path = self.csv_dir / csv_info
            if csv_path.exists():
                cic_df = self.load_cic_csv(csv_path)
            else:
                print(f"[!] CSV file không tìm thấy: {csv_path}. Gán nhãn BENIGN.")
        else:
            print(f"[!] Không tìm thấy mapping cho {pcap_name}. Gán nhãn BENIGN.")

        # Nếu không có CSV hoặc lỗi load, gán nhãn BENIGN
        if cic_df is None:
            zeek_df['attack_type'] = 'BENIGN'
            zeek_df['label'] = 0
            return zeek_df
        
        # Map labels bằng Connection Key
        zeek_df = self.map_labels_simple(zeek_df, cic_df)
        
        return zeek_df
    # ---------------------------------------
    
    def map_all_pcaps(self, zeek_df_with_source):
        """
        Map labels cho DataFrame chứa nhiều PCAPs
        
        Args:
            zeek_df_with_source: Zeek DataFrame có column 'pcap_source'
        """
        print("[*] Mapping labels for all PCAPs...")
        print("="*60)
        
        labeled_dfs = []
        
        for pcap_name in zeek_df_with_source['pcap_source'].unique():
            print(f"\n[*] Processing {pcap_name}")
            pcap_df = zeek_df_with_source[
                zeek_df_with_source['pcap_source'] == pcap_name
            ].copy()
            
            labeled_df = self.map_labels_for_pcap(pcap_df, pcap_name)
            labeled_dfs.append(labeled_df)
        
        # Combine
        result = pd.concat(labeled_dfs, ignore_index=True)
        
        print("\n" + "="*60)
        print("[✓] All labels mapped!")
        print(f"Total records: {len(result)}")
        print("\nOverall label distribution:")
        for attack, count in result['attack_type'].value_counts().items():
            pct = count / len(result) * 100
            print(f"  {attack}: {count} ({pct:.2f}%)")
        
        return result


if __name__ == "__main__":
    # Paths
    ZEEK_PARQUET = "./CIC-IDS-2017/processed_conn_logs.parquet"
    CIC_CSV_DIR = "./CIC-IDS-2017/CSVs"  # Directory chứa CSV files
    OUTPUT_FILE = "./CIC-IDS-2017/labeled_conn_logs.parquet"
    
    # Load Zeek logs
    print("[*] Loading Zeek logs...")
    zeek_df = pd.read_parquet(ZEEK_PARQUET)
    print(f"[✓] Loaded {len(zeek_df)} records")
    
    # Map labels
    mapper = CICIDSLabelMapper(CIC_CSV_DIR)
    labeled_df = mapper.map_all_pcaps(zeek_df)
    
    # Save
    print(f"\n[*] Saving to {OUTPUT_FILE}")
    labeled_df.to_parquet(OUTPUT_FILE, index=False, compression='snappy')
    
    print(f"[✓] Done! Labeled dataset ready for feature engineering.")