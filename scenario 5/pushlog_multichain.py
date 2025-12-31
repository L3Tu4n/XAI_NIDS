import json
import os
import threading
import subprocess
import re
import time
import datetime
from tailer import follow
from collections import defaultdict

# Cấu hình đường dẫn và MultiChain
ZEEK_LOG_DIR = "/usr/local/zeek/logs/current/"
SNORT_LOG_DIR = "/var/log/snort/"
MULTICHAIN_CHAIN_NAME = "securitylogchain"

# File lưu trạng thái offset và inode cho mỗi log file
STATE_FILE = "monitor_state.json"

# Danh sách các log file và stream tương ứng
LOG_FILES = {
    "notice.log": "zeek_notice",
    "snort.alert.fast": "snort_alerts"
}

# Cấu hình giới hạn số lượng log cho mỗi loại tấn công, theo mỗi IP
RATE_LIMIT_CONFIG = {
    "snort": {
        "DoS": {"window": 60, "max_count": 3},
        "DDoS": {"window": 60, "max_count": 3},
        "Brute Force": {"window": 60, "max_count": 3},
        "Scan": {"window": 60, "max_count": 3},
        "Default": {"window": 60, "max_count": 10}
    },
    "zeek": {
        "DoS": {"window": 60, "max_count": 3},
        "DDoS": {"window": 60, "max_count": 3},
        "Brute Force": {"window": 60, "max_count": 3},
        "Scan": {"window": 60, "max_count": 3},
        "Default": {"window": 60, "max_count": 10}
    }
}

# Bộ nhớ cache để theo dõi số lượng log theo cặp (nguồn, IP, loại)
ip_attack_counters = defaultdict(list)
state_lock = threading.Lock()

def load_state():
    """Đọc trạng thái (offset & inode) từ file"""
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE, 'r') as f:
                return json.load(f)
        except:
            return {}
    return {}

def save_state(state):
    """Ghi trạng thái (offset & inode) vào file"""
    tmp = STATE_FILE + ".tmp"
    with open(tmp, 'w') as f:
        json.dump(state, f)
    os.replace(tmp, STATE_FILE)

def identify_attack_type(log_entry):
    """Xác định loại tấn công dựa trên msg/note"""
    text = (log_entry.get("msg", "") + " " + log_entry.get("note", "")).lower()
    if any(k in text for k in ["port scan", "scan", "sweep"]):
        return "Scan"
    if any(k in text for k in ["dos", "denial of service"]):
        return "DoS"
    if any(k in text for k in ["ddos", "distributed denial"]):
        return "DDoS"
    if any(k in text for k in ["brute force", "bruteforce", "multiple failed"]):
        return "Brute Force"
    return "Default"

def get_ip_from_log(log_entry):
    """Lấy IP nguồn từ log entry"""
    return log_entry.get('src_ip') or log_entry.get('src') or log_entry.get('id.orig_h', 'unknown_ip')

def should_send_log(log_entry, source):
    """Kiểm tra rate-limit, chỉ gửi nếu chưa vượt ngưỡng"""
    now = time.time()
    category = identify_attack_type(log_entry)
    ip = get_ip_from_log(log_entry)
    key = f"{source}:{ip}:{category}"
    cfg = RATE_LIMIT_CONFIG[source].get(category, RATE_LIMIT_CONFIG[source]["Default"])
    window, maxc = cfg['window'], cfg['max_count']
    # Loại bỏ timestamps cũ
    ip_attack_counters[key] = [t for t in ip_attack_counters[key] if now - t < window]
    if len(ip_attack_counters[key]) < maxc:
        ip_attack_counters[key].append(now)
        return True
    return False

def parse_snort_log(line):
    """Phân tích một dòng log Snort (đã loại bỏ phần extras để tránh sinh trường lạ)"""
    try:
        p = {'raw': line.strip()}

        # Timestamp
        ts_match = re.match(r'^(\d{2}/\d{2}-\d{2}:\d{2}:\d{2}\.\d+)', line)
        if ts_match:
            orig_ts = ts_match.group(1)  # "MM/DD-HH:MM:SS.ffffff"
            # Chuyển orig_ts sang datetime
            try:
                dt = datetime.datetime.strptime(orig_ts, "%m/%d-%H:%M:%S.%f")
                dt = dt.replace(year=datetime.datetime.now().year)
                p['ts'] = dt.strftime("%Y-%m-%d %H:%M:%S")
            except:
                # Nếu parse không thành công, vẫn gán orig_ts vào ts
                p['timestamp'] = orig_ts
                p['ts'] = orig_ts

        # SID và Message
        sidm = re.search(r'\[\*\*\]\s+\[(\d+:\d+:\d+)\]\s+(.*?)\s+\[\*\*\]', line)
        if sidm:
            p['sid'] = sidm.group(1)
            p['msg'] = sidm.group(2)

        # Classification
        cl = re.search(r'\[Classification:\s*(.*?)\]', line)
        if cl:
            p['classification'] = cl.group(1)

        # Priority
        pr = re.search(r'\[Priority:\s*(\d+)\]', line)
        if pr:
            p['priority'] = pr.group(1)

        # Protocol, IP, Port
        ipm = re.search(r'\{(\w+)\}\s+(\d+\.\d+\.\d+\.\d+):(\d+)\s+->\s+(\d+\.\d+\.\d+\.\d+):(\d+)', line)
        if ipm:
            p.update({
                'protocol': ipm.group(1),
                'src_ip': ipm.group(2),
                'src_port': ipm.group(3),
                'dst_ip': ipm.group(4),
                'dst_port': ipm.group(5)
            })

        # KHÔNG THÊM bất kỳ extras chung nào nữa để tránh bắt nhầm
        return p
    except Exception as e:
        print(f"[!] Lỗi parse Snort: {e}")
        return None

def parse_zeek_json_log(line, log_type):
    """Phân tích một dòng Zeek JSON log"""
    try:
        j = json.loads(line)
        if 'ts' in j:
            try:
                j['ts'] = datetime.datetime.fromtimestamp(float(j['ts'])).strftime("%Y-%m-%d %H:%M:%S")
            except:
                pass
        return j
    except Exception as e:
        print(f"[!] Lỗi parse Zeek JSON: {e}")
        return None

def send_to_multichain(stream, log_entry):
    """Publish log lên MultiChain"""
    key = f"log_{log_entry.get('ts', time.time())}_{hash(str(log_entry))}"
    data = json.dumps({"json": log_entry})
    cmd = f"multichain-cli {MULTICHAIN_CHAIN_NAME} publish {stream} {json.dumps(key)} {json.dumps(data)}"
    try:
        subprocess.run(cmd, shell=True, check=True, timeout=10, capture_output=True, text=True)
        # Chọn msg cho snort, note cho zeek
        msg_or_note = log_entry.get('msg') if stream == 'snort_alerts' else log_entry.get('note', 'unknown')
        print(f"[+] Đã publish log '{msg_or_note}' vào {stream}")
    except Exception as e:
        print(f"[!] Lỗi publish: {e}")

def process_log_file(log_file, stream_name):
    """Theo dõi file log, chỉ gửi log mới kể cả khi restart script"""
    source = 'zeek' if log_file == 'notice.log' else 'snort'
    base = ZEEK_LOG_DIR if source == 'zeek' else SNORT_LOG_DIR
    path = os.path.join(base, log_file)
    if not os.path.exists(path):
        print(f"[!] Không tìm thấy {path}")
        return

    # Lấy inode và size hiện tại
    st_stat = os.stat(path)
    curr_ino = st_stat.st_ino
    curr_size = st_stat.st_size

    # Load và điều chỉnh state
    with state_lock:
        state = load_state()
        entry = state.get(log_file, {})
        off = entry.get('offset', 0)
        ino = entry.get('inode')
        if ino is None or ino != curr_ino or off > curr_size:
            off = 0
        state[log_file] = {'offset': off, 'inode': curr_ino}
        save_state(state)

    # Chọn parser, bao gồm log_type cho Zeek
    if source == 'zeek':
        parser = lambda line: parse_zeek_json_log(line, log_file)
    else:
        parser = parse_snort_log

    try:
        with open(path, 'r') as f:
            f.seek(off)
            for line in f:
                e = parser(line.strip())
                if e and should_send_log(e, source):
                    send_to_multichain(stream_name, e)

            with state_lock:
                state = load_state()
                state[log_file]['offset'] = f.tell()
                save_state(state)

            for line in follow(f, delay=1.0):
                e = parser(line.strip())
                if e and should_send_log(e, source):
                    send_to_multichain(stream_name, e)
                with state_lock:
                    state = load_state()
                    state[log_file]['offset'] = f.tell()
                    save_state(state)

    except Exception as ex:
        print(f"[!] Lỗi đọc {path}: {ex}")

def wait_and_monitor(log_file, stream_name):
    """Chờ file tồn tại rồi gọi process_log_file"""
    source = 'zeek' if log_file == 'notice.log' else 'snort'
    base = ZEEK_LOG_DIR if source == 'zeek' else SNORT_LOG_DIR
    path = os.path.join(base, log_file)
    while not os.path.exists(path):
        print(f"[!] Chờ tạo file {path} trong 30s...")
        time.sleep(30)
    print(f"[+] Phát hiện {path}, bắt đầu giám sát...")
    process_log_file(log_file, stream_name)

def print_rate_limits():
    """In thông tin về Rate Limits"""
    print("[+] Thông tin về Rate Limits:")
    for source, attack_types in RATE_LIMIT_CONFIG.items():
        print(f"  Nguồn: {source}")
        for attack, config in attack_types.items():
            window = config['window']
            max_count = config['max_count']
            print(f"    - {attack}: tối đa {max_count} log trong {window} giây")
    print("[+] Bắt đầu giám sát tất cả log...")

def start_monitoring():
    print_rate_limits()  # In thông tin rate limits trước khi giám sát
    for s in RATE_LIMIT_CONFIG:
        for t in RATE_LIMIT_CONFIG[s]:
            RATE_LIMIT_CONFIG[s].setdefault(t, RATE_LIMIT_CONFIG[s]['Default'])
    for lf, st in LOG_FILES.items():
        th = threading.Thread(target=wait_and_monitor, args=(lf, st), daemon=True)
        th.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("Đang dừng giám sát...")

if __name__ == '__main__':
    start_monitoring()
