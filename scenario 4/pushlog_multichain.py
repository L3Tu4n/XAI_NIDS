import json
import os
import threading
import subprocess
import time
import datetime
from tailer import follow
from collections import defaultdict

# --- CONFIG ---
ZEEK_LOG_DIR = "/usr/local/zeek/logs/current/"
SURICATA_LOG_DIR = "/var/log/suricata/"
MULTICHAIN_CHAIN_NAME = "securitylogchain"
STATE_FILE = "monitor_state.json"

LOG_FILES = {
    "notice.log": "zeek",
    "eve.json": "suricata"
}

RATE_LIMIT_CONFIG = {
    "suricata": {
        "DoS": {"window": 60, "max_count": 3},
        "DNS Tunneling": {"window": 60, "max_count": 5},
        "Unusual Port": {"window": 60, "max_count": 5},
        "Brute Force": {"window": 60, "max_count": 3},
        "Scan": {"window": 60, "max_count": 3}
    },
    "zeek": {
        "Ransomware": {"window": 60, "max_count": 5},
        "DNS Tunneling": {"window": 60, "max_count": 5},
        "Unusual Port": {"window": 60, "max_count": 5},
        "Brute Force": {"window": 60, "max_count": 3},
        "Scan": {"window": 60, "max_count": 3}
    }
}

ip_attack_counters = defaultdict(list)
state_lock = threading.Lock()

# --- UTILS ---
def get_time_str():
    return datetime.datetime.now().strftime("%H:%M:%S")

def load_state():
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE, 'r') as f: return json.load(f)
        except: return {}
    return {}

def save_state(state):
    tmp = STATE_FILE + ".tmp"
    with open(tmp, 'w') as f: json.dump(state, f)
    os.replace(tmp, STATE_FILE)

def identify_attack_type(log_entry):
    text_parts = []

    if "alert" in log_entry and isinstance(log_entry["alert"], dict):
        alert = log_entry["alert"]
        text_parts.append(str(alert.get("signature", "")))
        text_parts.append(str(alert.get("category", "")))
    
    else:
        text_parts.append(str(log_entry.get("msg", "")))
        text_parts.append(str(log_entry.get("note", "")))

    text = " ".join(text_parts).lower()

    rules = {
        "Ransomware": ["ransomware", "knownbadfilename"],
        "DNS Tunneling": ["dns tunnel", "dnstunnels", "tunneling"],
        "Unusual Port": ["unusual port", "unusual_port"],
        "Brute Force": ["brute force", "bruteforcer", "failed login"],
        "DoS": ["flood", "dos", "denial of service"],
        "Scan": ["scan", "sweep", "nmap"],
    }

    for attack, keywords in rules.items():
        if any(k in text for k in keywords):
            return attack

    return None

def get_ip_from_log(log_entry):
    return log_entry.get('src_ip') or log_entry.get('src') or log_entry.get('id.orig_h', 'unknown_ip')

def should_send_log(log_entry, source, attack_type):
    if not attack_type or attack_type not in RATE_LIMIT_CONFIG[source]:
        return False

    now = time.time()
    ip = get_ip_from_log(log_entry)
    key = f"{source}:{ip}:{attack_type}"
    cfg = RATE_LIMIT_CONFIG[source][attack_type]
    
    ip_attack_counters[key] = [t for t in ip_attack_counters[key] if now - t < cfg['window']]
    
    if len(ip_attack_counters[key]) < cfg['max_count']:
        ip_attack_counters[key].append(now)
        return True
    return False

def parse_suricata_log(line):
    try:
        j = json.loads(line)
        if j.get('event_type') != 'alert':
            return None
        return j
    except:
        return None

def parse_zeek_json_log(line):
    try:
        j = json.loads(line)
        if 'ts' in j:
            try:
                j['ts'] = datetime.datetime.fromtimestamp(float(j['ts'])).strftime("%Y-%m-%d %H:%M:%S")
            except: pass
        return j
    except: return None

def send_to_multichain(stream, log_entry, attack_type):
    key = f"log_{log_entry.get('ts', time.time())}_{hash(str(log_entry))}"
    data = json.dumps({"json": log_entry})
    cmd = f"multichain-cli {MULTICHAIN_CHAIN_NAME} publish {stream} {json.dumps(key)} {json.dumps(data)}"
    try:
        subprocess.run(cmd, shell=True, check=True, timeout=10, capture_output=True, text=True)
        
        source_name = "Zeek" if "zeek" in stream else "Suricata"
        print(f"[{get_time_str()}] [{source_name}] [{attack_type}] -> Published to Blockchain")
        
    except Exception as e:
        print(f"[!] Publish Error ({stream}): {e}")

def process_log_file(log_file, stream_name):
    source = 'zeek' if log_file == 'notice.log' else 'suricata'
    base_dir = ZEEK_LOG_DIR if source == 'zeek' else SURICATA_LOG_DIR
    path = os.path.join(base_dir, log_file)
    
    if not os.path.exists(path): return

    st_stat = os.stat(path)
    curr_ino = st_stat.st_ino
    curr_size = st_stat.st_size

    with state_lock:
        state = load_state()
        entry = state.get(log_file, {})
        off = entry.get('offset', 0)
        if entry.get('inode') != curr_ino or off > curr_size: off = 0
        state[log_file] = {'offset': off, 'inode': curr_ino}
        save_state(state)

    parser = parse_zeek_json_log if source == 'zeek' else parse_suricata_log

    def handle_line(line):
        e = parser(line.strip())
        if not e: return
        
        attack_type = identify_attack_type(e)
        if attack_type and should_send_log(e, source, attack_type):
            send_to_multichain(stream_name, e, attack_type)

    try:
        with open(path, 'r') as f:
            f.seek(off)
            for line in f: handle_line(line)
            
            with state_lock:
                state = load_state()
                state[log_file]['offset'] = f.tell()
                save_state(state)

            for line in follow(f, delay=1.0):
                handle_line(line)
                with state_lock:
                    state = load_state()
                    state[log_file]['offset'] = f.tell()
                    save_state(state)
    except Exception as ex:
        print(f"[!] Reading error {path}: {ex}")

def wait_and_monitor(log_file, stream_name):
    source = 'zeek' if log_file == 'notice.log' else 'suricata'
    base_dir = ZEEK_LOG_DIR if source == 'zeek' else SURICATA_LOG_DIR
    path = os.path.join(base_dir, log_file)
    
    while not os.path.exists(path):
        time.sleep(5)
    
    print(f"[+] Log Source Connected: {path}")
    process_log_file(log_file, stream_name)

def start_monitoring():
    print("=== INITIATING SECURE LOG TRANSFER TO MULTICHAIN ===")
    
    for lf, st in LOG_FILES.items():
        threading.Thread(target=wait_and_monitor, args=(lf, st), daemon=True).start()
        
    try:
        while True: time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] Stopping...")

if __name__ == '__main__':
    start_monitoring()
