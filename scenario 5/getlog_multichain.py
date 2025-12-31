import requests
import json
import os
import time
from datetime import datetime

# --- CONFIG ---
RPC_HOST = "localhost"
RPC_PORT = "8332"
RPC_USER = "multichainrpc"
RPC_PASS = "5jTNfQ9KkPzenTx3qAjYKFx7wNQjP1kKx9NdvoVot6kn"
RPC_URL = f"http://{RPC_HOST}:{RPC_PORT}"

LOGSTASH_URL = "http://192.168.63.148:8080/"
STATE_FILE = "stream_state.json"
FAILED_LOG = "failed_logs.json"

STREAMS = ["zeek", "suricata"]
BATCH_SIZE = 100

# --- UTILS ---
def rpc_request(method, params):
    payload = {"method": method, "params": params, "id": 1, "jsonrpc": "2.0"}
    try:
        r = requests.post(
            RPC_URL, 
            json=payload, 
            auth=(RPC_USER, RPC_PASS), 
            timeout=60
        )
        r.raise_for_status()
        return r.json().get("result", [])
    except Exception as e:
        print(f"[!] RPC Error: {e}")
        return None

def parse_timestamp(ts_str):
    # Zeek format
    try: return datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S")
    except: pass
    
    # Suricata format
    try:
        clean = ts_str.split('+')[0].replace('Z', '')
        return datetime.strptime(clean, "%Y-%m-%dT%H:%M:%S.%f")
    except: pass
    return None

def should_push(date_str, ranges, singles):
    if date_str in singles: return True
    for s, e in ranges:
        if s <= date_str <= e: return True
    return False

def load_state():
    if not os.path.exists(STATE_FILE):
        default = {s: {"date_ranges": [], "single_dates": []} for s in STREAMS}
        with open(STATE_FILE, "w") as f: json.dump(default, f, indent=2)
        return None
    try:
        with open(STATE_FILE, "r") as f: return json.load(f)
    except: return None

# --- Thay đổi ưu tiên hiển thị ---
def send_log(data, stream):
    data["stream"] = stream
    max_retries = 3    
    for attempt in range(1, max_retries + 1):
        try:
            requests.post(LOGSTASH_URL, json=data, timeout=5).raise_for_status()
            
            raw_ts = data.get('ts', data.get('timestamp', ''))
            dt = parse_timestamp(str(raw_ts))
            display_ts = dt.strftime("%Y-%m-%d %H:%M:%S") if dt else raw_ts
            
            content = data.get('note') if 'note' in data else (data.get('msg') or data.get('classification') or "Alert")
            print(f"[+] [{stream}] [{display_ts}] {content} -> Đã gửi tới ELK")
            return True
            
        except Exception as e:
            print(f"[!] Thử lại lần {attempt}/{max_retries} cho stream {stream} do lỗi: {e}")
            if attempt < max_retries:
                time.sleep(1)
                
    return False

def save_fail(data, stream):
    with open(FAILED_LOG, "a") as f:
        json.dump({"stream": stream, "log": data}, f)
        f.write("\n")

# --- MAIN ---
if __name__ == "__main__":
    config = load_state()
    mode = "FILTER" if config else "PULL_ALL"
    
    if config:
        empty = True
        for s in STREAMS:
            if config.get(s, {}).get("date_ranges") or config.get(s, {}).get("single_dates"):
                empty = False; break
        if empty: mode = "PULL_ALL"

    print(f"=== CHẾ ĐỘ: {mode} | BATCH: {BATCH_SIZE} ===")

    for stream in STREAMS:
        print(f"\n[*] Đang quét stream: {stream}")
        s_cfg = config.get(stream, {}) if config else {}
        ranges = s_cfg.get("date_ranges", [])
        singles = set(s_cfg.get("single_dates", []))
        
        start_idx = 0 
        total = 0
        
        while True:
            items = rpc_request("liststreamitems", [stream, False, BATCH_SIZE, start_idx])
            if not items: break

            for item in items:
                try: log = item.get("data", {}).get("json", {})
                except: continue
                if not log: continue

                if mode == "FILTER":
                    raw_ts = log.get("timestamp") or log.get("ts")
                    if not raw_ts: continue
                    dt = parse_timestamp(str(raw_ts))
                    if not dt or not should_push(dt.strftime("%Y-%m-%d"), ranges, singles):
                        continue

                if send_log(log, stream): total += 1
                else: save_fail(log, stream)

            start_idx += len(items)
            if len(items) < BATCH_SIZE: break

        print(f"[=] Hoàn thành {stream}. Đã đẩy: {total} log(s)")

    print("\n=== HOÀN TẤT ===")
