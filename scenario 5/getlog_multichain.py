import requests
import json
from json import JSONDecodeError
from datetime import datetime
import time
import os

# ——— Cấu hình MultiChain RPC ———
rpc_user     = "multichainrpc"
rpc_password = "2FaUWWmwdqQxXAcKaqv7566hejiaZ21FUXuuDFPtztq7"
rpc_host     = "192.168.63.130"
rpc_port     = "8332"
rpc_url      = f"http://{rpc_user}:{rpc_password}@{rpc_host}:{rpc_port}"

# ——— Cấu hình Logstash HTTP input ———
logstash_url = "http://192.168.63.143:8080/"   # endpoint HTTP input của Logstash

# Danh sách streams cần kiểm tra
streams     = ["zeek_notice", "snort_alerts"]
state_file  = "stream_state.json"              # file chứa cấu hình ngày

# --- Nếu file stream_state.json chưa có thì tạo mới ---
was_created = False
if not os.path.exists(state_file):
    default_structure = {
        "zeek_notice": {
            "date_ranges": [],
            "single_dates": []
        },
        "snort_alerts": {
            "date_ranges": [],
            "single_dates": []
        }
    }
    with open(state_file, "w") as f:
        json.dump(default_structure, f, indent=2)
    print(f"[i] Đã tạo mới '{state_file}' với cấu trúc mặc định.")
    was_created = True

# --- Hàm gọi RPC đến MultiChain (liststreamitems) ---
def rpc_request(method, params):
    payload = {"method": method, "params": params, "id": 1, "jsonrpc": "2.0"}
    try:
        r = requests.post(rpc_url, json=payload, timeout=10)
        r.raise_for_status()
        return r.json().get("result", [])
    except Exception as e:
        print(f"[LỖI RPC] {e}")
        return []

# --- Chỉnh hàm parse để nhận cả 2 định dạng timestamp ---
def parse_zeek_snort_timestamp(ts_str):
    # 1) "MM/DD-HH:MM:SS.micro" -> thêm năm hiện tại
    try:
        year = datetime.now().year
        date_part, time_part = ts_str.split("-", 1)
        mm, dd = date_part.split("/")
        reformatted = f"{year}-{mm}-{dd} {time_part}"
        return datetime.strptime(reformatted, "%Y-%m-%d %H:%M:%S.%f")
    except:
        pass
    # 2) "YYYY-MM-DD HH:MM:SS"
    try:
        return datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S")
    except:
        return None

# --- Kiểm tra xem date_str có nằm trong date_ranges hoặc single_dates không ---
def should_push_date(date_str, date_ranges, single_dates):
    if date_str in single_dates:
        return True
    for (start, end) in date_ranges:
        if start <= date_str <= end:
            return True
    return False

# --- Load cấu hình ngày (date_ranges + single_dates) từ file JSON ---
def load_state():
    try:
        with open(state_file, "r") as f:
            raw = json.load(f)
    except (FileNotFoundError, JSONDecodeError):
        return None

    result = {}
    for s in streams:
        val = raw.get(s)
        if isinstance(val, dict):
            dr_list = []
            for pair in val.get("date_ranges", []):
                if isinstance(pair, (list, tuple)) and len(pair) == 2:
                    start, end = pair
                    try:
                        datetime.strptime(start, "%Y-%m-%d")
                        datetime.strptime(end,   "%Y-%m-%d")
                        dr_list.append((start, end))
                    except:
                        print(f"[!] Bỏ qua date_range không hợp lệ: {pair}")
                else:
                    # Hoặc pair = [] (placeholder) ⇒ bỏ qua
                    pass
            sd_set = set()
            for d in val.get("single_dates", []):
                if isinstance(d, str):
                    try:
                        datetime.strptime(d, "%Y-%m-%d")
                        sd_set.add(d)
                    except:
                        print(f"[!] Bỏ qua single_date không hợp lệ: '{d}'")
            result[s] = {"date_ranges": dr_list, "single_dates": sd_set}
        else:
            result[s] = {"date_ranges": [], "single_dates": set()}
    return result

# --- Hàm gửi log lên Logstash với retry và throttle ---
def send_with_retry(log_data, stream, max_retries=3, throttle=0.1):
    for attempt in range(1, max_retries + 1):
        try:
            res = requests.post(logstash_url, json=log_data, timeout=10)
            res.raise_for_status()
            print(f"[✓] Gửi lên Logstash thành công (HTTP {res.status_code})")
            print(f"[LOG] {json.dumps(log_data, indent=2)}\n")
            time.sleep(throttle)
            return True
        except Exception as e:
            print(f"[!] Lần thử {attempt} gửi Logstash lỗi: {e}")
            if attempt < max_retries:
                time.sleep(1)
    return False

# --- Nếu gửi thất bại sau retry, lưu tạm vào file để replay sau ---
def save_failed_log(log_data, stream):
    entry = {"stream": stream, "log": log_data}
    with open("failed_logs.json", "a") as f:
        json.dump(entry, f)
        f.write("\n")

# === CHẠY CHÍNH ===

# Nếu vừa tạo file, hoặc load_state trả None, ta chạy push-all
if was_created:
    config = None
else:
    config = load_state()

# Kiểm tra nếu đã có config nhưng tất cả date_ranges và single_dates đều trống => treat as push-all
if config is not None:
    all_empty = True
    for s in streams:
        br = config[s]["date_ranges"]
        bs = config[s]["single_dates"]
        if br or bs:
            all_empty = False
            break
    if all_empty:
        # Xoá cấu trúc trống để đi vào push-all
        config = None

if config is None:
    # === PUSH ALL MODE ===
    print("=== ĐANG PUSH TOÀN BỘ LOG ===")
    for stream in streams:
        print(f"[+] Quét toàn bộ items của stream '{stream}' và push tất cả ...")
        items = rpc_request("liststreamitems", [stream, False, 999999, 0])
        if not isinstance(items, list):
            print(f"[!] Dữ liệu trả về không phải list, bỏ qua stream '{stream}'.")
            continue
        if not items:
            print(f"[ ] Stream '{stream}' chưa có item nào.")
            continue

        pushed = 0
        for item in items:
            log_data = item.get("data", {}).get("json", {})
            if not isinstance(log_data, dict):
                continue
            log_data["stream"] = stream
            if send_with_retry(log_data, stream):
                pushed += 1
            else:
                save_failed_log(log_data, stream)

        print(f"[→] Stream '{stream}': Đã push {pushed} log (tất cả), "
              f"{len(items)-pushed} log lỗi đã lưu vào 'failed_logs.json'.\n")
    print("=== HOÀN TẤT PUSH TOÀN BỘ LOG ===")
    exit(0)

# === FILTER MODE (đã có config và không trống) ===
print("=== BẮT ĐẦU QUÉT VÀ PUSH LOG THEO NGÀY/TỪNG KHOẢNG NGÀY (theo stream_state.json) ===")
for stream in streams:
    cfg = config.get(stream, {"date_ranges": [], "single_dates": set()})
    date_ranges = cfg["date_ranges"]
    single_dates = cfg["single_dates"]

    print(f"[+] Quét toàn bộ items của stream '{stream}' ...")
    items = rpc_request("liststreamitems", [stream, False, 999999, 0])
    if not isinstance(items, list):
        print(f"[!] Dữ liệu trả về không phải list, bỏ qua stream '{stream}'.")
        continue
    if not items:
        print(f"[ ] Stream '{stream}' chưa có item nào.")
        continue

    pushed = 0
    failed = 0
    for item in items:
        log_data = item.get("data", {}).get("json", {})
        if not isinstance(log_data, dict):
            continue

        raw_ts = log_data.get("timestamp") or log_data.get("ts")
        if not raw_ts:
            continue

        dt = parse_zeek_snort_timestamp(raw_ts)
        if dt is None:
            continue

        date_str = dt.strftime("%Y-%m-%d")
        if should_push_date(date_str, date_ranges, single_dates):
            log_data["stream"] = stream
            if send_with_retry(log_data, stream):
                pushed += 1
            else:
                failed += 1
                save_failed_log(log_data, stream)

    print(f"[→] Stream '{stream}': Đã push {pushed} log thành công, "
          f"{failed} log lỗi đã lưu vào 'failed_logs.json'.\n")

print("=== KẾT THÚC CHẠY ===")