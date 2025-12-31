# simulate_normal_traffic.py
import subprocess
import time
import random

WEBSITES = [
    "google.com", "github.com", "stackoverflow.com",
    "wikipedia.org", "youtube.com", "facebook.com"
]

def generate_web_traffic():
    """Giả lập duyệt web"""
    for _ in range(100):
        site = random.choice(WEBSITES)
        subprocess.run(['curl', '-s', f'https://{site}'], 
                      stdout=subprocess.DEVNULL)
        time.sleep(random.uniform(2, 8))

def generate_ssh_traffic():
    """Giả lập SSH (nếu có VM khác)"""
    # ssh user@other_vm 'ls -la; ps aux'
    pass

def generate_dns_queries():
    """Giả lập DNS lookups"""
    for _ in range(50):
        subprocess.run(['nslookup', random.choice(WEBSITES)])
        time.sleep(random.uniform(1, 3))

if __name__ == "__main__":
    print("[*] Generating normal traffic for 2 hours...")
    for i in range(24):  # 24 x 5 phút = 2 giờ
        print(f"[*] Batch {i+1}/24")
        generate_web_traffic()
        generate_dns_queries()
        time.sleep(60)