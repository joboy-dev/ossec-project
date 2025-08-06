import pathlib
import re, os, socket, json
from datetime import datetime
import subprocess
import sys

ROOT_DIR = pathlib.Path(__file__).parent.parent

# ADD PROJECT ROOT TO IMPORT SEARCH SCOPE
sys.path.append(str(ROOT_DIR))
BASE_DIR = f"logs/ossec-alerts/{datetime.now().strftime('%Y-%m-%d')}"
os.makedirs(BASE_DIR, exist_ok=True)

OSSEC_LOG = f"{BASE_DIR}/alerts.log"
OUTPUT_FILE = f"{BASE_DIR}/alerts.json"

def get_log_level_meaning(level):
    meanings = {
        0: "Ignored",
        1: "System low priority notification",
        2: "Successful/Authorized events",
        3: "System low priority error",
        4: "User generated error",
        5: "Low relevance attack",
        6: "\"Bad word\" matching",
        7: "First time seen",
        8: "Error from invalid source",
        9: "Multiple user generated errors",
        10: "Integrity checking warning",
        11: "High importance event",
        12: "Unusual error (high importance)",
        13: "High importance security event",
        14: "Severe attack",
        15: "Severe attack, no false positives",
    }
    return meanings.get(level, "Unknown log level.")

alerts = []

with open(OSSEC_LOG, "r", errors="ignore") as f:
    raw_data = f.read().strip()

# Split alerts by blank line
entries = raw_data.split("\n\n")

for entry in entries:
    lines = entry.strip().split("\n")
    if not lines or not lines[0].startswith("** Alert"):
        continue

    # Extract Alert ID
    alert_id_match = re.search(r"\*\* Alert ([\d\.]+):", lines[0])
    alert_id = alert_id_match.group(1) if alert_id_match else None

    # Extract Rule ID and Level
    rule_match = re.search(r"Rule: (\d+) \(level (\d+)\) -> '([^']+)'", entry)
    rule_id = rule_match.group(1) if rule_match else None
    level = int(rule_match.group(2)) if rule_match else None
    description = rule_match.group(3) if rule_match else None

    # Extract User (optional)
    user_match = re.search(r"User: (\w+)", entry)
    user = user_match.group(1) if user_match else None

    # Extract Source IP (optional)
    ip_match = re.search(r"Src IP: ([\d\.]+)", entry)
    src_ip = ip_match.group(1) if ip_match else None
    
    # Extract date and time (standard format)
    dt_match = re.search(r"(\d{4} \w{3} \d{2} \d{2}:\d{2}:\d{2})", entry)
    dt_str = dt_match.group(1) if dt_match else None
    timestamp = None
    if dt_str:
        try:
            timestamp = datetime.strptime(dt_str, "%Y %b %d %H:%M:%S").isoformat()
        except Exception:
            timestamp = None
            
    # Get the hostname from the alert line (e.g., "2025 Jul 31 12:54:33 KOREDE-PC->/var/log/auth.log")
    hostname = None
    for line in lines:
        # m = re.search(r"\d{4} \w{3} \d{2} \d{2}:\d{2}:\d{2} ([\w\-]+)", line)
        m = re.search(r"\d{4} \w{3} \d{2} \d{2}:\d{2}:\d{2} ([^->\s]+)", line)
        if m:
            hostname = m.group(1)
            break
        
    # Get device IP (best effort, fallback to 127.0.0.1)
    try:
        device_ip = socket.gethostbyname(socket.gethostname())
        if device_ip.startswith("127."):
            # Try to get the first non-localhost IP
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                s.connect(("8.8.8.8", 80))
                device_ip = s.getsockname()[0]
            except Exception:
                pass
            finally:
                s.close()
    except Exception:
        device_ip = "127.0.0.1"
        
    # Extract the source log file path (e.g., "/var/log/auth.log")
    log_file_path = None
    for line in lines:
        m = re.search(r"->([^\s]+)", line)
        if m:
            log_file_path = m.group(1)
            break

    # Final log message (last line)
    log_msg = lines[-1].replace('"', '\\"')
    
    data = {
        "alert_id": alert_id,
        "rule_id": rule_id,
        "level": level,
        "level_meaning": get_log_level_meaning(level),
        "description": description,
        "user": user or "root",
        "timestamp": timestamp,
        "hostname": hostname,
        "device_ip": device_ip,
        "log_file_path": log_file_path,
        "log": log_msg
    }

    alerts.append(data)
    
# Save as JSON
with open(OUTPUT_FILE, "w") as f:
    json.dump(alerts, f, indent=4)

print(f"✅ Alerts saved to {OUTPUT_FILE}")

# result = subprocess.run(
#     # ["python3", f"{ROOT_DIR}/scripts/load_alerts_into_db.py"], 
#     ["python3", f"scripts/load_alerts_into_db.py"], 
#     capture_output=True, text=True
# )
# print(result.stdout)
# print(result.stderr)
