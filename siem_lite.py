import re
import sys
import json
from collections import Counter


# ---------------- ARGUMENT CHECK ----------------
if len(sys.argv) != 3:
    print("Usage: python siem_lite.py <logfile> <threshold>")
    sys.exit(1)

log_file = sys.argv[1]

# ---------------- THRESHOLD ----------------
try:
    threshold = int(sys.argv[2])
except ValueError:
    print("Threshold must be a number")
    sys.exit(1)


ip_list = []

# ---------------- FILE READING ----------------
try:
    with open(log_file, "r") as file:
        logs = file.readlines()

except FileNotFoundError:
    print("Log file not found")
    sys.exit(1)

except Exception as e:
    print("Error reading file:", e)
    sys.exit(1)


# ---------------- PROCESS LOGS ----------------
for line in logs:

    # ✅ Detect multiple suspicious patterns (dynamic SIEM behaviour)
    if any(keyword in line for keyword in [
        "Failed password",
        "Invalid user",
        "authentication failure"
    ]):

        # ✅ Robust IP extraction
        matches = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', line)

        for ip in matches:
            ip_list.append(ip)


# ---------------- COUNT ----------------
ip_counter = Counter(ip_list)


# ---------------- DETECT MALICIOUS ----------------
malicious_ips = [
    ip for ip, count in ip_counter.items()
    if count >= threshold
]

# ✅ Sort by severity
malicious_ips = sorted(
    malicious_ips,
    key=lambda ip: ip_counter[ip],
    reverse=True
)


# ---------------- EXPORT JSON ----------------
output = {
    "alerts": [
        {
            "ip": ip,
            "attempts": ip_counter[ip],
            "threat_level": "HIGH" if ip_counter[ip] > threshold * 2 else "MEDIUM"
        }
        for ip in malicious_ips
    ]
}

try:
    with open("malicious_ips.json", "w") as file:
        json.dump(output, file, indent=4)

except Exception as e:
    print("Error writing JSON:", e)


# ---------------- PRINT ----------------
print("---- SIEM Lite Detection Results ----")

if malicious_ips:
    print("Malicious IPs detected:")

    for ip in malicious_ips:
        print(f"{ip} -> {ip_counter[ip]} suspicious events")

else:
    print("No malicious activity detected.")