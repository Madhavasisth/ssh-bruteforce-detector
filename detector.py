import re
import json
import argparse
from collections import defaultdict


def detect_bruteforce(log_file, threshold):
    failed_attempts = defaultdict(int)
    alerts = []

    with open(log_file, "r") as file:
        for line in file:
            if "Failed password" in line:
                match = re.search(r'from (\d+\.\d+\.\d+\.\d+)', line)
                if match:
                    ip = match.group(1)
                    failed_attempts[ip] += 1

    for ip, count in failed_attempts.items():
        if count >= threshold:
            alert = {
                "alert_type": "SSH Brute Force Detected",
                "attacker_ip": ip,
                "failed_attempts": count
            }
            alerts.append(alert)

    return alerts


def main():
    parser = argparse.ArgumentParser(description="SSH Brute Force Detector")
    parser.add_argument("--log", required=True, help="Path to SSH log file")
    parser.add_argument("--threshold", type=int, default=5,
                        help="Number of failed attempts before alert (default: 5)")
    parser.add_argument("--output", default="alerts.json",
                        help="Output file for alerts (default: alerts.json)")

    args = parser.parse_args()

    alerts = detect_bruteforce(args.log, args.threshold)

    if alerts:
        with open(args.output, "w") as f:
            json.dump(alerts, f, indent=4)
        print("🚨 ALERT: Brute force detected!")
        print(json.dumps(alerts, indent=4))
    else:
        print("✅ No brute force detected.")


if __name__ == "__main__":
    main()
