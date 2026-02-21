import re
import json
import argparse
from collections import defaultdict
from datetime import datetime


def parse_timestamp(log_line):
    # Example format: Jul 20 10:01:23
    match = re.match(r'(\w+\s+\d+\s+\d+:\d+:\d+)', log_line)
    if match:
        return datetime.strptime(match.group(1), "%b %d %H:%M:%S")
    return None


def detect_bruteforce(log_file, threshold, time_window):
    attempts = defaultdict(list)
    alerts = []

    with open(log_file, "r") as file:
        for line in file:
            if "Failed password" in line:
                timestamp = parse_timestamp(line)
                ip_match = re.search(r'from (\d+\.\d+\.\d+\.\d+)', line)

                if timestamp and ip_match:
                    ip = ip_match.group(1)
                    attempts[ip].append(timestamp)

    for ip, times in attempts.items():
        times.sort()

        for i in range(len(times)):
            window = [t for t in times if 0 <= (t - times[i]).total_seconds() <= time_window]

            if len(window) >= threshold:
                alert = {
                    "alert_type": "SSH Brute Force Detected",
                    "attacker_ip": ip,
                    "failed_attempts": len(window),
                    "time_window_seconds": time_window
                }
                alerts.append(alert)
                break

    return alerts


def main():
    parser = argparse.ArgumentParser(description="SSH Brute Force Detector with Time Window")
    parser.add_argument("--log", required=True, help="Path to SSH log file")
    parser.add_argument("--threshold", type=int, default=5,
                        help="Failed attempts before alert (default: 5)")
    parser.add_argument("--window", type=int, default=60,
                        help="Time window in seconds (default: 60)")
    parser.add_argument("--output", default="alerts.json",
                        help="Output file (default: alerts.json)")

    args = parser.parse_args()

    alerts = detect_bruteforce(args.log, args.threshold, args.window)

    if alerts:
        with open(args.output, "w") as f:
            json.dump(alerts, f, indent=4)
        print("🚨 ALERT: Brute force detected!")
        print(json.dumps(alerts, indent=4))
    else:
        print("✅ No brute force detected.")


if __name__ == "__main__":
    main()
