from pathlib import Path
from datetime import datetime, timedelta

def check_login(status):
  if status == "FAILED":
    print("Security Alert: Failed login detected.")
  else:
    print("Login successful.")

def parse_logs(log_path):
  failed_count = 0
  failed_by_ip = {}
  failed_times_by_ip = {}

  if not log_path.exists():
    print(f"Log file not found: {log_path}")
    return failed_count, failed_by_ip, failed_times_by_ip

  with open(log_path, "r") as log_file:
    for line in log_file:
      if "LOGIN_FAILED" in line:
        parts = line.split()
        timestamp_text = parts[0] + " " + parts[1]
        timestamp = datetime.strptime(timestamp_text, "%Y-%m-%d %H:%M:%S")
        username = parts[3]
        source_ip = parts[4]

        if source_ip in failed_times_by_ip:
          failed_times_by_ip[source_ip].append(timestamp)
        else:
          failed_times_by_ip[source_ip] = [timestamp]

        if source_ip in failed_by_ip:
          failed_by_ip[source_ip] += 1
        else:
          failed_by_ip[source_ip] = 1

        failed_count = failed_count + 1

        print("Failed login user:", username)
        print("Source IP:", source_ip)
        print(f"Timestamp: {timestamp}")

        check_login("FAILED")

      elif "LOGIN_SUCCESS" in line:
        check_login("SUCCESS")

  return failed_count, failed_by_ip, failed_times_by_ip


window = timedelta(minutes=5)
threshold = 3

def detect_brute_force(failed_times_by_ip, threshold, window):
  for ip, timestamps in failed_times_by_ip.items():
    timestamps = sorted(timestamps)

    if len(timestamps) >= threshold:
      for i in range(len(timestamps) - threshold + 1):
        if timestamps[i + threshold - 1] - timestamps[i] <= window:
          print(f"Security Alert: Possible brute force attack detected from IP {ip}.")
          break

def display_summary(failed_count, failed_by_ip):
  print("\nSummary of failed login attempts:")
  print(f"Total failed login attempts: {failed_count}")
  print("Failed login attempts by source IP:")
  for ip, count in failed_by_ip.items():
    print(f"{ip}: {count}")

log_path = Path(__file__).resolve().parent / "sample_logs" / "login.log"

failed_count, failed_by_ip, failed_times_by_ip = parse_logs(log_path)

display_summary(failed_count, failed_by_ip)

print("\nFive-minute brute force detection:")

detect_brute_force(failed_times_by_ip, threshold, window)
