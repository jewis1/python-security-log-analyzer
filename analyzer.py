from pathlib import Path
from datetime import datetime, timedelta

def check_login(status):
  if status == "FAILED":
    print("Security Alert: Failed login detected.")
  else:
    print("Login successful.")
    
failed_count = 0
failed_by_ip = {}
failed_times_by_ip = {}

log_path = Path(__file__).resolve().parent / "sample_logs" / "login.log"

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
      print("\nFive-minute security alerts:", failed_by_ip)

      check_login("FAILED")
   
    elif "LOGIN_SUCCESS" in line:
        check_login("SUCCESS")

print("Total failed login attempts:", failed_count)
print("\nFive-minute security alerts:")

window = timedelta(minutes=5)
threshold = 3

for ip, timestamps in failed_times_by_ip.items():
  timestamps = sorted(timestamps)

  if len(timestamps) >= threshold: 

      for i in range(len(timestamps) - threshold + 1):
        if timestamps[i + threshold - 1] - timestamps[i] <= window:
            print(f"Security Alert: IP {ip} has reached or exceeded the threshold of {threshold} failed login attempts within 5 minutes.")
            break
