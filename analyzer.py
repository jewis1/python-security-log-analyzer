from pathlib import Path
from datetime import datetime

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
      print("\nFailed login attempts by IP:", failed_by_ip)

      for ip, timestamps in failed_times_by_ip.items():      
        print(f"IP: {ip}, Timestamps: {timestamps}")

        elapsed_times = timestamps[-1] - timestamps[0]
        print(f"\nElapsed time between first and last failed Login attempt for IP {ip}: {elapsed_times}")
        
      check_login("FAILED")
   
    elif "LOGIN_SUCCESS" in line:
        check_login("SUCCESS")

print("Total failed login attempts:", failed_count)
print("\nFailed login attempts by IP:")

threshold = 3

for ip, count in failed_by_ip.items():
  print(f"IP: {ip}, Count: {count}")

  if count >= threshold: 
    print(f"Security Alert: IP {ip} has exceeded the threshold of {threshold} failed login attempts.")

first_attempt = datetime.strptime("2026-09-20 10:03:21", "%Y-%m-%d %H:%M:%S")
last_attempt = datetime.strptime("2026-09-20 10:03:34", "%Y-%m-%d %H:%M:%S") 
elapsed_time = last_attempt - first_attempt
print(f"\nElapsed time between first and last failed login attempt: {elapsed_time}")
