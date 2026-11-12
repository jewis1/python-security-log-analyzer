from pathlib import Path

def check_login(status):
  if status == "FAILED":
    print("Security Alert: Failed login detected.")
  else:
    print("Login successful.")
    
failed_count = 0
failed_by_ip = {}

log_path = Path(__file__).resolve().parent / "sample_logs" / "login.log"

with open(log_path, "r") as log_file:
  for line in log_file:
    if "LOGIN_FAILED" in line:
      parts = line.split()
      username = parts[3]
      source_ip = parts[4]
      if source_ip in failed_by_ip:
        failed_by_ip[source_ip] += 1
      else: 
        failed_by_ip[source_ip] = 1
      failed_count = failed_count + 1
      print("Failed login user:", username)
      print("Source IP:", source_ip)
      
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
