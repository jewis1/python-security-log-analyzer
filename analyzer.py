from pathlib import Path

def check_login(status):
  if status == "FAILED":
    print("Security Alert: Failed login detected.")
  else:
    print("Login successful.")
    
failed_count = 0

log_path = Path(__file__).resolve().parent / "sample_logs" / "login.log"

with open(log_path, "r") as log_file:
  for line in log_file:
    if "LOGIN_FAILED" in line:
      parts = line.split()
      username = parts[3]
      source_ip = parts[4]
      failed_count = failed_count + 1
      print("Failed login user:", username)
      print("Source IP:", source_ip)
      
      check_login("FAILED")
   
    elif "LOGIN_SUCCESS" in line:
        check_login("SUCCESS")
      
print("Total failed login attempts:", failed_count)
