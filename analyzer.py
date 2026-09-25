def check_login(status):
  if status == "FAILED":
    print("Security Alert: Failed login detected.")
  else:
    print("Login successful.")
    
failed_count = 0

with open("sample_logs/login.log", "r") as log_file:
  for line in log_file:
    if "LOGIN_FAILED" in line:
      parts = line.split()
      username = parts[3]
      failed_count = failed_count + 1
      print("Failed login user:", username)
      check_login("FAILED")
   
    elif "LOGIN_SUCCESS" in line:
        check_login("SUCCESS")
      
print("Total failed login attempts:", failed_count)
