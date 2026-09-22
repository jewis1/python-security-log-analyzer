def check_login(status):
  if status == "FAILED":
    print("Security Alert: Failed login detected.")
  else:
    print("Login successful.")

with open("sample_logs/login.log", "r") as log_file:
  for line in log_file:
    if "LOGIN_FAILED" in line:
        check_login("FAILED")
    elif "LOGIN_SUCCESS" in line:
        check_login("SUCCESS")
