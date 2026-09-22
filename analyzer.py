def check_login(status):
  if status == "FAILED":
    print("Security Alert: Failed login detected.")
  else:
    print("Login successful.")

login_status = ["SUCCESS", "FAILED", "FAILED", "FAILED", "FAILED"]
for status in login_statuses:
check_login(status)
