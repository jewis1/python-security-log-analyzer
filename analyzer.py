def check_login(status):
  if status == "FAILED":
    print("Security Alert: Failed login detected.")
  else:
    print("Login successful.")

login_status = "FAILED"
check_login(login_status)
