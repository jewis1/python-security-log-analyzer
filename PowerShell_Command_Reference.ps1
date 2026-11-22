# Calculate hashes for the active log and backup. This compares file
# contents without opening them in an editor or changing them.
# Get-FileHash login.log, login_backup.log

# Calculate the active log's hash alone. Compare before and after a test
# to verify that its contents have not changed.
# Get-FileHash login.log

# Previously verified original login.log SHA256:
# E8EB9EAB1FE66330E05F576CE624F0CD345DC9BBBB254CB51896A9D2827E459A
#
# A matching hash means the contents are identical. Renaming a file does
# not change its contents or hash.


# ---------------------------------------------------------------------------
# 3. RUN THE ANALYZER — ORIGINAL DATASET / REGRESSION TEST
# ---------------------------------------------------------------------------

# Run analyzer.py from the project root while PowerShell is in sample_logs.
# The & operator executes the Python .exe; ..\ means the parent folder.
# This checks that existing behavior still works after a code change.
# & "$HOME\.local\bin\python3.15.exe" ..\analyzer.py

# Expected original-dataset results:
# - 16 failed login attempts
# - 5 unique source IP addresses
# - 3 brute-force alerts
# - 0 invalid timestamp warnings


# ---------------------------------------------------------------------------
# 4. TEST MISSING-FILE HANDLING (V1.2A)
# ---------------------------------------------------------------------------
#
# CAUTION: This test temporarily renames login.log. Run the rename,
# analyzer, and restore commands in order. Do not leave it renamed.

# Step 1 — Temporarily rename the original log file.
# Rename-Item -Path login.log -NewName login_v12_test.log

# Step 2 — Confirm the temporary filename is present.
# Get-ChildItem

# Step 3 — Run the analyzer. It should print a clear "Log file not found"
# message rather than an unhandled traceback.
# & "$HOME\.local\bin\python3.15.exe" ..\analyzer.py

# Step 4 — RESTORE THE ORIGINAL FILENAME immediately after the test.
# Rename-Item login_v12_test.log login.log

# Step 5 — Confirm login.log has been restored.
# Get-ChildItem

# Step 6 — Run the analyzer again to confirm normal operation.
# & "$HOME\.local\bin\python3.15.exe" ..\analyzer.py


# ---------------------------------------------------------------------------
# 5. QUICK RECOVERY IF THE LOG IS STILL RENAMED
# ---------------------------------------------------------------------------

# If Get-ChildItem shows login_v12_test.log but not login.log, restore it:
# Rename-Item login_v12_test.log login.log

# Verify the original filename is back:
# Get-ChildItem

# Then rerun the normal analyzer command from Section 3.


# ---------------------------------------------------------------------------
# SAFETY NOTES
# ---------------------------------------------------------------------------

# Get-ChildItem, Get-Content, and Get-FileHash are inspection commands;
# they do not modify the log file.
#
# Rename-Item changes the filename, not the file contents. Restore the
# original name immediately after the missing-file test.
#
# The Python command runs the analyzer; it does not itself edit login.log.
#
# Do not use Remove-Item on login.log or login_backup.log.
# Keep the original sample dataset intact as a regression-test baseline.

