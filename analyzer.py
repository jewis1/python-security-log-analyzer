
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

    # V1.2A: Missing-file exception handling
    if not log_path.exists():
        raise FileNotFoundError(f"Log file not found: {log_path}")

    with open(log_path, "r") as log_file:
        for line in log_file:

            # V1.2B-A: Remove leading and trailing whitespace
            line = line.strip()

            # V1.2B-A: Ignore blank lines and comments
            if not line or line.startswith("#"):
                continue

            # V1.2B-B: Split the authentication record
            parts = line.split()

            # V1.2B-B: Validate the number of fields
            if len(parts) != 5:
                print(f"Malformed log entry: {line}")
                continue

            # V1.2B-C: Extract the authentication event
            event_type = parts[2]

            # V1.2B-C: Reject unrecognized authentication events
            if event_type != "LOGIN_FAILED" and event_type != "LOGIN_SUCCESS":
                print(f"Unrecognized authentication event: {line}")
                continue

            # V1.2B-C: Construct the timestamp string
            timestamp_text = parts[0] + " " + parts[1]

            # V1.2C-B: Validate the timestamp format
            try:
                timestamp = datetime.strptime(timestamp_text, "%Y-%m-%d %H:%M:%S")

            except ValueError as error:
                #V1.2C-B: Reject invalid timestamp formats
                print(f"Invalid timestamp format: {timestamp_text} - {error}")
                continue

            # V1.2B-D: Process failed authentication attempts
            if event_type == "LOGIN_FAILED":
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

            # V1.2B-D: Process successful authentication attempts
            elif event_type == "LOGIN_SUCCESS":
                check_login("SUCCESS")

    return failed_count, failed_by_ip, failed_times_by_ip


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


def main():
    # Configuration variables
    window = timedelta(minutes=5)
    threshold = 3

    # Establish log file path
    log_path = Path(__file__).resolve().parent / "sample_logs" / "login.log"

    # Parse authentication logs
    try:
        failed_count, failed_by_ip, failed_times_by_ip = parse_logs(log_path)
    except FileNotFoundError as error:
        print(error)
        return

    # Display authentication statistics
    display_summary(failed_count, failed_by_ip)

    # Execute brute force detection
    print("\nFive-minute brute force detection:")
    detect_brute_force(failed_times_by_ip, threshold, window)


if __name__ == "__main__":
    main()  
