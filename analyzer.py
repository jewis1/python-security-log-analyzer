
from pathlib import Path
from datetime import datetime, timedelta
import argparse

def validate_config(threshold, window):
    #V1.2E:Validate configuration parameters
    if not isinstance(threshold, int) or isinstance(threshold, bool):
        raise ValueError("Threshold must be a positive integer.")

    if threshold <= 0:
        raise ValueError("Threshold must be greater than zero.")

    #V1.2E: Validate detection time window and threshold values
    if not isinstance(window, timedelta):
        raise ValueError("Detection window must be a timedelta object.")

    if window <= timedelta(0):
        raise ValueError("Detection time window must be greater than zero.")


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
    #V1.4B-A: Store detected brute-force source IPs
    detected_ips = []
    for ip, timestamps in failed_times_by_ip.items():
        timestamps = sorted(timestamps)

        if len(timestamps) >= threshold:
            for i in range(len(timestamps) - threshold + 1):
                if timestamps[i + threshold - 1] - timestamps[i] <= window:
                    #V1.4B-A: Record detected brute-force source IP
                    detected_ips.append(ip)
                    print(f"Security Alert: Possible brute force attack detected from IP {ip}.")
                    detected_ips.append(ip)
                    break

    return detected_ips


def display_summary(failed_count, failed_by_ip):
    print("\nSummary of failed login attempts:")
    print(f"Total failed login attempts: {failed_count}")
    print("Failed login attempts by source IP:")

    for ip, count in failed_by_ip.items():
        print(f"{ip}: {count}")

def main():
    #V1.3A: Initialize argument parser (CLI)
    parser = argparse.ArgumentParser(description="Python Security Log Analyzer")

    #V1.3B: Define the brute-force detection threshold 
    parser.add_argument("--threshold", type=int, default=3,
                        help="Failed login threshold (default: 3)")

    #V1.3B: Define the detection time window (in minutes)
    parser.add_argument("--window", type=int, default=5,
                        help="Detection window in minutes (default: 5)")

    #V1.3B: Define the input log file path (optional)   
    parser.add_argument("--file", type=str, default=None,
                        help="Path to authentication log file (default: sample_logs/login.log)")

    #V1.3A: Parse command-line arguments
    args = parser.parse_args()

    # Configuration variables
    threshold = args.threshold

    # V1.3C-D: Handle excessive detection window values
    try:
        window = timedelta(minutes=args.window)
        validate_config(threshold, window)

    # V1.3C-E: Return failure exit codes
    except OverflowError:
        print("Configuration error: Detection time window is too large.")
        return 1

    except ValueError as error:
        print(f"Configuration error: {error}")
        return 1

    # V1.3B: Establish log file path from CLI
    if args.file:
        log_path = Path(args.file)
    else:
        log_path = Path(__file__).resolve().parent / "sample_logs" / "login.log" 

    # Parse authentication logs
    try:
        failed_count, failed_by_ip, failed_times_by_ip = parse_logs(log_path)

    except FileNotFoundError as error:
        print(error)
        return 1

    except PermissionError as error:
        print(f"Permission denied: {error}")
        return 1

    except OSError as error:
        print(f"Unable to access log file: {error}")
        return 1

    except Exception as error:
        print(f"An unexpected error occurred while parsing logs: {error}")
        return 1

    # Display authentication statistics
    display_summary(failed_count, failed_by_ip)

    # Execute brute force detection
    print(f"\n{args.window}-minute brute force detection:")
    detect_brute_force(failed_times_by_ip, threshold, window)

    # V1.3C-E: Indicate successful execution
    return 0

# V2.3C-E: Communicate process exit status
if __name__ == "__main__":
    raise SystemExit(main())
