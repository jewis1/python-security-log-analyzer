import subprocess
import sys
import pytest
import csv
import os

from pathlib import Path


# V1.5F-A: Establish the analyzer's absolute path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
ANALYZER_PATH = PROJECT_ROOT / "analyzer.py"


# V1.5F-A: Reusable CLI execution helper
def run_cli(*args):

    return subprocess.run(
        [sys.executable, str(ANALYZER_PATH), *args],
        capture_output=True,
        text=True,
        cwd=PROJECT_ROOT,
        timeout=10
    )


# V1.5F-A1: Verify default CLI execution
def test_cli_default_execution():

    result = run_cli()

    assert result.returncode == 0
    assert result.stderr == ""
    assert "Total failed login attempts: 16" in result.stdout
    assert "5-minute brute force detection:" in result.stdout

    assert result.stdout.count(
        "Possible brute force attack detected from IP"
    ) == 3


# V1.5F-A2: Verify CLI help menu
def test_cli_help():

    result = run_cli("--help")

    assert result.returncode == 0
    assert result.stderr == ""

    assert "--threshold" in result.stdout
    assert "--window" in result.stdout
    assert "--file" in result.stdout
    assert "--report" in result.stdout


# V1.5F-A3: Verify unrecognized CLI arguments
def test_cli_invalid_argument():

    result = run_cli("--invalid")

    assert result.returncode == 2
    assert "unrecognized arguments" in result.stderr


# V1.5F-B1/B3: Verify customized detection configurations
@pytest.mark.parametrize("threshold, window, expected_alerts", [
    (5, 5, 0),
    (3, 1, 2),
    (3, 15, 4)
])
def test_cli_custom_configuration(
    threshold, window, expected_alerts
):

    result = run_cli(
        "--threshold", str(threshold),
        "--window", str(window)
    )

    assert result.returncode == 0
    assert result.stderr == ""

    assert "Total failed login attempts: 16" in result.stdout

    assert f"{window}-minute brute force detection:" in result.stdout

    assert result.stdout.count(
        "Possible brute force attack detected from IP"
    ) == expected_alerts


# V1.5F-B4/B8: Verify CLI configuration error handling
@pytest.mark.parametrize("arguments, exit_code, expected_message", [
    (
        ["--threshold", "0"],
        1,
        "Threshold must be greater than zero."
    ),
    (
        ["--window", "-5"],
        1,
        "Detection time window must be greater than zero."
    ),
    (
        ["--threshold", "abc"],
        2,
        "invalid int value"
    ),
    (
        ["--window", "abc"],
        2,
        "invalid int value"
    ),
    (
        ["--window", "999999999999999999999999"],
        1,
        "Detection time window is too large."
    )
])
def test_cli_configuration_errors(
    arguments, exit_code, expected_message
):

    result = run_cli(*arguments)

    assert result.returncode == exit_code

    if exit_code == 1:
        assert expected_message in result.stdout
    else:
        assert expected_message in result.stderr

    assert "Traceback" not in result.stderr
    assert "Total failed login attempts:" not in result.stdout


# V1.5F-C1: Verify actual CLI report generation
def test_cli_report_export(tmp_path):

    report_path = tmp_path / "report.csv"

    result = run_cli("--report", str(report_path))

    assert result.returncode == 0
    assert report_path.is_file()
    assert "CSV report generated successfully:" in result.stdout

    with open(report_path, "r", newline="", encoding="utf-8") as report_file:
        rows = list(csv.reader(report_file))

    assert rows == [
        ["source_ip", "failed_attempts", "brute_force_detected"],
        ["192.168.1.77", "4", "True"],
        ["10.0.0.15", "2", "False"],
        ["172.16.0.20", "3", "True"],
        ["192.168.1.99", "4", "True"],
        ["192.168.1.55", "3", "False"]
    ]


# V1.5F-C2/C3: Verify CLI filesystem error handling
@pytest.mark.parametrize("scenario, expected_message", [
    ("missing_log", "Log file not found:"),
    ("missing_directory", "Report error: Destination directory not found:")
])
def test_cli_filesystem_errors(
    tmp_path, scenario, expected_message
):

    if scenario == "missing_log":
        result = run_cli(
            "--file", str(tmp_path / "nonexistent.log")
        )
    else:
        result = run_cli(
            "--report",
            str(tmp_path / "missing_folder" / "report.csv")
        )

    assert result.returncode == 1
    assert expected_message in result.stdout
    assert "Traceback" not in result.stderr
    assert "CSV report generated successfully:" not in result.stdout


# V1.5F-C4/C5: Verify source-log integrity protection
@pytest.mark.parametrize("use_hardlink", [False, True])
def test_cli_source_protection(tmp_path, use_hardlink):

    log_path = tmp_path / "login.log"

    log_path.write_text(
        "2026-11-27 10:00:00 LOGIN_FAILED admin 192.168.1.77\n",
        encoding="utf-8"
    )

    original_content = log_path.read_bytes()

    if use_hardlink:
        report_path = tmp_path / "alias.csv"

        try:
            os.link(log_path, report_path)
        except (OSError, NotImplementedError) as error:
            pytest.skip(f"Hard links unavailable: {error}")

        expected_message = "Report destination references the source log file."
    else:
        report_path = log_path
        expected_message = "Report destination cannot match the source log file."

    result = run_cli(
        "--file", str(log_path),
        "--report", str(report_path)
    )

    assert result.returncode == 1
    assert expected_message in result.stdout
    assert log_path.read_bytes() == original_content
    assert report_path.read_bytes() == original_content


# V1.5F-C6: Preserve existing report during configuration failure
def test_cli_report_preservation(tmp_path):

    report_path = tmp_path / "report.csv"

    report_path.write_text(
        "Existing security report",
        encoding="utf-8"
    )

    original_content = report_path.read_bytes()

    result = run_cli(
        "--threshold", "0",
        "--report", str(report_path)
    )

    assert result.returncode == 1
    assert "Threshold must be greater than zero." in result.stdout
    assert report_path.read_bytes() == original_content
