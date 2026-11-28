import csv
import pytest
import sys

from analyzer import generate_csv_report, main


# V1.5E-A1: Verify CSV report file creation
def test_report_creation(tmp_path):

    report_path = tmp_path / "report.csv"

    generate_csv_report(report_path, {}, [])

    assert report_path.is_file()


# V1.5E-A2: Verify CSV column headers
def test_report_schema(tmp_path):

    report_path = tmp_path / "report.csv"

    generate_csv_report(report_path, {}, [])

    with open(report_path, "r", newline="", encoding="utf-8") as report_file:
        reader = csv.reader(report_file)
        header = next(reader)

    assert header == [
        "source_ip",
        "failed_attempts",
        "brute_force_detected"
    ]


# V1.5E-A3: Verify empty report contains only headers
def test_empty_report(tmp_path):

    report_path = tmp_path / "report.csv"

    generate_csv_report(report_path, {}, [])

    with open(report_path, "r", newline="", encoding="utf-8") as report_file:
        reader = csv.reader(report_file)
        rows = list(reader)

    assert len(rows) == 1


# V1.5E-B: Verify CSV report content and detection accuracy
@pytest.mark.parametrize("failed_by_ip, detected_ips, expected_rows", [
    (
        {"192.168.1.77": 4},
        ["192.168.1.77"],
        [["192.168.1.77", "4", "True"]]
    ),
    (
        {"10.0.0.15": 2},
        [],
        [["10.0.0.15", "2", "False"]]
    ),
    (
        {
            "192.168.1.77": 4,
            "10.0.0.15": 2,
            "172.16.0.20": 3,
            "192.168.1.55": 3
        },
        ["192.168.1.77", "172.16.0.20"],
        [
            ["192.168.1.77", "4", "True"],
            ["10.0.0.15", "2", "False"],
            ["172.16.0.20", "3", "True"],
            ["192.168.1.55", "3", "False"]
        ]
    ),
    (
        {"192.168.1.77": 2, "10.0.0.15": 1},
        [],
        [
            ["192.168.1.77", "2", "False"],
            ["10.0.0.15", "1", "False"]
        ]
    )
])
def test_report_content(
    tmp_path, failed_by_ip, detected_ips, expected_rows
):

    report_path = tmp_path / "report.csv"

    generate_csv_report(
        report_path, failed_by_ip, detected_ips
    )

    with open(report_path, "r", newline="", encoding="utf-8") as report_file:
        reader = csv.reader(report_file)
        next(reader)
        rows = list(reader)

    assert rows == expected_rows


# V1.5E-C1: Verify missing destination directory
def test_missing_report_directory(tmp_path):

    report_path = tmp_path / "missing_folder" / "report.csv"

    with pytest.raises(FileNotFoundError):
        generate_csv_report(report_path, {}, [])


# V1.5E-C2/C3: Simulate filesystem write failures
@pytest.mark.parametrize("error_type, message", [
    (PermissionError, "Simulated access denied"),
    (OSError, "Simulated disk write failure")
])
def test_report_write_error(
    tmp_path, monkeypatch, error_type, message
):

    report_path = tmp_path / "report.csv"

    def fail_write(*args, **kwargs):
        raise error_type(message)

    monkeypatch.setattr(
        "analyzer.open", fail_write, raising=False
    )

    with pytest.raises(error_type, match=message):
        generate_csv_report(report_path, {}, [])


# V1.5E-C4: Simulate CSV writer failure
def test_csv_writer_error(tmp_path, monkeypatch):

    report_path = tmp_path / "report.csv"

    def fail_writer(*args, **kwargs):
        raise csv.Error("Simulated CSV writer failure")

    monkeypatch.setattr("analyzer.csv.writer", fail_writer)

    with pytest.raises(
        csv.Error, match="Simulated CSV writer failure"
    ):
        generate_csv_report(report_path, {}, [])


# V1.5E-D1: Verify end-to-end report generation
def test_reporting_integration(tmp_path, monkeypatch, capsys):

    log_path = tmp_path / "login.log"
    report_path = tmp_path / "report.csv"

    log_path.write_text(
        "2026-11-27 10:00:00 LOGIN_FAILED admin 192.168.1.77\n"
        "2026-11-27 10:00:01 LOGIN_FAILED admin 192.168.1.77\n"
        "2026-11-27 10:00:02 LOGIN_FAILED admin 192.168.1.77\n"
        "2026-11-27 10:00:03 LOGIN_FAILED guest 10.0.0.15\n",
        encoding="utf-8"
    )

    monkeypatch.setattr(sys, "argv", [
        "analyzer.py",
        "--file", str(log_path),
        "--report", str(report_path)
    ])

    result = main()

    assert result == 0
    assert report_path.is_file()

    with open(report_path, "r", newline="", encoding="utf-8") as report_file:
        rows = list(csv.reader(report_file))

    assert rows == [
        ["source_ip", "failed_attempts", "brute_force_detected"],
        ["192.168.1.77", "3", "True"],
        ["10.0.0.15", "1", "False"]
    ]

    assert "CSV report generated successfully:" in capsys.readouterr().out


# V1.5E-D2: Prevent overwriting the source log
def test_source_log_protection(tmp_path, monkeypatch, capsys):

    log_path = tmp_path / "login.log"

    log_path.write_text(
        "2026-11-27 10:00:00 LOGIN_FAILED admin 192.168.1.77\n",
        encoding="utf-8"
    )

    original_content = log_path.read_bytes()

    monkeypatch.setattr(sys, "argv", [
        "analyzer.py",
        "--file", str(log_path),
        "--report", str(log_path)
    ])

    result = main()

    assert result == 1
    assert log_path.read_bytes() == original_content

    assert "Report destination cannot match the source log file." in capsys.readouterr().out


# V1.5E-D3/D6: Verify integrated report exception handling
@pytest.mark.parametrize("error_type, expected_message", [
    (FileNotFoundError, "Report error: Destination directory not found:"),
    (PermissionError, "Report error: Permission denied:"),
    (OSError, "Report error: Unable to write CSV report:"),
    (csv.Error, "Report error: CSV export failed:")
])
def test_reporting_exception_handling(
    tmp_path, monkeypatch, capsys,
    error_type, expected_message
):

    log_path = tmp_path / "login.log"
    report_path = tmp_path / "report.csv"

    log_path.write_text(
        "2026-11-27 10:00:00 LOGIN_FAILED admin 192.168.1.77\n",
        encoding="utf-8"
    )

    monkeypatch.setattr(sys, "argv", [
        "analyzer.py",
        "--file", str(log_path),
        "--report", str(report_path)
    ])

    def fail_export(*args, **kwargs):
        raise error_type("Simulated export failure")

    monkeypatch.setattr(
        "analyzer.generate_csv_report", fail_export
    )

    result = main()

    assert result == 1
    assert not report_path.exists()

    captured = capsys.readouterr()

    assert expected_message in captured.out
    assert "CSV report generated successfully:" not in captured.out
