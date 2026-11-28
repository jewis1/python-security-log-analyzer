from datetime import datetime
from analyzer import parse_logs
import pytest


# V1.5C-A: Verify valid failed-login parsing
def test_valid_failed_login(tmp_path):

    log_path = tmp_path / "test.log"

    log_path.write_text(
        "2026-11-27 10:00:00 LOGIN_FAILED admin 192.168.1.77\n"
    )

    failed_count, failed_by_ip, failed_times_by_ip = parse_logs(log_path)

    assert failed_count == 1

    assert failed_by_ip == {"192.168.1.77": 1}

    assert failed_times_by_ip == {
        "192.168.1.77": [datetime(2026, 11, 27, 10, 0, 0)]
    }

# V1.5C-B1: Verify successful logins are excluded
def test_successful_login(tmp_path):

    log_path = tmp_path / "test.log"

    log_path.write_text(
        "2026-11-27 10:00:00 LOGIN_SUCCESS admin 192.168.1.77\n"
    )

    failed_count, failed_by_ip, failed_times_by_ip = parse_logs(log_path)

    assert failed_count == 0
    assert failed_by_ip == {}
    assert failed_times_by_ip == {}

# V1.5C-B2: Verify mixed authentication event classification
def test_mixed_authentication(tmp_path):

    log_path = tmp_path / "test.log"

    log_path.write_text(
        "2026-11-27 10:00:00 LOGIN_FAILED admin 192.168.1.77\n"
        "2026-11-27 10:01:00 LOGIN_SUCCESS admin 192.168.1.77\n"
        "2026-11-27 10:02:00 LOGIN_FAILED admin 192.168.1.77\n"
        "2026-11-27 10:03:00 LOGIN_FAILED guest 10.0.0.15\n"
    )

    failed_count, failed_by_ip, failed_times_by_ip = parse_logs(log_path)

    assert failed_count == 3

    assert failed_by_ip == {
        "192.168.1.77": 2,
        "10.0.0.15": 1
    }

    assert failed_times_by_ip == {
        "192.168.1.77": [
            datetime(2026, 11, 27, 10, 0, 0),
            datetime(2026, 11, 27, 10, 2, 0)
        ],
        "10.0.0.15": [
            datetime(2026, 11, 27, 10, 3, 0)
        ]
    }

# V1.5C-C1: Verify invalid authentication entries are rejected
@pytest.mark.parametrize("entry, expected_message", [
    (
        "MALFORMED LOG ENTRY",
        "Malformed log entry:"
    ),
    (
        "2026-11-27 10:00:00 UNKNOWN_EVENT admin 192.168.1.77",
        "Unrecognized authentication event:"
    ),
    (
        "2026-13-27 10:00:00 LOGIN_FAILED admin 192.168.1.77",
        "Invalid timestamp format:"
    )
])
def test_invalid_log_entry(tmp_path, capsys, entry, expected_message):

    log_path = tmp_path / "test.log"

    log_path.write_text(entry + "\n")

    failed_count, failed_by_ip, failed_times_by_ip = parse_logs(log_path)

    captured = capsys.readouterr()

    assert failed_count == 0
    assert failed_by_ip == {}
    assert failed_times_by_ip == {}
    assert expected_message in captured.out

# V1.5C-C2: Verify parsing continues after invalid entries
def test_parsing_resilience(tmp_path, capsys):

    log_path = tmp_path / "test.log"

    log_path.write_text(
        "2026-11-27 10:00:00 LOGIN_FAILED admin 192.168.1.77\n"
        "MALFORMED LOG ENTRY\n"
        "2026-11-27 10:01:00 UNKNOWN_EVENT admin 192.168.1.77\n"
        "2026-13-27 10:02:00 LOGIN_FAILED admin 192.168.1.77\n"
        "2026-11-27 10:03:00 LOGIN_FAILED admin 192.168.1.77\n"
    )

    failed_count, failed_by_ip, failed_times_by_ip = parse_logs(log_path)

    captured = capsys.readouterr()

    assert failed_count == 2
    assert failed_by_ip == {"192.168.1.77": 2}

    assert failed_times_by_ip == {
        "192.168.1.77": [
            datetime(2026, 11, 27, 10, 0, 0),
            datetime(2026, 11, 27, 10, 3, 0)
        ]
    }

    assert "Malformed log entry:" in captured.out
    assert "Unrecognized authentication event:" in captured.out
    assert "Invalid timestamp format:" in captured.out

# V1.5C-D1: Verify empty logs and ignored content
@pytest.mark.parametrize("content", [
    "",
    "   \n\n# Authentication log comment\n"
])
def test_empty_log(tmp_path, capsys, content):

    log_path = tmp_path / "test.log"

    log_path.write_text(content)

    result = parse_logs(log_path)

    captured = capsys.readouterr()

    assert result == (0, {}, {})
    assert captured.out == ""

# V1.5C-D2: Verify missing file exception
def test_missing_log(tmp_path):

    log_path = tmp_path / "nonexistent.log"

    with pytest.raises(FileNotFoundError, match="Log file not found:"):
        parse_logs(log_path)

# V1.5C-D3: Simulate denied file access
def test_log_permission_error(tmp_path, monkeypatch):

    log_path = tmp_path / "test.log"

    log_path.write_text("Authentication log")

    def deny_access(*args, **kwargs):
        raise PermissionError("Simulated access denied")

    monkeypatch.setattr("builtins.open", deny_access)

    with pytest.raises(PermissionError, match="Simulated access denied"):
        parse_logs(log_path)
