import pytest

from datetime import datetime, timedelta
from analyzer import detect_brute_force


# V1.5A-C: Verify detection behavior with an empty dataset
def test_empty_detection():

    result = detect_brute_force({}, 3, timedelta(minutes=5))

    assert result == []

# V1.5D-A: Verify brute-force detection thresholds
@pytest.mark.parametrize("attempts, threshold, expected_result", [
    (2, 3, []),
    (3, 3, ["192.168.1.77"]),
    (4, 3, ["192.168.1.77"]),
    (1, 1, ["192.168.1.77"])
])
def test_detection_threshold(attempts, threshold, expected_result):

    start_time = datetime(2026, 11, 27, 10, 0, 0)

    timestamps = []

    for i in range(attempts):
        timestamps.append(start_time + timedelta(seconds=i))

    failed_times_by_ip = {
        "192.168.1.77": timestamps
    }

    result = detect_brute_force(
        failed_times_by_ip, threshold, timedelta(minutes=5)
    )

    assert result == expected_result

# V1.5D-B: Verify detection time-window boundaries
@pytest.mark.parametrize("offsets, window_minutes, expected_result", [
    ([0, 150, 299], 5, ["192.168.1.77"]),
    ([0, 150, 300], 5, ["192.168.1.77"]),
    ([0, 150, 301], 5, []),
    ([0, 150, 301], 6, ["192.168.1.77"])
])
def test_detection_window(offsets, window_minutes, expected_result):

    start_time = datetime(2026, 11, 27, 10, 0, 0)

    timestamps = []

    for offset in offsets:
        timestamps.append(
            start_time + timedelta(seconds=offset)
        )

    failed_times_by_ip = {
        "192.168.1.77": timestamps
    }

    result = detect_brute_force(
        failed_times_by_ip, 3,
        timedelta(minutes=window_minutes)
    )

    assert result == expected_result

# V1.5D-C: Verify chronological sorting and sliding windows
@pytest.mark.parametrize("offsets, expected_result", [
    ([240, 0, 120], ["192.168.1.77"]),
    ([720, 360, 0], []),
    ([0, 600, 720, 840], ["192.168.1.77"]),
    ([0, 360, 720, 1080], [])
])
def test_detection_sliding_window(offsets, expected_result):

    start_time = datetime(2026, 11, 27, 10, 0, 0)

    timestamps = []

    for offset in offsets:
        timestamps.append(
            start_time + timedelta(seconds=offset)
        )

    failed_times_by_ip = {
        "192.168.1.77": timestamps
    }

    result = detect_brute_force(
        failed_times_by_ip, 3, timedelta(minutes=5)
    )

    assert result == expected_result

# V1.5D-D1: Verify independent IP classification
def test_multiple_suspicious_ips():

    t = datetime(2026, 11, 27, 10, 0, 0)

    failed_times_by_ip = {
        "192.168.1.77": [t, t, t, t],
        "10.0.0.15": [t, t],
        "172.16.0.20": [t, t, t]
    }

    result = detect_brute_force(
        failed_times_by_ip, 3, timedelta(minutes=5)
    )

    assert result == ["192.168.1.77", "172.16.0.20"]

# V1.5D-D2: Prevent aggregation across separate IPs
def test_independent_ip_thresholds():

    t = datetime(2026, 11, 27, 10, 0, 0)

    failed_times_by_ip = {
        "192.168.1.77": [t],
        "10.0.0.15": [t],
        "172.16.0.20": [t]
    }

    result = detect_brute_force(
        failed_times_by_ip, 3, timedelta(minutes=5)
    )

    assert result == []

# V1.5D-D3: Prevent duplicate detections
def test_duplicate_alert_prevention():

    t = datetime(2026, 11, 27, 10, 0, 0)

    timestamps = []

    for i in range(6):
        timestamps.append(t + timedelta(seconds=i))

    failed_times_by_ip = {
        "192.168.1.77": timestamps
    }

    result = detect_brute_force(
        failed_times_by_ip, 3, timedelta(minutes=5)
    )

    assert result == ["192.168.1.77"]
