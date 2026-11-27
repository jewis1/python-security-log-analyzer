from datetime import timedelta
from analyzer import detect_brute_force


# V1.5A-C: Verify detection behavior with an empty dataset
def test_empty_detection():

    result = detect_brute_force({}, 3, timedelta(minutes=5))

    assert result == []
