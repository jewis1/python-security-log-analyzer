import pytest

from datetime import timedelta
from analyzer import validate_config


# V1.5B-A: Verify that a valid configuration is accepted
def test_valid_config():

    result = validate_config(3, timedelta(minutes=5))

    assert result is None

# V1.5B-B/D: Validate invalid thresholds and exception messages
@pytest.mark.parametrize("threshold, expected_message", [
    (0, "Threshold must be greater than zero."),
    (-3, "Threshold must be greater than zero."),
    (3.5, "Threshold must be a positive integer."),
    (True, "Threshold must be a positive integer."),
    ("abc", "Threshold must be a positive integer.")
])
def test_invalid_threshold(threshold, expected_message):

    with pytest.raises(ValueError, match=expected_message):
        validate_config(threshold, timedelta(minutes=5))

# V1.5B-C/D: Validate invalid windows and exception messages
@pytest.mark.parametrize("window, expected_message", [
    (timedelta(minutes=0),
     "Detection time window must be greater than zero."),

    (timedelta(minutes=-5),
     "Detection time window must be greater than zero."),

    (5, "Detection window must be a timedelta object."),
    ("abc", "Detection window must be a timedelta object."),
    (None, "Detection window must be a timedelta object.")
])
def test_invalid_window(window, expected_message):

    with pytest.raises(ValueError, match=expected_message):
        validate_config(3, window)
