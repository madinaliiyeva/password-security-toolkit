import math

import pytest

from src.cracktime import (
    attack_scenarios,
    estimate_crack_times,
    humanize_seconds,
    seconds_to_crack,
)


class TestSecondsToCrack:
    def test_basic_math(self):
        # entropy=20, 1 gps → average guesses = 2^19 = 524288 seconds
        assert seconds_to_crack(20, 1) == pytest.approx(2 ** 19)

    def test_zero_entropy(self):
        assert seconds_to_crack(0, 1) == pytest.approx(0.5)

    def test_negative_entropy_is_zero(self):
        assert seconds_to_crack(-5, 1000) == 0.0

    def test_nan_entropy_is_zero(self):
        assert seconds_to_crack(float("nan"), 1000) == 0.0

    def test_zero_gps_is_infinite(self):
        assert seconds_to_crack(50, 0) == float("inf")

    def test_negative_gps_is_infinite(self):
        assert seconds_to_crack(50, -1) == float("inf")

    def test_very_high_entropy_returns_infinity(self):
        # Avoids overflow at extreme entropy values.
        assert seconds_to_crack(10_000, 1) == float("inf")

    def test_higher_entropy_takes_longer(self):
        assert seconds_to_crack(80, 1000) > seconds_to_crack(40, 1000)

    def test_higher_gps_is_faster(self):
        assert seconds_to_crack(60, 1_000_000) < seconds_to_crack(60, 10)


class TestHumanizeSeconds:
    def test_sub_second_is_instantly(self):
        assert humanize_seconds(0) == "instantly"
        assert humanize_seconds(0.5) == "instantly"

    def test_infinity_is_forever(self):
        assert humanize_seconds(float("inf")) == "effectively forever"

    def test_nan_is_forever(self):
        assert humanize_seconds(float("nan")) == "effectively forever"

    def test_seconds(self):
        assert "second" in humanize_seconds(5)

    def test_minutes(self):
        assert "minute" in humanize_seconds(120)

    def test_hours(self):
        assert "hour" in humanize_seconds(3 * 3600)

    def test_days(self):
        assert "day" in humanize_seconds(5 * 86400)

    def test_years(self):
        assert "year" in humanize_seconds(3 * 365.25 * 86400)

    def test_centuries(self):
        # 500 years → centuries
        assert "centur" in humanize_seconds(500 * 365.25 * 86400)

    def test_singular_one_second(self):
        assert humanize_seconds(1) == "1 second"

    def test_plural_two_seconds(self):
        assert humanize_seconds(2) == "2 seconds"


class TestEstimateCrackTimes:
    def test_returns_all_scenarios(self):
        result = estimate_crack_times(60)
        assert set(result.keys()) == set(attack_scenarios.keys())

    def test_all_values_are_strings(self):
        result = estimate_crack_times(60)
        assert all(isinstance(v, str) for v in result.values())

    def test_slower_attacker_takes_longer_or_equal(self):
        # For a moderate-entropy password, the throttled online attacker
        # should never finish faster than the offline fast-hash attacker.
        result = estimate_crack_times(50)
        # Both are humanized strings, so we re-derive via seconds_to_crack
        online = seconds_to_crack(50, attack_scenarios["online_throttled"])
        offline_fast = seconds_to_crack(50, attack_scenarios["offline_fast_hash"])
        assert online > offline_fast

    def test_zero_entropy_is_instant_for_fast_attackers(self):
        result = estimate_crack_times(0)
        # 0 entropy / 100B gps → way under 1s
        assert result["offline_fast_hash"] == "instantly"
        assert result["nation_state"] == "instantly"
