import math
import string

import pytest

from src.analyzer import (
    calculate_entropy,
    get_character_pool_size,
    rate_strength,
    describe_charset,
)


class TestCharacterPoolSize:
    def test_empty_string_is_zero(self):
        assert get_character_pool_size("") == 0

    def test_lowercase_only(self):
        assert get_character_pool_size("abc") == 26

    def test_uppercase_only(self):
        assert get_character_pool_size("ABC") == 26

    def test_digits_only(self):
        assert get_character_pool_size("123") == 10

    def test_symbols_only(self):
        assert get_character_pool_size("!@#") == len(string.punctuation)

    def test_space_only(self):
        assert get_character_pool_size("   ") == 1

    def test_non_ascii_uses_other_bucket(self):
        # _OTHER_POOL_SIZE = 1024
        assert get_character_pool_size("é") == 1024

    def test_full_ascii_printable(self):
        # lowercase + uppercase + digits + symbols = 26+26+10+32 = 94
        assert get_character_pool_size("Aa1!") == 26 + 26 + 10 + len(string.punctuation)

    def test_mixed_with_space(self):
        # lowercase + space = 27
        assert get_character_pool_size("ab c") == 27


class TestCalculateEntropy:
    def test_empty_string_is_zero(self):
        assert calculate_entropy("") == 0.0

    def test_known_value_lowercase(self):
        # 'aaaa' → len=4, pool=26 → 4 * log2(26)
        assert calculate_entropy("aaaa") == pytest.approx(4 * math.log2(26))

    def test_known_value_digits(self):
        # '1234' → len=4, pool=10 → 4 * log2(10)
        assert calculate_entropy("1234") == pytest.approx(4 * math.log2(10))

    def test_scales_with_length(self):
        # Doubling length should double entropy for same charset.
        short = calculate_entropy("abcd")
        long = calculate_entropy("abcdabcd")
        assert long == pytest.approx(2 * short)

    def test_larger_pool_means_more_entropy(self):
        # Same length, larger pool → more entropy.
        assert calculate_entropy("Aa1!aaaa") > calculate_entropy("aaaaaaaa")


class TestRateStrength:
    @pytest.mark.parametrize(
        "entropy,expected",
        [
            (0, "Weak"),
            (40, "Weak"),
            (59.9, "Weak"),
            (60, "Fair"),
            (79.9, "Fair"),
            (80, "Strong"),
            (99.9, "Strong"),
            (100, "Very Strong"),
            (200, "Very Strong"),
        ],
    )
    def test_thresholds(self, entropy, expected):
        assert rate_strength(entropy) == expected


class TestDescribeCharset:
    def test_empty(self):
        assert describe_charset("") == "none"

    def test_single_class(self):
        assert describe_charset("abc") == "lowercase"

    def test_mixed_classes_listed(self):
        result = describe_charset("Aa1!")
        assert "lowercase" in result
        assert "uppercase" in result
        assert "digits" in result
        assert "symbols" in result
