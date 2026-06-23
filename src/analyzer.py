"""
Password Strength Analyzer:
Analyzes a password and reports its length, character composition,
entropy in bits, and an overall strength rating.
"""

import math
import string
from .cracktime import estimate_crack_times
from .hibp import check_pwned

# Conservative pool size for non-ASCII / unrecognized characters. An attacker
# targeting unicode would draw from a much larger space; we cap at a reasonable
# common-codepoint count to avoid wildly over-rewarding obscure characters.
_OTHER_POOL_SIZE = 1024
_PUNCTUATION_SET = set(string.punctuation)


def _classify(password: str) -> dict:
    """Single pass over the password identifying which character classes are present."""
    classes = {
        "lowercase": False, "uppercase": False, "digits": False,
        "symbols": False, "space": False, "other": False,
    }
    for c in password:
        if c.isascii() and c.islower():
            classes["lowercase"] = True
        elif c.isascii() and c.isupper():
            classes["uppercase"] = True
        elif c.isascii() and c.isdigit():
            classes["digits"] = True
        elif c in _PUNCTUATION_SET:
            classes["symbols"] = True
        elif c == " ":
            classes["space"] = True
        else:
            classes["other"] = True
    return classes


def get_character_pool_size(password: str) -> int:
    """
    Determines the size of the character pool used in the password.
    For example, if a password contains lowercase letters and digits, the pool size is 26 + 10 = 36.
    """
    classes = _classify(password)
    pool = 0
    if classes["lowercase"]:
        pool += 26
    if classes["uppercase"]:
        pool += 26
    if classes["digits"]:
        pool += 10
    if classes["symbols"]:
        pool += len(string.punctuation)
    if classes["space"]:
        pool += 1
    if classes["other"]:
        pool += _OTHER_POOL_SIZE
    return pool


def calculate_entropy(password: str) -> float:
    """
    Calculates the entropy of a password in bits using H = L * log2(R),
    where L is the length and R is the character pool size.

    NOTE: This assumes characters are chosen uniformly at random from the pool.
    It does not account for dictionary words, common substitutions, repeated
    patterns, or keyboard walks, so this is an UPPER BOUND on real strength.
    """
    if not password:
        return 0.0
    pool_size = get_character_pool_size(password)
    if pool_size == 0:
        return 0.0
    return len(password) * math.log2(pool_size)


def rate_strength(entropy: float) -> str:
    """
    Maps an entropy value (in bits) to a human-readable strength rating.
    Thresholds reflect modern offline-attack capabilities: <60 bits is breakable
    in hours by a GPU rig against fast hashes.
    """
    if entropy < 60:
        return "Weak"
    if entropy < 80:
        return "Fair"
    if entropy < 100:
        return "Strong"
    return "Very Strong"


def describe_charset(password: str) -> str:
    """
    Returns a human-readable description of the character types present in the password.
    """
    classes = _classify(password)
    present = [name for name, found in classes.items() if found]
    return ", ".join(present) if present else "none"


def analyze(password: str, check_breach: bool = True) -> dict:
    """
    Performs a full analysis of a password and returns the results as a dictionary.

    When check_breach is True, queries HaveIBeenPwned via k-anonymity and
    includes a "breach_count" key (int, or None if the lookup failed).
    """
    entropy = calculate_entropy(password)
    result = {
        "length": len(password),
        "charset": describe_charset(password),
        "pool_size": get_character_pool_size(password),
        "entropy": round(entropy, 1),
        "strength": rate_strength(entropy),
        "crack_times": estimate_crack_times(entropy),
    }
    if check_breach:
        result["breach_count"] = check_pwned(password)
    return result

if __name__ == "__main__":
    test_passwords = ["password", "P@ssw0rd", "Tr0ub4dor&3", "correct horse battery staple"]
    for pw in test_passwords:
        result = analyze(pw)
        print(f"\nPassword: {pw!r}")
        for key, value in result.items():
            print(f"  {key:10s}: {value}")
