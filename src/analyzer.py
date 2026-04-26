""" 
Password Strength Analyzer:
Analyzes a password and reports its length, character composition,
entropy in bits, and an overall strength rating.
"""

import math
import string 
from cracktime import estimate_crack_times 

def get_character_pool_size(password: str) -> int:
    """
    Determines the size of the character pool used in the password.
    For example, if a password contains lowercase letters and digits, the pool size is 26 + 10 = 36.
    """
    pool = 0
    if any(c in string.ascii_lowercase for c in password):
        pool += 26
    if any(c in string.ascii_uppercase for c in password):
        pool += 26
    if any(c in string.digits for c in password):
        pool += 10
    if any(c in string.punctuation for c in password):
        pool += len(string.punctuation)
    return pool


def calculate_entropy(password: str) -> float:
    """
    Calculates the entropy of a password in bits using the formula:
    H = L * log2(R)
    where L is the length and R is the character pool size.
    """
    pool_size = get_character_pool_size(password)
    if pool_size == 0:
        return 0.0
    return len(password) * math.log2(pool_size)


def rate_strength(entropy: float) -> str:
    """
    Maps an entropy value (in bits) to a human-readable strength rating.
    """
    if entropy < 40:
        return "Weak"
    elif entropy < 60:
        return "Fair"
    elif entropy < 80:
        return "Strong"
    else:
        return "Very Strong"
    
def describe_charset (password: str) -> str:
    """
    Returns a human-readable description of the character types present in the password.
    """
    types = []
    if any(c in string.ascii_lowercase for c in password):
        types.append("lowercase")
    if any(c in string.ascii_uppercase for c in password):
        types.append("uppercase")
    if any(c in string.digits for c in password):
        types.append("digits")
    if any(c in string.punctuation for c in password):
        types.append("symbols")
    return ", ".join(types) if types else "none"


def analyze(password: str) -> dict:
    """
    Performs a full analysis of a password and returns the results as a dictionary
    """
    entropy = calculate_entropy(password)
    return {
        "length": len(password),
        "charset": describe_charset(password),
        "pool_size": get_character_pool_size(password),
        "entropy": round(entropy, 1),
        "strength": rate_strength(entropy),
        "crack_times": estimate_crack_times(entropy),
    }

if __name__ == "__main__":
    test_passwords = ["password", "P@ssw0rd", "Tr0ub4dor&3", "correct horse battery staple"]
    for pw in test_passwords:
        result = analyze(pw)
        print(f"\nPassword: {pw!r}")
        for key, value in result.items():
            print(f"  {key:10s}: {value}")