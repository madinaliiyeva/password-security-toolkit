"""
Crack-Time Estimator:
Estimates how long it would take an attacker to crack a password, given its entropy in bits and an assumed attacker capability
(guesses per second).

"""
attack_scenarios = {
    "online_throttled": 10,                       # Login form with rate limiting
    "online_unthrottled": 1_000,                  # No rate limit, just network speed
    "offline_slow_hash": 10_000,                  # bcrypt, Argon2, scrypt
    "offline_fast_hash":   100_000_000_000,       # MD5, SHA-1 on GPU rig
    "nation_state":        1_000_000_000_000,     # Custom ASICs, distributed
}

def seconds_to_crack(entropy: float, guesses_per_second: float) -> float:
    """
    Returns the average time (in seconds) to crack a password of the given entropy at the given attack rate.
    """
    if guesses_per_second <= 0:
        return float("inf")
    average_guesses = 2 ** (entropy - 1)
    return average_guesses / guesses_per_second

def humanize_seconds(seconds: float) -> str:
    """
    Converts a duration in seconds into a human-readable string, 
    e.g., '3 hours', '2.5 years', 'instantly', or 'centuries'.
    """
    if seconds < 1:
        return "instantly"
    
    minute = 60
    hour = 60 * minute 
    day = 24 * hour
    year = 365.25 * day
    century = 100 * year

    if seconds < minute:
        return f"{seconds:.0f} seconds"
    if seconds < hour:
        return f"{seconds / minute:.0f} minutes"
    if seconds < day:
        return f"{seconds / hour:.0f} hours"
    if seconds < year:
        return f"{seconds / day:.0f} days"
    if seconds < century:
        return f"{seconds / year:.1f} years"
    if seconds < 1_000_000 * year:
        return f"{seconds / century:.0f} centuries"
    return "effectively forever"


def estimate_crack_times(entropy: float) -> dict:
    """
    For a given entropy, returns a dict mapping each attack scenario to a human-readable crack time estimate.
    """
    return {
        scenario: humanize_seconds(seconds_to_crack(entropy, gps))
        for scenario, gps in attack_scenarios.items()
    }

if __name__ == "__main__":
    test_entropies = [20, 40, 60, 80, 100]
    for h in test_entropies:
        print(f"\nEntropy: {h} bits")
        for scenario, time_str in estimate_crack_times(h).items():
            print(f"  {scenario:25s}: {time_str}")
