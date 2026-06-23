"""
Crack-Time Estimator:
Estimates how long it would take an attacker to crack a password, given its entropy in bits and an assumed attacker capability
(guesses per second).

"""
import math

attack_scenarios = {
    "online_throttled":     10,                    # Login form with rate limiting
    "online_unthrottled":   1_000,                 # No rate limit, just network speed
    "offline_slow_hash":    100,                   # bcrypt cost ~10 / Argon2id on a single GPU
    "offline_fast_hash":    100_000_000_000,       # MD5 / SHA-1 on a GPU rig
    "nation_state":         1_000_000_000_000_000, # Custom ASICs, distributed (~PH/s)
}

def seconds_to_crack(entropy: float, guesses_per_second: float) -> float:
    """
    Returns the average time (in seconds) to crack a password of the given entropy at the given attack rate.
    """
    if not math.isfinite(entropy) or entropy < 0:
        return 0.0
    if guesses_per_second <= 0:
        return float("inf")
    # Compute in log2 space first so very high entropies don't overflow the 2**x step.
    log2_seconds = (entropy - 1) - math.log2(guesses_per_second)
    if log2_seconds > 1023:
        return float("inf")
    return 2 ** log2_seconds

def humanize_seconds(seconds: float) -> str:
    """
    Converts a duration in seconds into a human-readable string,
    e.g., '3 hours', '2.5 years', 'instantly', or 'centuries'.
    """
    if not math.isfinite(seconds):
        return "effectively forever"
    if seconds < 1:
        return "instantly"

    minute = 60
    hour = 60 * minute
    day = 24 * hour
    year = 365.25 * day
    century = 100 * year

    # (size, singular, plural, format, cap-before-rolling-to-next-unit)
    units = [
        (1,       "second",  "seconds",   "{:.0f}", 60),
        (minute,  "minute",  "minutes",   "{:.0f}", 60),
        (hour,    "hour",    "hours",     "{:.0f}", 24),
        (day,     "day",     "days",      "{:.0f}", 365),
        (year,    "year",    "years",     "{:.1f}", 100),
        (century, "century", "centuries", "{:.0f}", 10_000),
    ]

    for size, singular, plural, fmt, cap in units:
        rendered = fmt.format(seconds / size)
        rounded = float(rendered)
        if rounded < cap:
            label = singular if rounded == 1 else plural
            return f"{rendered} {label}"
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
