"""
HaveIBeenPwned k-anonymity lookup.

Only the first 5 hex chars of the SHA-1 hash are sent to the Pwned Passwords
API; the full hash and the password itself never leave this process.
"""

import hashlib
from typing import Optional

import requests

_API_URL = "https://api.pwnedpasswords.com/range/{prefix}"
_USER_AGENT = "password-security-toolkit"
_TIMEOUT_SECONDS = 5


def check_pwned(password: str) -> Optional[int]:
    """
    Returns how many times the password appears in known breaches.
    0 means it has not been seen; None means the lookup failed
    (network error, non-2xx response, etc.) and the caller should treat
    the result as unknown rather than safe.
    """
    if not password:
        return 0

    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]

    try:
        response = requests.get(
            _API_URL.format(prefix=prefix),
            headers={"User-Agent": _USER_AGENT},
            timeout=_TIMEOUT_SECONDS,
        )
        response.raise_for_status()
    except requests.RequestException:
        return None

    for line in response.text.splitlines():
        line_suffix, _, count = line.partition(":")
        if line_suffix == suffix:
            return int(count)
    return 0


if __name__ == "__main__":
    for pw in ["password", "Tr0ub4dor&3", "correct horse battery staple"]:
        count = check_pwned(pw)
        if count is None:
            print(f"{pw!r}: lookup failed")
        elif count == 0:
            print(f"{pw!r}: not found in known breaches")
        else:
            print(f"{pw!r}: seen {count:,} times in known breaches")
