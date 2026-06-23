"""CLI entrypoint for the password security toolkit."""

import argparse
import getpass
import sys

from src.analyzer import analyze


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="password-security-toolkit",
        description="Analyze a password's strength and estimate crack times.",
    )
    parser.parse_args()

    try:
        password = getpass.getpass("Enter password: ")
    except (KeyboardInterrupt, EOFError):
        print()
        return 1

    if not password:
        print("No password entered.", file=sys.stderr)
        return 1

    result = analyze(password)

    print(f"Length     : {result['length']}")
    print(f"Charset    : {result['charset']}")
    print(f"Pool size  : {result['pool_size']}")
    print(f"Entropy    : {result['entropy']} bits")
    print(f"Strength   : {result['strength']}")
    print("Crack times:")
    for scenario, time_str in result["crack_times"].items():
        print(f"  {scenario:22s}: {time_str}")

    breach_count = result.get("breach_count")
    if breach_count is None:
        print("Breach check: lookup failed (network error)")
    elif breach_count == 0:
        print("Breach check: not found in known breaches")
    else:
        print(f"Breach check: seen {breach_count:,} times in known breaches")
    return 0


if __name__ == "__main__":
    sys.exit(main())
