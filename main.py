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
    return 0


if __name__ == "__main__":
    sys.exit(main())
