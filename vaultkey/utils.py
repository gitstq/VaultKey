"""
Utility functions for VaultKey.

Provides common helper functions used across modules including
charset definitions, pattern detection, and formatting utilities.
"""

import math
import re
import string
from typing import Dict, List, Optional, Set, Tuple


# Character set definitions
CHARSETS: Dict[str, str] = {
    "uppercase": string.ascii_uppercase,
    "lowercase": string.ascii_lowercase,
    "digits": string.digits,
    "symbols": "!@#$%^&*()-_=+[]{}|;:,.<>?/~`",
}

# Ambiguous characters that look similar
AMBIGUOUS_CHARS: Set[str] = {"0", "O", "o", "1", "l", "I", "|", "`", "'", '"'}

# Keyboard patterns (rows and common sequences)
KEYBOARD_PATTERNS: List[str] = [
    "qwertyuiop", "asdfghjkl", "zxcvbnm",
    "1234567890", "0987654321",
    "qwerty", "asdfgh", "zxcvbn",
    "!@#$%^&*()", "qazwsx", "edcrfv",
    "1qaz", "2wsx", "3edc", "4rfv", "5tgb",
    "qwert", "wert", "erty", "rtyu", "tyui",
]

# Common date patterns
DATE_PATTERNS: List[str] = [
    r"\d{4}-\d{2}-\d{2}",  # YYYY-MM-DD
    r"\d{2}/\d{2}/\d{4}",  # MM/DD/YYYY
    r"\d{2}-\d{2}-\d{4}",  # MM-DD-YYYY
    r"\d{8}",               # YYYYMMDD or DDMMYYYY
]

# Common sequential patterns
SEQUENTIAL_PATTERNS: List[str] = [
    "abcdefghijklmnopqrstuvwxyz",
    "zyxwvutsrqponmlkjihgfedcba",
    "01234567890",
    "09876543210",
    "abcdefghijklmnop",
    "ponmlkjihgfedcba",
]


def get_charset(config: Dict[str, bool]) -> str:
    """Build a character set string from a configuration dictionary.

    Args:
        config: Dictionary with boolean keys for each charset type.
                Supported keys: uppercase, lowercase, digits, symbols.

    Returns:
        A concatenated string of all enabled character sets.

    Raises:
        ValueError: If no character sets are enabled.
    """
    charset = ""
    if config.get("uppercase", True):
        charset += CHARSETS["uppercase"]
    if config.get("lowercase", True):
        charset += CHARSETS["lowercase"]
    if config.get("digits", True):
        charset += CHARSETS["digits"]
    if config.get("symbols", True):
        charset += CHARSETS["symbols"]

    if not charset:
        raise ValueError("At least one character set must be enabled.")
    return charset


def filter_ambiguous(charset: str) -> str:
    """Remove ambiguous characters from a character set.

    Args:
        charset: The character set to filter.

    Returns:
        The filtered character set with ambiguous characters removed.
    """
    return "".join(c for c in charset if c not in AMBIGUOUS_CHARS)


def detect_sequential(password: str) -> List[Tuple[int, int, str]]:
    """Detect sequential character patterns in a password.

    Args:
        password: The password to check.

    Returns:
        A list of tuples (start_index, length, matched_pattern) for each
        sequential pattern found.
    """
    results: List[Tuple[int, int, str]] = []
    lower = password.lower()

    for pattern in SEQUENTIAL_PATTERNS:
        pattern_len = len(pattern)
        for i in range(len(lower)):
            for length in range(min(4, pattern_len), pattern_len + 1):
                if i + length > len(lower):
                    break
                segment = lower[i:i + length]
                if segment in pattern:
                    results.append((i, length, segment))
                    break  # Only report the longest match at each position

    return results


def detect_keyboard_pattern(password: str) -> List[Tuple[int, int, str]]:
    """Detect keyboard walking patterns in a password.

    Args:
        password: The password to check.

    Returns:
        A list of tuples (start_index, length, matched_pattern) for each
        keyboard pattern found.
    """
    results: List[Tuple[int, int, str]] = []
    lower = password.lower()

    for pattern in KEYBOARD_PATTERNS:
        for i in range(len(lower)):
            for length in range(4, len(pattern) + 1):
                if i + length > len(lower):
                    break
                segment = lower[i:i + length]
                if segment in pattern:
                    results.append((i, length, segment))
                    break

    return results


def detect_repeated_chars(password: str) -> List[Tuple[int, int, str]]:
    """Detect repeated character sequences in a password.

    Args:
        password: The password to check.

    Returns:
        A list of tuples (start_index, length, repeated_char) for each
        repeated character sequence found.
    """
    results: List[Tuple[int, int, str]] = []
    if not password:
        return results

    current_char = password[0]
    start = 0
    count = 1

    for i in range(1, len(password)):
        if password[i] == current_char:
            count += 1
        else:
            if count >= 3:
                results.append((start, count, current_char))
            current_char = password[i]
            start = i
            count = 1

    if count >= 3:
        results.append((start, count, current_char))

    return results


def detect_date_pattern(password: str) -> List[str]:
    """Detect date-like patterns in a password.

    Args:
        password: The password to check.

    Returns:
        A list of matched date strings found in the password.
    """
    results: List[str] = []
    for pattern in DATE_PATTERNS:
        matches = re.findall(pattern, password)
        results.extend(matches)
    return results


def calculate_charset_size(password: str) -> int:
    """Estimate the effective character set size based on character types present.

    Args:
        password: The password to analyze.

    Returns:
        The estimated character pool size.
    """
    size = 0
    if any(c.isupper() for c in password):
        size += 26
    if any(c.islower() for c in password):
        size += 26
    if any(c.isdigit() for c in password):
        size += 10
    if any(c in CHARSETS["symbols"] for c in password):
        size += len(CHARSETS["symbols"])
    return max(size, 1)


def format_time(seconds: float) -> str:
    """Format a number of seconds into a human-readable time string.

    Args:
        seconds: The number of seconds to format.

    Returns:
        A human-readable time string (e.g., '3 days', '2.5 hours').
    """
    if seconds < 0:
        return "instant"
    if seconds < 1:
        return "less than 1 second"

    intervals = [
        (365.25 * 24 * 3600, "year"),
        (30 * 24 * 3600, "month"),
        (7 * 24 * 3600, "week"),
        (24 * 3600, "day"),
        (3600, "hour"),
        (60, "minute"),
        (1, "second"),
    ]

    for interval_length, interval_name in intervals:
        value = seconds / interval_length
        if value >= 1:
            if value == 1:
                return f"1 {interval_name}"
            rounded = round(value, 1)
            if rounded == int(rounded):
                return f"{int(rounded)} {interval_name}s"
            return f"{rounded} {interval_name}s"

    return f"{seconds:.2f} seconds"


def crack_time_estimate(entropy: float, guesses_per_second: float = 1e10) -> float:
    """Estimate the time to crack a password given its entropy.

    Args:
        entropy: The password entropy in bits.
        guesses_per_second: Estimated guessing rate (default: 10 billion/sec).

    Returns:
        Estimated seconds to crack the password.
    """
    if entropy <= 0:
        return 0.0
    total_combinations = 2 ** entropy
    # On average, half the keyspace needs to be searched
    return (total_combinations / 2) / guesses_per_second


def get_score_color(score: int) -> str:
    """Get a Rich-compatible color name based on a score (0-100).

    Args:
        score: The score value (0-100).

    Returns:
        A color name string for Rich console output.
    """
    if score < 20:
        return "red"
    elif score < 40:
        return "bright_red"
    elif score < 60:
        return "yellow"
    elif score < 80:
        return "green"
    else:
        return "bright_green"


def get_strength_label(score: int) -> str:
    """Get a human-readable strength label based on score.

    Args:
        score: The score value (0-100).

    Returns:
        A strength label string.
    """
    if score < 20:
        return "Very Weak"
    elif score < 40:
        return "Weak"
    elif score < 60:
        return "Moderate"
    elif score < 80:
        return "Strong"
    else:
        return "Very Strong"


def mask_password(password: str, show_first: int = 2, show_last: int = 2) -> str:
    """Mask a password for safe display, showing only a few characters.

    Args:
        password: The password to mask.
        show_first: Number of characters to show at the beginning.
        show_last: Number of characters to show at the end.

    Returns:
        The masked password string.
    """
    if len(password) <= show_first + show_last:
        return "*" * len(password)
    return (
        password[:show_first]
        + "*" * (len(password) - show_first - show_last)
        + password[-show_last:]
    )
