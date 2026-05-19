"""
Password breach checker module for VaultKey.

Implements a local SHA-1 hash prefix comparison model inspired by the
k-anonymity approach used by Have I Been Pwned. Uses a built-in database
of known breached password hashes for demonstration purposes.

Note: This is a local simulation and does not make any external API calls.
"""

import hashlib
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from .utils import mask_password


# Built-in breached password SHA-1 hash database (prefix: full_hash)
# Contains SHA-1 hashes of common breached passwords for demonstration.
# Format: {first_5_chars_of_sha1: {remaining_35_chars: count}}
_BREACH_DB: Dict[str, Dict[str, int]] = {}

# Common breached passwords and their approximate breach counts
_SAMPLE_BREACHED_PASSWORDS: List[Tuple[str, int]] = [
    ("123456", 23456789),
    ("password", 19876543),
    ("12345678", 12345678),
    ("qwerty", 11234567),
    ("123456789", 9876543),
    ("12345", 8765432),
    ("1234", 7654321),
    ("111111", 6543210),
    ("1234567", 5432109),
    ("dragon", 4321098),
    ("123123", 3210987),
    ("baseball", 2109876),
    ("abc123", 1987654),
    ("football", 1876543),
    ("monkey", 1765432),
    ("letmein", 1654321),
    ("shadow", 1543210),
    ("master", 1432109),
    ("666666", 1321098),
    ("qwertyuiop", 1210987),
    ("123321", 1109876),
    ("mustang", 1098765),
    ("1234567890", 987654),
    ("michael", 876543),
    ("654321", 765432),
    ("superman", 654321),
    ("1qaz2wsx", 543210),
    ("7777777", 432109),
    ("121212", 321098),
    ("000000", 210987),
    ("qazwsx", 198765),
    ("123qwe", 187654),
    ("killer", 176543),
    ("trustno1", 165432),
    ("jordan", 154321),
    ("jennifer", 143210),
    ("zxcvbnm", 132109),
    ("asdfgh", 121098),
    ("hunter", 110987),
    ("buster", 109876),
    ("soccer", 98765),
    ("harley", 87654),
    ("batman", 76543),
    ("andrew", 65432),
    ("tigger", 54321),
    ("sunshine", 43210),
    ("iloveyou", 39876),
    ("2000", 38765),
    ("charlie", 37654),
    ("robert", 36543),
    ("thomas", 35432),
    ("hockey", 34321),
    ("ranger", 33210),
    ("daniel", 32109),
    ("starwars", 31098),
    ("klaster", 30087),
    ("112233", 29076),
    ("george", 28065),
    ("computer", 27054),
    ("michelle", 26043),
    ("jessica", 25032),
    ("pepper", 24021),
    ("1111", 23010),
    ("zxcvbn", 21999),
    ("555555", 20988),
    ("11111111", 19977),
    ("131313", 18966),
    ("freedom", 17955),
    ("777777", 16944),
    ("pass", 15933),
    ("maggie", 14922),
    ("159753", 13911),
    ("aaaaaa", 12900),
    ("ginger", 11899),
    ("princess", 10888),
    ("joshua", 9877),
    ("cheese", 8866),
    ("amanda", 7755),
    ("summer", 6644),
    ("love", 5533),
    ("ashley", 4422),
    ("nicole", 3311),
    ("chelsea", 2200),
    ("biteme", 1199),
    ("matthew", 1088),
    ("access", 977),
    ("yankees", 866),
    ("987654321", 755),
    ("dallas", 644),
    ("austin", 533),
    ("thunder", 422),
    ("taylor", 311),
    ("matrix", 200),
    ("admin", 15000000),
    ("admin123", 5000000),
    ("root", 8000000),
    ("root123", 3000000),
    ("test", 7000000),
    ("test123", 2500000),
    ("guest", 4000000),
    ("default", 3500000),
    ("changeme", 1800000),
    ("welcome", 6000000),
    ("welcome1", 2000000),
    ("password1", 9000000),
    ("password123", 4500000),
    ("P@ssw0rd", 3200000),
    ("P@ssword1", 1500000),
    ("letmein1", 1200000),
    ("qwerty123", 1800000),
    ("Abc123", 2100000),
    ("Admin123", 1600000),
    ("Password1", 2800000),
    ("Qwerty123", 1100000),
]


def _build_breach_db() -> None:
    """Build the in-memory breach database from sample passwords.

    Computes SHA-1 hashes and stores them in a k-anonymity compatible
    format (first 5 chars as prefix, rest as suffix).
    """
    if _BREACH_DB:
        return

    for password, count in _SAMPLE_BREACHED_PASSWORDS:
        sha1_hash = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
        prefix = sha1_hash[:5]
        suffix = sha1_hash[5:]

        if prefix not in _BREACH_DB:
            _BREACH_DB[prefix] = {}
        _BREACH_DB[prefix][suffix] = count


@dataclass
class BreachCheckResult:
    """Result of a single password breach check.

    Attributes:
        password: The checked password (masked).
        sha1_prefix: The first 5 characters of the SHA-1 hash.
        found: Whether the password was found in the breach database.
        count: Number of occurrences if found, 0 otherwise.
        message: Human-readable result message.
    """

    password: str
    sha1_prefix: str
    found: bool
    count: int
    message: str

    def to_dict(self) -> Dict:
        """Convert the result to a dictionary.

        Returns:
            A dictionary containing all breach check fields.
        """
        return {
            "password_masked": mask_password(self.password),
            "sha1_prefix": self.sha1_prefix,
            "found": self.found,
            "occurrences": self.count,
            "message": self.message,
        }


class BreachChecker:
    """Checks passwords against a local breach database using SHA-1 hash prefixes.

    Uses the k-anonymity model: only the first 5 characters of the SHA-1 hash
    are used for lookup, ensuring the full password is never exposed.

    Attributes:
        db: The in-memory breach database.
    """

    def __init__(self) -> None:
        """Initialize the BreachChecker and build the database."""
        _build_breach_db()
        self.db = _BREACH_DB

    def _sha1_prefix(self, password: str) -> Tuple[str, str]:
        """Compute the SHA-1 hash prefix and suffix of a password.

        Args:
            password: The password to hash.

        Returns:
            A tuple of (prefix, suffix) where prefix is the first 5 hex chars
            and suffix is the remaining 35 hex chars.
        """
        sha1_hash = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
        return sha1_hash[:5], sha1_hash[5:]

    def check(self, password: str) -> BreachCheckResult:
        """Check if a password has been found in known breaches.

        Uses SHA-1 hash prefix matching (k-anonymity model). Only the first
        5 characters of the hash are compared, so the full password hash
        is never transmitted or fully exposed.

        Args:
            password: The password to check.

        Returns:
            A BreachCheckResult with the check outcome.
        """
        if not password:
            return BreachCheckResult(
                password="",
                sha1_prefix="",
                found=False,
                count=0,
                message="Empty password provided.",
            )

        prefix, suffix = self._sha1_prefix(password)

        if prefix in self.db and suffix in self.db[prefix]:
            count = self.db[prefix][suffix]
            return BreachCheckResult(
                password=password,
                sha1_prefix=prefix,
                found=True,
                count=count,
                message=f"WARNING: Password found in breach database! "
                        f"Occurrences: {count:,}",
            )
        else:
            return BreachCheckResult(
                password=password,
                sha1_prefix=prefix,
                found=False,
                count=0,
                message="Password was NOT found in the breach database.",
            )

    def check_batch(self, passwords: List[str]) -> List[BreachCheckResult]:
        """Check a batch of passwords against the breach database.

        Args:
            passwords: A list of password strings to check.

        Returns:
            A list of BreachCheckResult objects, one per password.
        """
        return [self.check(p) for p in passwords]

    def check_file(self, filepath: str) -> List[BreachCheckResult]:
        """Check passwords from a file against the breach database.

        Args:
            filepath: Path to the file containing passwords (one per line).

        Returns:
            A list of BreachCheckResult objects.

        Raises:
            FileNotFoundError: If the specified file does not exist.
        """
        with open(filepath, "r", encoding="utf-8") as f:
            passwords = [line.strip() for line in f if line.strip()]
        return self.check_batch(passwords)

    @property
    def database_size(self) -> int:
        """Return the total number of entries in the breach database.

        Returns:
            The number of password hashes in the database.
        """
        return sum(len(suffixes) for suffixes in self.db.values())


def display_breach_result(
    result: BreachCheckResult, console: Optional[Console] = None
) -> None:
    """Display a breach check result in a formatted Rich panel.

    Args:
        result: The BreachCheckResult to display.
        console: Optional Rich Console instance. Creates a new one if not provided.
    """
    if console is None:
        console = Console()

    if result.found:
        color = "red"
        title = "[bold red]BREACH DETECTED[/bold red]"
    else:
        color = "green"
        title = "[bold green]No Breach Found[/bold green]"

    table = Table(show_header=False, expand=True, box=None, padding=(0, 1))
    table.add_column("Key", style="bold", width=18)
    table.add_column("Value")

    table.add_row("Password", f"[white on black] {mask_password(result.password)} [/]")
    table.add_row("SHA-1 Prefix", result.sha1_prefix)

    if result.found:
        table.add_row("Occurrences", f"[bold red]{result.count:,}[/bold red]")
        table.add_row(
            "Risk Level",
            "[bold red]HIGH[/bold red] - Password is publicly known and should be changed immediately.",
        )
    else:
        table.add_row("Occurrences", "[green]0[/green]")
        table.add_row(
            "Risk Level",
            "[green]LOW[/green] - Password was not found in the breach database.",
        )

    panel = Panel(
        table,
        title=title,
        subtitle="[dim]Note: This uses a local demonstration database. "
                  "For production use, integrate with a real breach API.[/dim]",
        border_style=color,
        expand=True,
    )

    console.print(panel)


def display_batch_breach_summary(
    results: List[BreachCheckResult], console: Optional[Console] = None
) -> None:
    """Display a summary table for batch breach check results.

    Args:
        results: A list of BreachCheckResult objects.
        console: Optional Rich Console instance. Creates a new one if not provided.
    """
    if console is None:
        console = Console()

    table = Table(
        title="Batch Breach Check Summary",
        show_header=True,
        header_style="bold cyan",
        expand=True,
    )
    table.add_column("#", style="dim", width=4)
    table.add_column("Password", width=20)
    table.add_column("SHA-1 Prefix", width=12)
    table.add_column("Status", width=10, justify="center")
    table.add_column("Occurrences", width=14, justify="right")

    found_count = sum(1 for r in results if r.found)

    for i, result in enumerate(results, 1):
        if result.found:
            table.add_row(
                str(i),
                mask_password(result.password),
                result.sha1_prefix,
                "[red]BREACHED[/red]",
                f"[red]{result.count:,}[/red]",
            )
        else:
            table.add_row(
                str(i),
                mask_password(result.password),
                result.sha1_prefix,
                "[green]SAFE[/green]",
                "[green]0[/green]",
            )

    console.print(table)
    console.print(
        f"\n  [bold]Summary:[/bold] "
        f"{len(results)} checked, "
        f"[red]{found_count} breached[/red], "
        f"[green]{len(results) - found_count} safe[/green]"
    )
