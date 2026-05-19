"""
Password strength analysis module for VaultKey.

Analyzes password strength using multiple criteria including entropy
calculation, NIST SP 800-63B scoring, pattern detection, and common
password dictionary matching. Provides comprehensive analysis with
Rich-formatted output.
"""

import math
import re
from typing import Any, Dict, List, Optional, Tuple

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from .entropy import effective_entropy, shannon_entropy
from .utils import (
    CHARSETS,
    calculate_charset_size,
    crack_time_estimate,
    detect_date_pattern,
    detect_keyboard_pattern,
    detect_repeated_chars,
    detect_sequential,
    format_time,
    get_score_color,
    get_strength_label,
    mask_password,
)

# Common passwords list (top 200+ most common passwords)
COMMON_PASSWORDS: List[str] = [
    "123456", "password", "12345678", "qwerty", "123456789",
    "12345", "1234", "111111", "1234567", "dragon",
    "123123", "baseball", "abc123", "football", "monkey",
    "letmein", "shadow", "master", "666666", "qwertyuiop",
    "123321", "mustang", "1234567890", "michael", "654321",
    "superman", "1qaz2wsx", "7777777", "121212", "000000",
    "qazwsx", "123qwe", "killer", "trustno1", "jordan",
    "jennifer", "zxcvbnm", "asdfgh", "hunter", "buster",
    "soccer", "harley", "batman", "andrew", "tigger",
    "sunshine", "iloveyou", "2000", "charlie", "robert",
    "thomas", "hockey", "ranger", "daniel", "starwars",
    "klaster", "112233", "george", "computer", "michelle",
    "jessica", "pepper", "1111", "zxcvbn", "555555",
    "11111111", "131313", "freedom", "777777", "pass",
    "maggie", "159753", "aaaaaa", "ginger", "princess",
    "joshua", "cheese", "amanda", "summer", "love",
    "ashley", "nicole", "chelsea", "biteme", "matthew",
    "access", "yankees", "987654321", "dallas", "austin",
    "thunder", "taylor", "matrix", "mobilemail", "mom",
    "monitor", "monitoring", "montana", "moon", "moscow",
    "abcdef", "abcd1234", "andrea", "anthony", "apollo",
    "apple", "arsenal", "asdf1234", "asdfghjkl", "asdfghjk",
    "azerty", "backyard", "banana", "barney", "baseball1",
    "batman1", "bear", "bigdog", "black", "blackcat",
    "blowjob", "bond007", "bonnie", "brandon", "braves",
    "brazil", "broncos", "butter", "calvin", "camaro",
    "cameron", "carolina", "carolina1", "cat", "charles",
    "cheese1", "chicken", "chris", "cocacola", "coffee",
    "college", "compaq", "computer1", "cookie", "corvette",
    "creative", "crystal", "cumming", "dakota", "dallas1",
    "daniel1", "danielle", "debbie", "dennis", "diablo",
    "dinosaur", "doctor", "dog", "dolphin", "donald",
    "dragon1", "dreamweaver", "dustin", "eagles", "edward",
    "einstein", "elizabeth", "emerica", "enter", "falcon",
    "ferrari", "fire", "fish", "florida", "flower",
    "football1", "forever", "frank", "fucking", "gandalf",
    "gateway", "george1", "gfhjkm", "golfer", "gordon",
    "gregory", "guitar", "hammer", "hannah", "happy",
    "hardcore", "hello", "help", "henry", "homer",
    "hotdog", "hottie", "hunter1", "hunter2", "iceman",
    "ihateyou", "iloveu", "internet", "jackass", "james",
    "january", "jessica1", "johnny", "johnson", "joseph",
    "junior", "justin", "killer1", "king", "knight",
    "lakers", "lauren", "learn", "legend", "letmein1",
    "liverpool", "login", "lol", "lucky", "madison",
    "maggie1", "magic", "malcolm", "manager", "marina",
    "marino", "mark", "martin", "marvin", "mary",
    "maximus", "melissa", "member", "mercedes", "michael1",
    "michael2", "mickey", "midnight", "mike", "miller",
    "minime", "mississippi", "mistress", "monica", "money",
    "monster", "morgan", "murphy", "mustang1", "nascar",
    "nathan", "naughty", "navy", "newyork", "nicholas",
    "nick", "nirvana", "nothing", "nurse", "nyjets",
    "ocean", "office", "oliver", "orange", "packers",
    "panther", "panties", "parker", "partner", "passw0rd",
    "passw0rd1", "patrick", "peanut", "peter", "philippines",
    "phoenix", "player", "please", "pookie", "pookie1",
    "porsche", "power", "prince1", "princess1", "private",
    "purple", "pussies", "pussy", "qwer1234", "qwerty12",
    "rabbit", "rachel", "racing", "raiders", "rainbow1",
    "ranger1", "rangers", "rebecca", "redsox", "redskins",
    "redwings", "richard", "ripper", "robert1", "robin",
    "rocket", "rosebud", "runner", "russia", "samantha",
    "sammy", "sandra", "samsung", "scooby", "scotty",
    "secret", "security", "semperfi", "sexy", "shadow1",
    "shanghai", "shannon", "shaved", "sheep", "sierra",
    "simple", "single", "skittles", "slayer", "smokey",
    "snowball", "soccer1", "sophie", "spanky", "sparky",
    "spider", "squirt", "star", "starwars1", "steelers",
    "steven", "stupid", "success", "suck", "sucker",
    "summer1", "sunshine1", "super", "superman1", "surfer",
    "swimming", "taylor1", "tennis", "teresa", "texas",
    "thunder1", "timothy", "tits", "tigger1", "tiffany",
    "tigers", "tommy", "topgun", "toyota", "travis",
    "tribal", "truck", "trustme", "tucker", "turtle",
    "united", "vanessa", "viking", "voodoo", "walker",
    "walter", "warrior", "welcome", "whatever", "william",
    "willie", "winston", "winter", "wizard", "wolves",
    "xavier", "xxxxxx", "yamaha", "yankees1", "yellow",
    "zxcvbn1", "zzzzzz", "1q2w3e4r", "1q2w3e", "password1",
    "password123", "qwerty123", "letmein123", "admin", "admin123",
    "root", "root123", "toor", "changeme", "default",
    "guest", "info", "mysql", "postgres", "oracle",
    "test", "test123", "pass123", "temp", "welcome1",
    "P@ssw0rd", "P@ssword1", "Iloveyou", "Trustno1",
    "Abc123", "Admin123", "Password1", "Qwerty123",
]


class AnalysisResult:
    """Container for password analysis results.

    Attributes:
        password: The analyzed password (masked).
        score: Overall strength score (0-100).
        grade: Letter grade (A-F).
        strength: Strength label.
        entropy_bits: Effective entropy in bits.
        crack_time: Estimated crack time string.
        charset_size: Estimated character pool size.
        length: Password length.
        has_uppercase: Whether password contains uppercase letters.
        has_lowercase: Whether password contains lowercase letters.
        has_digits: Whether password contains digits.
        has_symbols: Whether password contains symbols.
        is_common: Whether password is in the common passwords list.
        sequential_found: List of sequential patterns found.
        keyboard_found: List of keyboard patterns found.
        repeated_found: List of repeated character sequences found.
        dates_found: List of date patterns found.
        details: Full analysis details dictionary.
    """

    def __init__(self, **kwargs: Any) -> None:
        """Initialize AnalysisResult with keyword arguments.

        Args:
            **kwargs: Analysis result fields.
        """
        self.password: str = kwargs.get("password", "")
        self.score: int = kwargs.get("score", 0)
        self.grade: str = kwargs.get("grade", "F")
        self.strength: str = kwargs.get("strength", "Unknown")
        self.entropy_bits: float = kwargs.get("entropy_bits", 0.0)
        self.crack_time: str = kwargs.get("crack_time", "")
        self.charset_size: int = kwargs.get("charset_size", 0)
        self.length: int = kwargs.get("length", 0)
        self.has_uppercase: bool = kwargs.get("has_uppercase", False)
        self.has_lowercase: bool = kwargs.get("has_lowercase", False)
        self.has_digits: bool = kwargs.get("has_digits", False)
        self.has_symbols: bool = kwargs.get("has_symbols", False)
        self.is_common: bool = kwargs.get("is_common", False)
        self.sequential_found: List[Tuple[int, int, str]] = kwargs.get(
            "sequential_found", []
        )
        self.keyboard_found: List[Tuple[int, int, str]] = kwargs.get(
            "keyboard_found", []
        )
        self.repeated_found: List[Tuple[int, int, str]] = kwargs.get(
            "repeated_found", []
        )
        self.dates_found: List[str] = kwargs.get("dates_found", [])
        self.details: Dict[str, Any] = kwargs.get("details", {})

    def to_dict(self) -> Dict[str, Any]:
        """Convert the analysis result to a dictionary.

        Returns:
            A dictionary containing all analysis fields.
        """
        return {
            "password_masked": mask_password(self.password),
            "length": self.length,
            "score": self.score,
            "grade": self.grade,
            "strength": self.strength,
            "entropy_bits": round(self.entropy_bits, 2),
            "crack_time": self.crack_time,
            "charset_size": self.charset_size,
            "character_types": {
                "uppercase": self.has_uppercase,
                "lowercase": self.has_lowercase,
                "digits": self.has_digits,
                "symbols": self.has_symbols,
            },
            "is_common_password": self.is_common,
            "patterns": {
                "sequential": len(self.sequential_found) > 0,
                "keyboard": len(self.keyboard_found) > 0,
                "repeated": len(self.repeated_found) > 0,
                "dates": len(self.dates_found) > 0,
            },
            "details": self.details,
        }


def analyze_password(password: str) -> AnalysisResult:
    """Perform a comprehensive strength analysis of a password.

    Evaluates the password against multiple criteria including length,
    character diversity, entropy, pattern detection, and common password
    matching. Returns a detailed analysis result with a score from 0-100.

    Args:
        password: The password string to analyze.

    Returns:
        An AnalysisResult containing all analysis metrics.
    """
    if not password:
        return AnalysisResult(
            password="",
            score=0,
            grade="F",
            strength="Empty",
            entropy_bits=0.0,
            crack_time="instant",
            charset_size=0,
            length=0,
        )

    # Basic character analysis
    has_upper = bool(re.search(r"[A-Z]", password))
    has_lower = bool(re.search(r"[a-z]", password))
    has_digit = bool(re.search(r"[0-9]", password))
    has_symbol = bool(re.search(rf"[{re.escape(CHARSETS['symbols'])}]", password))

    charset_size = calculate_charset_size(password)
    char_types_count = sum([has_upper, has_lower, has_digit, has_symbol])

    # Entropy calculation
    entropy_result = effective_entropy(password)
    entropy_bits = entropy_result.effective_entropy

    # Crack time estimation
    crack_seconds = crack_time_estimate(entropy_bits)
    crack_time_str = format_time(crack_seconds)

    # Pattern detection
    sequential = detect_sequential(password)
    keyboard = detect_keyboard_pattern(password)
    repeated = detect_repeated_chars(password)
    dates = detect_date_pattern(password)

    # Common password check
    is_common = password.lower() in [p.lower() for p in COMMON_PASSWORDS]

    # === NIST SP 800-63B inspired scoring ===
    score = 0
    details: Dict[str, Any] = {}

    # 1. Length scoring (NIST-inspired)
    length_score = 0
    if len(password) >= 8:
        length_score += 8
    if len(password) >= 12:
        length_score += 12
    if len(password) >= 16:
        length_score += 15
    if len(password) >= 20:
        length_score += 10
    if len(password) >= 24:
        length_score += 5
    # Bonus for very long passwords
    length_score += min(max(0, len(password) - 24), 10)
    score += length_score
    details["length_score"] = length_score

    # 2. Character diversity scoring
    diversity_score = 0
    if has_upper:
        diversity_score += 5
    if has_lower:
        diversity_score += 5
    if has_digit:
        diversity_score += 5
    if has_symbol:
        diversity_score += 10
    score += diversity_score
    details["diversity_score"] = diversity_score

    # 3. Entropy scoring
    entropy_score = min(int(entropy_bits / 1.28), 25)
    score += entropy_score
    details["entropy_score"] = entropy_score

    # === Penalties ===

    # 4. Common password penalty
    if is_common:
        score -= 50
        details["common_password_penalty"] = -50

    # 5. Pattern penalties
    pattern_penalty = 0
    if sequential:
        seq_len = sum(l for _, l, _ in sequential)
        penalty = min(seq_len * 3, 15)
        pattern_penalty += penalty
        details["sequential_penalty"] = -penalty

    if keyboard:
        kb_len = sum(l for _, l, _ in keyboard)
        penalty = min(kb_len * 3, 15)
        pattern_penalty += penalty
        details["keyboard_penalty"] = -penalty

    if repeated:
        rep_len = sum(l for _, l, _ in repeated)
        penalty = min(rep_len * 2, 10)
        pattern_penalty += penalty
        details["repeated_penalty"] = -penalty

    if dates:
        pattern_penalty += 5
        details["date_penalty"] = -5

    score -= pattern_penalty

    # 6. Length penalty for short passwords
    if len(password) < 6:
        score -= 20
        details["short_password_penalty"] = -20
    elif len(password) < 8:
        score -= 10
        details["short_password_penalty"] = -10

    # 7. Low diversity penalty
    if char_types_count == 1:
        score -= 10
        details["low_diversity_penalty"] = -10

    # Clamp score
    score = max(0, min(100, score))

    # Determine grade
    if score >= 90:
        grade = "A"
    elif score >= 80:
        grade = "B"
    elif score >= 60:
        grade = "C"
    elif score >= 40:
        grade = "D"
    else:
        grade = "F"

    strength = get_strength_label(score)

    return AnalysisResult(
        password=password,
        score=score,
        grade=grade,
        strength=strength,
        entropy_bits=entropy_bits,
        crack_time=crack_time_str,
        charset_size=charset_size,
        length=len(password),
        has_uppercase=has_upper,
        has_lowercase=has_lower,
        has_digits=has_digit,
        has_symbols=has_symbol,
        is_common=is_common,
        sequential_found=sequential,
        keyboard_found=keyboard,
        repeated_found=repeated,
        dates_found=dates,
        details=details,
    )


def display_analysis(result: AnalysisResult, console: Optional[Console] = None) -> None:
    """Display password analysis results in a formatted Rich panel.

    Args:
        result: The AnalysisResult to display.
        console: Optional Rich Console instance. Creates a new one if not provided.
    """
    if console is None:
        console = Console()

    color = get_score_color(result.score)

    # Build main info table
    info_table = Table(show_header=False, expand=True, box=None, padding=(0, 1))
    info_table.add_column("Key", style="bold", width=22)
    info_table.add_column("Value")

    info_table.add_row("Password", f"[white on black] {mask_password(result.password)} [/]")
    info_table.add_row("Length", str(result.length))
    info_table.add_row("Charset Size", str(result.charset_size))
    info_table.add_row("Entropy", f"{result.entropy_bits:.1f} bits")
    info_table.add_row("Crack Time (est.)", f"[{color}]{result.crack_time}[/{color}]")

    # Character types
    type_str = ""
    if result.has_uppercase:
        type_str += "[green]A-Z[/] "
    if result.has_lowercase:
        type_str += "[green]a-z[/] "
    if result.has_digits:
        type_str += "[green]0-9[/] "
    if result.has_symbols:
        type_str += "[green]!@#[/]"
    if not type_str:
        type_str = "[red]None[/]"
    info_table.add_row("Char Types", type_str)

    # Score and grade
    score_text = Text()
    score_text.append(f"  {result.score}/100", style=f"bold {color}")
    score_text.append(f"  Grade: {result.grade}", style=f"bold {color}")
    score_text.append(f"  [{result.strength}]", style=color)
    info_table.add_row("Score", score_text)

    # Build findings table
    findings_table = Table(show_header=True, header_style="bold yellow", expand=True, box=None)
    findings_table.add_column("Finding", style="bold", width=20)
    findings_table.add_column("Status", width=10)
    findings_table.add_column("Details")

    # Common password
    if result.is_common:
        findings_table.add_row(
            "Common Password",
            "[red]FAIL[/red]",
            "Found in common password dictionary",
        )
    else:
        findings_table.add_row(
            "Common Password",
            "[green]PASS[/green]",
            "Not found in common password list",
        )

    # Sequential patterns
    if result.sequential_found:
        seq_info = ", ".join(f"'{p}' (len={l})" for _, l, p in result.sequential_found)
        findings_table.add_row(
            "Sequential Chars",
            "[red]FOUND[/red]",
            seq_info,
        )
    else:
        findings_table.add_row(
            "Sequential Chars",
            "[green]NONE[/green]",
            "No sequential patterns detected",
        )

    # Keyboard patterns
    if result.keyboard_found:
        kb_info = ", ".join(f"'{p}' (len={l})" for _, l, p in result.keyboard_found)
        findings_table.add_row(
            "Keyboard Pattern",
            "[red]FOUND[/red]",
            kb_info,
        )
    else:
        findings_table.add_row(
            "Keyboard Pattern",
            "[green]NONE[/green]",
            "No keyboard walking patterns detected",
        )

    # Repeated characters
    if result.repeated_found:
        rep_info = ", ".join(f"'{c}' x{l}" for _, l, c in result.repeated_found)
        findings_table.add_row(
            "Repeated Chars",
            "[yellow]FOUND[/yellow]",
            rep_info,
        )
    else:
        findings_table.add_row(
            "Repeated Chars",
            "[green]NONE[/green]",
            "No excessive repeated characters",
        )

    # Date patterns
    if result.dates_found:
        findings_table.add_row(
            "Date Patterns",
            "[yellow]FOUND[/yellow]",
            f"Possible dates: {', '.join(result.dates_found)}",
        )
    else:
        findings_table.add_row(
            "Date Patterns",
            "[green]NONE[/green]",
            "No date-like patterns detected",
        )

    # Combine into a panel
    content = Table.grid(expand=True)
    content.add_row(info_table)
    content.add_row("")
    content.add_row(findings_table)

    panel = Panel(
        content,
        title=f"[bold {color}]Password Strength Analysis[/bold {color}]",
        border_style=color,
        expand=True,
    )

    console.print(panel)


def analyze_batch(passwords: List[str]) -> List[AnalysisResult]:
    """Analyze a batch of passwords.

    Args:
        passwords: A list of password strings to analyze.

    Returns:
        A list of AnalysisResult objects, one per password.
    """
    return [analyze_password(p) for p in passwords]


def display_batch_summary(
    results: List[AnalysisResult], console: Optional[Console] = None
) -> None:
    """Display a summary table for batch password analysis.

    Args:
        results: A list of AnalysisResult objects.
        console: Optional Rich Console instance. Creates a new one if not provided.
    """
    if console is None:
        console = Console()

    table = Table(
        title="Batch Password Analysis Summary",
        show_header=True,
        header_style="bold cyan",
        expand=True,
    )
    table.add_column("#", style="dim", width=4)
    table.add_column("Password", width=20)
    table.add_column("Length", width=7, justify="center")
    table.add_column("Score", width=7, justify="center")
    table.add_column("Grade", width=7, justify="center")
    table.add_column("Strength", width=12)
    table.add_column("Crack Time", width=20)

    for i, result in enumerate(results, 1):
        color = get_score_color(result.score)
        table.add_row(
            str(i),
            mask_password(result.password),
            str(result.length),
            f"[{color}]{result.score}[/{color}]",
            f"[{color}]{result.grade}[/{color}]",
            f"[{color}]{result.strength}[/{color}]",
            result.crack_time,
        )

    console.print(table)
