"""
Password entropy calculation module for VaultKey.

Provides various entropy calculation methods including Shannon entropy,
charset-based entropy, and effective entropy that accounts for known patterns.
"""

import math
from collections import Counter
from typing import Dict, List, Optional, Tuple

from rich.console import Console
from rich.panel import Panel
from rich.progress import BarColumn, Progress
from rich.table import Table
from rich.text import Text

from .utils import (
    calculate_charset_size,
    detect_keyboard_pattern,
    detect_repeated_chars,
    detect_sequential,
    get_score_color,
)


class EntropyResult:
    """Container for entropy calculation results.

    Attributes:
        password: The analyzed password.
        shannon_entropy: Shannon entropy per character.
        charset_entropy: Entropy based on character set size.
        effective_entropy: Entropy adjusted for known patterns.
        charset_size: Estimated character pool size.
        pattern_deductions: List of (deduction_amount, reason) tuples.
    """

    def __init__(
        self,
        password: str,
        shannon_entropy: float,
        charset_entropy: float,
        effective_entropy: float,
        charset_size: int,
        pattern_deductions: Optional[List[Tuple[float, str]]] = None,
    ) -> None:
        """Initialize EntropyResult.

        Args:
            password: The analyzed password.
            shannon_entropy: Shannon entropy per character.
            charset_entropy: Entropy based on charset size.
            effective_entropy: Effective entropy after pattern deductions.
            charset_size: Estimated character pool size.
            pattern_deductions: List of entropy deductions due to patterns.
        """
        self.password = password
        self.shannon_entropy = shannon_entropy
        self.charset_entropy = charset_entropy
        self.effective_entropy = effective_entropy
        self.charset_size = charset_size
        self.pattern_deductions = pattern_deductions or []

    def to_dict(self) -> Dict:
        """Convert the result to a dictionary.

        Returns:
            A dictionary containing all entropy metrics.
        """
        return {
            "password_length": len(self.password),
            "charset_size": self.charset_size,
            "shannon_entropy": round(self.shannon_entropy, 2),
            "charset_entropy": round(self.charset_entropy, 2),
            "effective_entropy": round(self.effective_entropy, 2),
            "pattern_deductions": [
                {"deduction": round(d, 2), "reason": r}
                for d, r in self.pattern_deductions
            ],
        }


def shannon_entropy(password: str) -> float:
    """Calculate the Shannon entropy of a password.

    Shannon entropy measures the randomness/unpredictability of the
    character distribution in the password.

    Args:
        password: The password to analyze.

    Returns:
        Shannon entropy in bits per character.
    """
    if not password:
        return 0.0

    length = len(password)
    counts = Counter(password)
    entropy = 0.0

    for count in counts.values():
        probability = count / length
        if probability > 0:
            entropy -= probability * math.log2(probability)

    return entropy


def charset_entropy(password: str) -> float:
    """Calculate entropy based on the character set size and password length.

    This assumes a uniform random distribution over the character set.

    Args:
        password: The password to analyze.

    Returns:
        Entropy in bits.
    """
    if not password:
        return 0.0

    charset_size = calculate_charset_size(password)
    return len(password) * math.log2(charset_size)


def effective_entropy(password: str) -> EntropyResult:
    """Calculate effective entropy accounting for known patterns.

    Starts with charset-based entropy and applies deductions for detected
    patterns such as sequential characters, keyboard walks, and repeated
    characters.

    Args:
        password: The password to analyze.

    Returns:
        An EntropyResult containing all entropy metrics and deductions.
    """
    if not password:
        return EntropyResult("", 0.0, 0.0, 0.0, 0)

    # Base calculations
    shannon = shannon_entropy(password)
    charset_ent = charset_entropy(password)
    charset_size = calculate_charset_size(password)

    # Start with charset entropy and apply deductions
    effective = charset_ent
    deductions: List[Tuple[float, str]] = []

    # Check for sequential patterns
    sequential = detect_sequential(password)
    if sequential:
        total_seq_len = sum(length for _, length, _ in sequential)
        deduction = total_seq_len * math.log2(charset_size) * 0.5
        effective -= deduction
        deductions.append((deduction, f"Sequential patterns ({total_seq_len} chars)"))

    # Check for keyboard patterns
    keyboard = detect_keyboard_pattern(password)
    if keyboard:
        total_kb_len = sum(length for _, length, _ in keyboard)
        deduction = total_kb_len * math.log2(charset_size) * 0.5
        effective -= deduction
        deductions.append((deduction, f"Keyboard patterns ({total_kb_len} chars)"))

    # Check for repeated characters
    repeated = detect_repeated_chars(password)
    if repeated:
        total_rep_len = sum(length for _, length, _ in repeated)
        deduction = total_rep_len * math.log2(charset_size) * 0.3
        effective -= deduction
        deductions.append((deduction, f"Repeated characters ({total_rep_len} chars)"))

    # Shannon entropy ratio adjustment
    max_shannon = math.log2(charset_size) if charset_size > 0 else 0
    if max_shannon > 0:
        ratio = shannon / max_shannon
        if ratio < 0.7:
            deduction = charset_ent * (1 - ratio) * 0.3
            effective -= deduction
            deductions.append((deduction, "Low character distribution randomness"))

    # Ensure entropy doesn't go below 0
    effective = max(effective, 0.0)

    return EntropyResult(
        password=password,
        shannon_entropy=shannon,
        charset_entropy=charset_ent,
        effective_entropy=effective,
        charset_size=charset_size,
        pattern_deductions=deductions,
    )


def display_entropy(result: EntropyResult, console: Optional[Console] = None) -> None:
    """Display entropy analysis results in a formatted Rich panel.

    Args:
        result: The EntropyResult to display.
        console: Optional Rich Console instance. Creates a new one if not provided.
    """
    if console is None:
        console = Console()

    # Build entropy visualization table
    table = Table(show_header=True, header_style="bold cyan", expand=True)
    table.add_column("Metric", style="bold", width=25)
    table.add_column("Value", style="bold", width=15)
    table.add_column("Visualization", min_width=30)

    # Shannon entropy bar
    max_shannon = math.log2(result.charset_size) if result.charset_size > 0 else 1
    shannon_pct = min(result.shannon_entropy / max_shannon, 1.0) if max_shannon > 0 else 0
    shannon_bar = _make_bar(shannon_pct, get_score_color(int(shannon_pct * 100)))
    table.add_row(
        "Shannon Entropy",
        f"{result.shannon_entropy:.2f} bits/char",
        shannon_bar,
    )

    # Charset entropy bar
    max_charset_ent = 128.0  # Reasonable max for display
    charset_pct = min(result.charset_entropy / max_charset_ent, 1.0)
    charset_bar = _make_bar(charset_pct, get_score_color(int(charset_pct * 100)))
    table.add_row(
        "Charset Entropy",
        f"{result.charset_entropy:.2f} bits",
        charset_bar,
    )

    # Effective entropy bar
    effective_pct = min(result.effective_entropy / max_charset_ent, 1.0)
    effective_bar = _make_bar(
        effective_pct, get_score_color(int(effective_pct * 100))
    )
    table.add_row(
        "Effective Entropy",
        f"{result.effective_entropy:.2f} bits",
        effective_bar,
    )

    # Charset size
    table.add_row("Charset Size", str(result.charset_size), "")

    # Pattern deductions
    if result.pattern_deductions:
        for deduction, reason in result.pattern_deductions:
            table.add_row(
                f"  [red]-[/red] {reason}",
                f"[red]-{deduction:.2f} bits[/red]",
                "",
            )

    panel = Panel(
        table,
        title="[bold cyan]Password Entropy Analysis[/bold cyan]",
        subtitle=f"Password length: {len(result.password)} characters",
        border_style="cyan",
        expand=True,
    )

    console.print(panel)


def _make_bar(percentage: float, color: str = "green", width: int = 30) -> str:
    """Create a text-based progress bar string.

    Args:
        percentage: Fill percentage (0.0 to 1.0).
        color: Rich color name for the filled portion.
        width: Total width of the bar in characters.

    Returns:
        A Rich-formatted bar string.
    """
    filled = int(width * percentage)
    empty = width - filled
    return f"[{color}]{'█' * filled}[/{color}][dim]{'░' * empty}[/dim] {percentage * 100:.0f}%"
