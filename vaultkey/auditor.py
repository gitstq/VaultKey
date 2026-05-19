"""
Password policy audit module for VaultKey.

Provides password policy enforcement and auditing capabilities with
support for multiple policy templates (NIST, PCI-DSS, Strict, Custom)
and batch auditing from files.
"""

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from .analyzer import COMMON_PASSWORDS, analyze_password
from .entropy import effective_entropy
from .utils import (
    CHARSETS,
    detect_date_pattern,
    detect_keyboard_pattern,
    detect_repeated_chars,
    detect_sequential,
    mask_password,
)


class AuditStatus(str, Enum):
    """Enumeration of possible audit result statuses."""

    PASS = "PASS"
    FAIL = "FAIL"
    WARN = "WARN"


@dataclass
class AuditCheck:
    """Represents a single audit check result.

    Attributes:
        name: Name of the check.
        status: Pass/fail/warning status.
        message: Human-readable description of the result.
        details: Optional additional details.
    """

    name: str
    status: AuditStatus
    message: str
    details: str = ""


@dataclass
class AuditResult:
    """Container for a complete password audit result.

    Attributes:
        password: The audited password (masked).
        checks: List of individual audit check results.
        passed: Number of checks that passed.
        failed: Number of checks that failed.
        warnings: Number of warnings.
        overall_status: Overall audit status (PASS if no failures).
    """

    password: str
    checks: List[AuditCheck] = field(default_factory=list)
    passed: int = 0
    failed: int = 0
    warnings: int = 0
    overall_status: AuditStatus = AuditStatus.PASS

    def to_dict(self) -> Dict[str, Any]:
        """Convert the audit result to a dictionary.

        Returns:
            A dictionary containing all audit fields.
        """
        return {
            "password_masked": mask_password(self.password),
            "overall_status": self.overall_status.value,
            "passed": self.passed,
            "failed": self.failed,
            "warnings": self.warnings,
            "checks": [
                {
                    "name": check.name,
                    "status": check.status.value,
                    "message": check.message,
                    "details": check.details,
                }
                for check in self.checks
            ],
        }


class PasswordAuditor:
    """Audits passwords against configurable security policies.

    Supports multiple policy templates and custom rule configuration.
    Can audit individual passwords or batches from files.

    Attributes:
        policy: The active policy dictionary.
    """

    def __init__(self, policy: Optional[Dict[str, Any]] = None) -> None:
        """Initialize the PasswordAuditor with a policy.

        Args:
            policy: A policy dictionary. If None, uses the 'custom' default policy.
        """
        from .config import POLICY_TEMPLATES

        self.policy = policy or POLICY_TEMPLATES["custom"]

    def set_policy(self, policy: Dict[str, Any]) -> None:
        """Set or update the active audit policy.

        Args:
            policy: A policy dictionary with audit rules.
        """
        self.policy = policy

    def audit(self, password: str, username: str = "") -> AuditResult:
        """Audit a single password against the active policy.

        Runs all configured checks and returns a comprehensive result.

        Args:
            password: The password to audit.
            username: Optional username to check against (for username-in-password check).

        Returns:
            An AuditResult containing all check outcomes.
        """
        if not password:
            result = AuditResult(password="")
            result.checks.append(
                AuditCheck("Empty Password", AuditStatus.FAIL, "Password is empty.")
            )
            result.failed = 1
            result.overall_status = AuditStatus.FAIL
            return result

        result = AuditResult(password=password)
        checks: List[AuditCheck] = []

        # 1. Minimum length check
        min_len = self.policy.get("min_length", 8)
        if len(password) >= min_len:
            checks.append(
                AuditCheck(
                    "Minimum Length",
                    AuditStatus.PASS,
                    f"Password length ({len(password)}) meets minimum ({min_len}).",
                )
            )
        else:
            checks.append(
                AuditCheck(
                    "Minimum Length",
                    AuditStatus.FAIL,
                    f"Password length ({len(password)}) is below minimum ({min_len}).",
                )
            )

        # 2. Maximum length check
        max_len = self.policy.get("max_length", 128)
        if len(password) <= max_len:
            checks.append(
                AuditCheck(
                    "Maximum Length",
                    AuditStatus.PASS,
                    f"Password length ({len(password)}) is within maximum ({max_len}).",
                )
            )
        else:
            checks.append(
                AuditCheck(
                    "Maximum Length",
                    AuditStatus.FAIL,
                    f"Password length ({len(password)}) exceeds maximum ({max_len}).",
                )
            )

        # 3. Uppercase requirement
        if self.policy.get("require_uppercase", False):
            if re.search(r"[A-Z]", password):
                checks.append(
                    AuditCheck(
                        "Uppercase Required",
                        AuditStatus.PASS,
                        "Password contains at least one uppercase letter.",
                    )
                )
            else:
                checks.append(
                    AuditCheck(
                        "Uppercase Required",
                        AuditStatus.FAIL,
                        "Password must contain at least one uppercase letter (A-Z).",
                    )
                )

        # 4. Lowercase requirement
        if self.policy.get("require_lowercase", False):
            if re.search(r"[a-z]", password):
                checks.append(
                    AuditCheck(
                        "Lowercase Required",
                        AuditStatus.PASS,
                        "Password contains at least one lowercase letter.",
                    )
                )
            else:
                checks.append(
                    AuditCheck(
                        "Lowercase Required",
                        AuditStatus.FAIL,
                        "Password must contain at least one lowercase letter (a-z).",
                    )
                )

        # 5. Digit requirement
        if self.policy.get("require_digits", False):
            if re.search(r"[0-9]", password):
                checks.append(
                    AuditCheck(
                        "Digits Required",
                        AuditStatus.PASS,
                        "Password contains at least one digit.",
                    )
                )
            else:
                checks.append(
                    AuditCheck(
                        "Digits Required",
                        AuditStatus.FAIL,
                        "Password must contain at least one digit (0-9).",
                    )
                )

        # 6. Symbol requirement
        if self.policy.get("require_symbols", False):
            if re.search(rf"[{re.escape(CHARSETS['symbols'])}]", password):
                checks.append(
                    AuditCheck(
                        "Symbols Required",
                        AuditStatus.PASS,
                        "Password contains at least one special symbol.",
                    )
                )
            else:
                checks.append(
                    AuditCheck(
                        "Symbols Required",
                        AuditStatus.FAIL,
                        "Password must contain at least one special symbol.",
                    )
                )

        # 7. Common password check
        if self.policy.get("block_common_passwords", False):
            if password.lower() in [p.lower() for p in COMMON_PASSWORDS]:
                checks.append(
                    AuditCheck(
                        "Common Password",
                        AuditStatus.FAIL,
                        "Password found in common password dictionary.",
                    )
                )
            else:
                checks.append(
                    AuditCheck(
                        "Common Password",
                        AuditStatus.PASS,
                        "Password is not in the common password dictionary.",
                    )
                )

        # 8. Username check
        if self.policy.get("block_username", False) and username:
            if username.lower() in password.lower():
                checks.append(
                    AuditCheck(
                        "Username Check",
                        AuditStatus.FAIL,
                        f"Password contains the username '{username}'.",
                    )
                )
            else:
                checks.append(
                    AuditCheck(
                        "Username Check",
                        AuditStatus.PASS,
                        "Password does not contain the username.",
                    )
                )

        # 9. Sequential character check
        if self.policy.get("block_sequential", False):
            sequential = detect_sequential(password)
            if sequential:
                seq_info = ", ".join(f"'{p}'" for _, _, p in sequential)
                checks.append(
                    AuditCheck(
                        "Sequential Chars",
                        AuditStatus.FAIL,
                        f"Sequential patterns detected: {seq_info}",
                    )
                )
            else:
                checks.append(
                    AuditCheck(
                        "Sequential Chars",
                        AuditStatus.PASS,
                        "No sequential character patterns detected.",
                    )
                )

        # 10. Repeated character check
        if self.policy.get("block_repeated", False):
            repeated = detect_repeated_chars(password)
            if repeated:
                rep_info = ", ".join(f"'{c}' x{l}" for _, l, c in repeated)
                checks.append(
                    AuditCheck(
                        "Repeated Chars",
                        AuditStatus.FAIL,
                        f"Excessive repeated characters: {rep_info}",
                    )
                )
            else:
                checks.append(
                    AuditCheck(
                        "Repeated Chars",
                        AuditStatus.PASS,
                        "No excessive repeated characters detected.",
                    )
                )

        # 11. Minimum entropy check
        min_entropy = self.policy.get("min_entropy", 0)
        if min_entropy > 0:
            ent_result = effective_entropy(password)
            if ent_result.effective_entropy >= min_entropy:
                checks.append(
                    AuditCheck(
                        "Minimum Entropy",
                        AuditStatus.PASS,
                        f"Entropy ({ent_result.effective_entropy:.1f} bits) meets minimum ({min_entropy} bits).",
                    )
                )
            else:
                checks.append(
                    AuditCheck(
                        "Minimum Entropy",
                        AuditStatus.FAIL,
                        f"Entropy ({ent_result.effective_entropy:.1f} bits) is below minimum ({min_entropy} bits).",
                    )
                )

        # 12. Keyboard pattern warning (always check, but only warn)
        keyboard = detect_keyboard_pattern(password)
        if keyboard:
            kb_info = ", ".join(f"'{p}'" for _, _, p in keyboard)
            checks.append(
                AuditCheck(
                    "Keyboard Pattern",
                    AuditStatus.WARN,
                    f"Keyboard walking pattern detected: {kb_info}",
                )
            )

        # 13. Date pattern warning (always check, but only warn)
        dates = detect_date_pattern(password)
        if dates:
            checks.append(
                AuditCheck(
                    "Date Pattern",
                    AuditStatus.WARN,
                    f"Possible date pattern detected: {', '.join(dates)}",
                )
            )

        # Compile results
        result.checks = checks
        result.passed = sum(1 for c in checks if c.status == AuditStatus.PASS)
        result.failed = sum(1 for c in checks if c.status == AuditStatus.FAIL)
        result.warnings = sum(1 for c in checks if c.status == AuditStatus.WARN)

        if result.failed > 0:
            result.overall_status = AuditStatus.FAIL
        elif result.warnings > 0:
            result.overall_status = AuditStatus.WARN
        else:
            result.overall_status = AuditStatus.PASS

        return result

    def audit_batch(
        self,
        passwords: List[str],
        usernames: Optional[List[str]] = None,
    ) -> List[AuditResult]:
        """Audit a batch of passwords against the active policy.

        Args:
            passwords: A list of password strings to audit.
            usernames: Optional list of usernames corresponding to each password.

        Returns:
            A list of AuditResult objects, one per password.
        """
        results: List[AuditResult] = []
        for i, password in enumerate(passwords):
            username = usernames[i] if usernames and i < len(usernames) else ""
            results.append(self.audit(password, username))
        return results

    def audit_file(self, filepath: str) -> List[AuditResult]:
        """Audit passwords from a file.

        Each line in the file is treated as a separate password.

        Args:
            filepath: Path to the file containing passwords (one per line).

        Returns:
            A list of AuditResult objects.

        Raises:
            FileNotFoundError: If the specified file does not exist.
        """
        with open(filepath, "r", encoding="utf-8") as f:
            passwords = [line.strip() for line in f if line.strip()]
        return self.audit_batch(passwords)


def display_audit_result(
    result: AuditResult, console: Optional[Console] = None
) -> None:
    """Display a password audit result in a formatted Rich panel.

    Args:
        result: The AuditResult to display.
        console: Optional Rich Console instance. Creates a new one if not provided.
    """
    if console is None:
        console = Console()

    status_colors = {
        AuditStatus.PASS: "green",
        AuditStatus.FAIL: "red",
        AuditStatus.WARN: "yellow",
    }

    overall_color = status_colors.get(result.overall_status, "white")

    table = Table(
        show_header=True,
        header_style="bold cyan",
        expand=True,
    )
    table.add_column("Check", style="bold", width=22)
    table.add_column("Status", width=8, justify="center")
    table.add_column("Message")

    for check in result.checks:
        color = status_colors.get(check.status, "white")
        status_str = f"[{color}]{check.status.value}[/{color}]"
        table.add_row(check.name, status_str, check.message)

    # Summary
    summary = (
        f"[bold]Results:[/bold] "
        f"[green]{result.passed} passed[/green], "
        f"[red]{result.failed} failed[/red], "
        f"[yellow]{result.warnings} warnings[/yellow]"
    )

    panel = Panel(
        table,
        title=f"[bold {overall_color}]Password Audit - "
              f"[{overall_color}]{result.overall_status.value}[/{overall_color}][/bold {overall_color}]",
        subtitle=summary,
        border_style=overall_color,
        expand=True,
    )

    console.print(panel)


def display_batch_audit_summary(
    results: List[AuditResult], console: Optional[Console] = None
) -> None:
    """Display a summary table for batch password audit results.

    Args:
        results: A list of AuditResult objects.
        console: Optional Rich Console instance. Creates a new one if not provided.
    """
    if console is None:
        console = Console()

    table = Table(
        title="Batch Audit Summary",
        show_header=True,
        header_style="bold cyan",
        expand=True,
    )
    table.add_column("#", style="dim", width=4)
    table.add_column("Password", width=20)
    table.add_column("Status", width=8, justify="center")
    table.add_column("Passed", width=7, justify="center")
    table.add_column("Failed", width=7, justify="center")
    table.add_column("Warnings", width=9, justify="center")

    status_colors = {
        AuditStatus.PASS: "green",
        AuditStatus.FAIL: "red",
        AuditStatus.WARN: "yellow",
    }

    for i, result in enumerate(results, 1):
        color = status_colors.get(result.overall_status, "white")
        table.add_row(
            str(i),
            mask_password(result.password),
            f"[{color}]{result.overall_status.value}[/{color}]",
            f"[green]{result.passed}[/green]",
            f"[red]{result.failed}[/red]",
            f"[yellow]{result.warnings}[/yellow]",
        )

    console.print(table)
