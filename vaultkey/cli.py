"""
CLI entry point for VaultKey.

Provides the command-line interface using Click, with commands for
password generation, analysis, auditing, breach checking, entropy
calculation, report export, and configuration management.
"""

import sys
from typing import List, Optional

import click
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from . import __version__
from .analyzer import analyze_batch, analyze_password, display_analysis, display_batch_summary
from .auditor import (
    PasswordAuditor,
    display_audit_result,
    display_batch_audit_summary,
)
from .breach_checker import (
    BreachChecker,
    display_batch_breach_summary,
    display_breach_result,
)
from .config import ConfigManager
from .entropy import display_entropy, effective_entropy
from .generator import generate_batch, generate_passphrase, generate_password, generate_pin
from .report import (
    export_analysis_results,
    export_audit_results,
    export_breach_results,
)

console = Console()


def _version_message() -> str:
    """Return the version banner string.

    Returns:
        A formatted version string.
    """
    return f"VaultKey v{__version__}"


@click.group()
@click.version_option(version=__version__, prog_name="VaultKey", message=_version_message())
@click.pass_context
def main(ctx: click.Context) -> None:
    """VaultKey - Lightweight Terminal Password Generator & Security Audit Engine.

    A powerful CLI tool for generating secure passwords, analyzing password
    strength, auditing password policies, and checking for password breaches.
    """
    ctx.ensure_object(dict)
    ctx.obj["console"] = console
    ctx.obj["config"] = ConfigManager()


# ============================================================
# Generate Command
# ============================================================

@main.command()
@click.option(
    "-l", "--length", default=None, type=int,
    help="Password length (default: from config, usually 16).",
)
@click.option(
    "--no-uppercase", is_flag=True, default=False,
    help="Exclude uppercase letters.",
)
@click.option(
    "--no-lowercase", is_flag=True, default=False,
    help="Exclude lowercase letters.",
)
@click.option(
    "--no-digits", is_flag=True, default=False,
    help="Exclude digits.",
)
@click.option(
    "--no-symbols", is_flag=True, default=False,
    help="Exclude special symbols.",
)
@click.option(
    "--exclude-ambiguous", is_flag=True, default=False,
    help="Exclude ambiguous characters (0/O, 1/l/I, etc.).",
)
@click.option(
    "--no-repeating", is_flag=True, default=False,
    help="Prevent consecutive repeated characters.",
)
@click.option(
    "--passphrase", is_flag=True, default=False,
    help="Generate a passphrase instead of a password.",
)
@click.option(
    "--words", default=None, type=int,
    help="Number of words for passphrase (default: 4).",
)
@click.option(
    "--separator", default=None, type=str,
    help="Word separator for passphrase (default: '-').",
)
@click.option(
    "--capitalize", is_flag=True, default=False,
    help="Capitalize each word in passphrase.",
)
@click.option(
    "--pin", default=None, type=int,
    help="Generate a PIN of specified length.",
)
@click.option(
    "-b", "--batch", default=None, type=int,
    help="Generate multiple passwords.",
)
@click.pass_context
def generate(
    ctx: click.Context,
    length: Optional[int],
    no_uppercase: bool,
    no_lowercase: bool,
    no_digits: bool,
    no_symbols: bool,
    exclude_ambiguous: bool,
    no_repeating: bool,
    passphrase: bool,
    words: Optional[int],
    separator: Optional[str],
    capitalize: bool,
    pin: Optional[int],
    batch: Optional[int],
) -> None:
    """Generate secure random passwords, passphrases, or PIN codes."""
    try:
        if pin is not None:
            # PIN mode
            count = batch or 1
            pins = generate_batch(count, mode="pin", length=pin)
            if count == 1:
                console.print(Panel(
                    f"[bold green]{pins[0]}[/bold green]",
                    title="[bold cyan]Generated PIN[/bold cyan]",
                    border_style="green",
                ))
            else:
                _display_batch_results(pins, "Generated PINs")
            return

        if passphrase:
            # Passphrase mode
            cfg = ctx.obj["config"]
            num_words = words or cfg.get("passphrase.num_words", 4)
            sep = separator if separator is not None else cfg.get("passphrase.separator", "-")

            count = batch or 1
            phrases = generate_batch(
                count,
                mode="passphrase",
                num_words=num_words,
                separator=sep,
                capitalize=capitalize,
            )
            if count == 1:
                console.print(Panel(
                    f"[bold green]{phrases[0]}[/bold green]",
                    title="[bold cyan]Generated Passphrase[/bold cyan]",
                    border_style="green",
                ))
            else:
                _display_batch_results(phrases, "Generated Passphrases")
            return

        # Standard password mode
        cfg = ctx.obj["config"]
        pwd_length = length or cfg.get("generation.length", 16)

        charset_config = {
            "uppercase": not no_uppercase,
            "lowercase": not no_lowercase,
            "digits": not no_digits,
            "symbols": not no_symbols,
        }

        count = batch or 1
        passwords = generate_batch(
            count,
            mode="password",
            length=pwd_length,
            charset_config=charset_config,
            exclude_ambiguous=exclude_ambiguous,
            no_repeating=no_repeating,
        )

        if count == 1:
            console.print(Panel(
                f"[bold green]{passwords[0]}[/bold green]",
                title=f"[bold cyan]Generated Password (length: {pwd_length})[/bold cyan]",
                border_style="green",
            ))
        else:
            _display_batch_results(passwords, "Generated Passwords")

    except ValueError as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)


def _display_batch_results(items: List[str], title: str) -> None:
    """Display a list of generated items in a numbered panel.

    Args:
        items: The list of strings to display.
        title: The panel title.
    """
    from rich.table import Table

    table = Table(
        title=title,
        show_header=True,
        header_style="bold cyan",
        expand=True,
    )
    table.add_column("#", style="dim", width=5, justify="right")
    table.add_column("Value", style="bold green")

    for i, item in enumerate(items, 1):
        table.add_row(str(i), item)

    console.print(table)


# ============================================================
# Analyze Command
# ============================================================

@main.command()
@click.argument("password", required=False)
@click.option(
    "-f", "--file", "filepath", default=None, type=str,
    help="Read passwords from a file (one per line).",
)
@click.pass_context
def analyze(ctx: click.Context, password: Optional[str], filepath: Optional[str]) -> None:
    """Analyze password strength and provide detailed feedback."""
    if not password and not filepath:
        console.print("[red]Error:[/red] Provide a password or use --file to specify a file.")
        sys.exit(1)

    try:
        if filepath:
            with open(filepath, "r", encoding="utf-8") as f:
                passwords = [line.strip() for line in f if line.strip()]
            results = analyze_batch(passwords)
            display_batch_summary(results, console)
        else:
            result = analyze_password(password)  # type: ignore
            display_analysis(result, console)

    except FileNotFoundError:
        console.print(f"[red]Error:[/red] File not found: {filepath}")
        sys.exit(1)
    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)


# ============================================================
# Audit Command
# ============================================================

@main.command()
@click.argument("password", required=False)
@click.option(
    "-f", "--file", "filepath", default=None, type=str,
    help="Read passwords from a file (one per line).",
)
@click.option(
    "-p", "--policy", default="custom", type=str,
    help="Policy template to use (nist, pci-dss, strict, custom).",
)
@click.option(
    "-u", "--username", default="", type=str,
    help="Username to check against (for username-in-password detection).",
)
@click.pass_context
def audit(
    ctx: click.Context,
    password: Optional[str],
    filepath: Optional[str],
    policy: str,
    username: str,
) -> None:
    """Audit passwords against security policies."""
    if not password and not filepath:
        console.print("[red]Error:[/red] Provide a password or use --file to specify a file.")
        sys.exit(1)

    try:
        cfg = ctx.obj["config"]
        policy_dict = cfg.get_policy(policy)
        auditor = PasswordAuditor(policy_dict)

        if filepath:
            results = auditor.audit_file(filepath)
            display_batch_audit_summary(results, console)
        else:
            result = auditor.audit(password, username)  # type: ignore
            display_audit_result(result, console)

    except ValueError as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)
    except FileNotFoundError:
        console.print(f"[red]Error:[/red] File not found: {filepath}")
        sys.exit(1)
    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)


# ============================================================
# Check Command (Breach Check)
# ============================================================

@main.command()
@click.argument("password", required=False)
@click.option(
    "-f", "--file", "filepath", default=None, type=str,
    help="Read passwords from a file (one per line).",
)
@click.pass_context
def check(ctx: click.Context, password: Optional[str], filepath: Optional[str]) -> None:
    """Check if a password has been exposed in known data breaches."""
    if not password and not filepath:
        console.print("[red]Error:[/red] Provide a password or use --file to specify a file.")
        sys.exit(1)

    try:
        checker = BreachChecker()

        if filepath:
            results = checker.check_file(filepath)
            display_batch_breach_summary(results, console)
        else:
            result = checker.check(password)  # type: ignore
            display_breach_result(result, console)

    except FileNotFoundError:
        console.print(f"[red]Error:[/red] File not found: {filepath}")
        sys.exit(1)
    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)


# ============================================================
# Entropy Command
# ============================================================

@main.command()
@click.argument("password", required=False)
@click.pass_context
def entropy(ctx: click.Context, password: Optional[str]) -> None:
    """Calculate and display password entropy metrics."""
    if not password:
        console.print("[red]Error:[/red] Please provide a password to analyze.")
        sys.exit(1)

    try:
        result = effective_entropy(password)
        display_entropy(result, console)
    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)


# ============================================================
# Export Command
# ============================================================

@main.command()
@click.option(
    "--format", "fmt", default="json", type=click.Choice(["json", "csv", "txt"]),
    help="Output format (json, csv, txt).",
)
@click.option(
    "-o", "--output", default=None, type=str,
    help="Output file path. If not specified, prints to stdout.",
)
@click.option(
    "--type", "report_type", default="analysis", type=click.Choice(["analysis", "audit", "breach"]),
    help="Type of report to export.",
)
@click.option(
    "-f", "--file", "filepath", default=None, type=str,
    help="Input file with passwords to analyze before exporting.",
)
@click.pass_context
def export(
    ctx: click.Context,
    fmt: str,
    output: Optional[str],
    report_type: str,
    filepath: Optional[str],
) -> None:
    """Export analysis/audit/breach results to JSON, CSV, or TXT."""
    try:
        if not filepath:
            console.print(
                "[yellow]Note:[/yellow] No input file specified. "
                "Provide --file to generate a report from passwords."
            )
            console.print(
                "[dim]Usage: vaultkey export --type analysis --file passwords.txt --format json -o report.json[/dim]"
            )
            return

        with open(filepath, "r", encoding="utf-8") as f:
            passwords = [line.strip() for line in f if line.strip()]

        if not passwords:
            console.print("[yellow]Warning:[/yellow] No passwords found in the input file.")
            return

        if report_type == "analysis":
            results = analyze_batch(passwords)
            content = export_analysis_results(results, fmt, output)
        elif report_type == "audit":
            cfg = ctx.obj["config"]
            policy_dict = cfg.get_policy(cfg.get("audit.policy", "custom"))
            auditor = PasswordAuditor(policy_dict)
            results = auditor.audit_batch(passwords)
            content = export_audit_results(results, fmt, output)
        elif report_type == "breach":
            checker = BreachChecker()
            results = checker.check_batch(passwords)
            content = export_breach_results(results, fmt, output)
        else:
            console.print(f"[red]Error:[/red] Unknown report type: {report_type}")
            sys.exit(1)

        if output:
            console.print(f"[green]Report exported to:[/green] {output}")
        else:
            console.print(content)

    except FileNotFoundError:
        console.print(f"[red]Error:[/red] File not found: {filepath}")
        sys.exit(1)
    except ValueError as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)
    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)


# ============================================================
# Config Command
# ============================================================

@main.command()
@click.option(
    "--show", is_flag=True, default=False,
    help="Display current configuration.",
)
@click.option(
    "--set", "set_value", nargs=2, default=None,
    help="Set a configuration value (key value). Supports dot notation.",
)
@click.option(
    "--list-policies", is_flag=True, default=False,
    help="List available policy templates.",
)
@click.pass_context
def config(
    ctx: click.Context,
    show: bool,
    set_value: Optional[List[str]],
    list_policies: bool,
) -> None:
    """Manage VaultKey configuration."""
    cfg_mgr = ctx.obj["config"]

    try:
        if list_policies:
            policies = cfg_mgr.list_policies()
            from rich.table import Table

            table = Table(
                title="Available Policy Templates",
                show_header=True,
                header_style="bold cyan",
                expand=True,
            )
            table.add_column("Name", style="bold", width=15)
            table.add_column("Description")

            for p in policies:
                table.add_row(p["name"], p["description"])

            console.print(table)
            return

        if set_value:
            key, value = set_value[0], set_value[1]
            # Try to convert value to appropriate type
            if value.lower() == "true":
                value = True
            elif value.lower() == "false":
                value = False
            else:
                try:
                    value = int(value)
                except ValueError:
                    try:
                        value = float(value)
                    except ValueError:
                        pass  # Keep as string

            cfg_mgr.set(key, value)
            cfg_mgr.save()
            console.print(f"[green]Set:[/green] {key} = {value}")
            console.print(f"[dim]Configuration saved to {cfg_mgr.config_path}[/dim]")
            return

        if show:
            from rich.table import Table

            full_config = cfg_mgr.show()

            table = Table(
                title=f"VaultKey Configuration",
                show_header=True,
                header_style="bold cyan",
                expand=True,
            )
            table.add_column("Section", style="bold cyan", width=15)
            table.add_column("Key", style="bold", width=25)
            table.add_column("Value")

            for section, values in full_config.items():
                if isinstance(values, dict) and section != "policies":
                    first = True
                    for key, val in values.items():
                        table.add_row(
                            section if first else "",
                            key,
                            str(val),
                        )
                        first = False
                elif section == "policies":
                    for policy_name, policy_data in values.items():
                        if isinstance(policy_data, dict):
                            table.add_row(
                                f"[bold]{section}[/bold]",
                                f"[bold]{policy_name}[/bold]",
                                policy_data.get("description", ""),
                            )

            console.print(table)
            console.print(f"\n[dim]Config file: {cfg_mgr.config_path}[/dim]")
            return

        # No option specified - show help
        console.print(
            "[yellow]Usage:[/yellow]\n"
            "  vaultkey config --show          Show current configuration\n"
            "  vaultkey config --set key value Set a configuration value\n"
            "  vaultkey config --list-policies List available policies\n"
        )

    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
