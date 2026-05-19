"""
Report export module for VaultKey.

Provides functionality to export analysis, audit, and breach check results
to various formats including JSON, CSV, and plain text.
"""

import csv
import json
from datetime import datetime
from io import StringIO
from typing import Any, Dict, List, Optional, Union

from .analyzer import AnalysisResult
from .auditor import AuditResult
from .breach_checker import BreachCheckResult


def _get_timestamp() -> str:
    """Return the current timestamp as an ISO 8601 string.

    Returns:
        A timestamp string.
    """
    return datetime.now().isoformat()


def export_json(
    data: Union[List[Dict], Dict],
    output_path: Optional[str] = None,
    pretty: bool = True,
) -> str:
    """Export data to JSON format.

    Args:
        data: The data to export (dictionary or list of dictionaries).
        output_path: Optional file path to write the JSON to.
                    If None, returns the JSON string.
        pretty: If True, formats JSON with indentation.

    Returns:
        The JSON string.

    Raises:
        IOError: If writing to the output path fails.
    """
    indent = 2 if pretty else None
    json_str = json.dumps(data, indent=indent, ensure_ascii=False, default=str)

    if output_path:
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(json_str)

    return json_str


def export_csv(
    data: List[Dict[str, Any]],
    output_path: Optional[str] = None,
    fields: Optional[List[str]] = None,
) -> str:
    """Export data to CSV format.

    Args:
        data: A list of dictionaries to export. Each dictionary represents a row.
        output_path: Optional file path to write the CSV to.
                    If None, returns the CSV string.
        fields: Optional list of field names to include. If None, uses all keys
                from the first dictionary.

    Returns:
        The CSV string.

    Raises:
        ValueError: If data is empty.
        IOError: If writing to the output path fails.
    """
    if not data:
        raise ValueError("No data to export.")

    if fields is None:
        fields = list(data[0].keys())

    output = StringIO()
    writer = csv.DictWriter(output, fieldnames=fields, extrasaction="ignore")
    writer.writeheader()
    writer.writerows(data)

    csv_str = output.getvalue()

    if output_path:
        with open(output_path, "w", encoding="utf-8", newline="") as f:
            f.write(csv_str)

    return csv_str


def export_text(
    data: Union[List[Dict], Dict],
    output_path: Optional[str] = None,
    title: str = "VaultKey Report",
) -> str:
    """Export data to a formatted plain text report.

    Args:
        data: The data to export (dictionary or list of dictionaries).
        output_path: Optional file path to write the text to.
                    If None, returns the text string.
        title: Title for the report.

    Returns:
        The formatted text string.

    Raises:
        IOError: If writing to the output path fails.
    """
    lines: List[str] = []
    separator = "=" * 60
    thin_sep = "-" * 60

    lines.append(separator)
    lines.append(f"  {title}")
    lines.append(f"  Generated: {_get_timestamp()}")
    lines.append(separator)
    lines.append("")

    if isinstance(data, list):
        for i, item in enumerate(data, 1):
            lines.append(f"--- Entry #{i} ---")
            _dict_to_text(item, lines)
            lines.append("")
    elif isinstance(data, dict):
        _dict_to_text(data, lines)
    else:
        lines.append(str(data))

    lines.append("")
    lines.append(separator)
    lines.append("  End of Report")
    lines.append(separator)

    text = "\n".join(lines)

    if output_path:
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(text)

    return text


def _dict_to_text(d: Dict[str, Any], lines: List[str], indent: int = 2) -> None:
    """Recursively format a dictionary into text lines.

    Args:
        d: The dictionary to format.
        lines: The list to append formatted lines to.
        indent: Current indentation level.
    """
    prefix = " " * indent
    for key, value in d.items():
        if isinstance(value, dict):
            lines.append(f"{prefix}{key}:")
            _dict_to_text(value, lines, indent + 2)
        elif isinstance(value, list):
            lines.append(f"{prefix}{key}:")
            for item in value:
                if isinstance(item, dict):
                    _dict_to_text(item, lines, indent + 2)
                else:
                    lines.append(f"{prefix}  - {item}")
        elif isinstance(value, bool):
            lines.append(f"{prefix}{key}: {'Yes' if value else 'No'}")
        else:
            lines.append(f"{prefix}{key}: {value}")


def export_analysis_results(
    results: List[AnalysisResult],
    format: str = "json",
    output_path: Optional[str] = None,
) -> str:
    """Export password analysis results to the specified format.

    Args:
        results: A list of AnalysisResult objects.
        format: Output format - 'json', 'csv', or 'txt'.
        output_path: Optional file path to write the report to.

    Returns:
        The formatted report string.

    Raises:
        ValueError: If the format is not supported.
    """
    data = [r.to_dict() for r in results]

    # Add metadata
    report_data = {
        "report_type": "password_analysis",
        "generated_at": _get_timestamp(),
        "total_passwords": len(results),
        "results": data,
    }

    if format == "json":
        return export_json(report_data, output_path)
    elif format == "csv":
        # Flatten for CSV
        flat_data = []
        for item in data:
            flat = {"password_masked": item["password_masked"]}
            flat.update({k: v for k, v in item.items() if k != "password_masked"})
            # Flatten nested dicts
            if "character_types" in item:
                for k, v in item["character_types"].items():
                    flat[f"char_type_{k}"] = v
            if "patterns" in item:
                for k, v in item["patterns"].items():
                    flat[f"pattern_{k}"] = v
            flat_data.append(flat)

        fields = [
            "password_masked", "length", "score", "grade", "strength",
            "entropy_bits", "crack_time", "charset_size",
            "is_common_password",
        ]
        # Add any additional fields that exist
        for item in flat_data:
            for key in item:
                if key not in fields:
                    fields.append(key)

        return export_csv(flat_data, output_path, fields)
    elif format == "txt":
        return export_text(data, output_path, "Password Analysis Report")
    else:
        raise ValueError(f"Unsupported format: '{format}'. Use 'json', 'csv', or 'txt'.")


def export_audit_results(
    results: List[AuditResult],
    format: str = "json",
    output_path: Optional[str] = None,
) -> str:
    """Export password audit results to the specified format.

    Args:
        results: A list of AuditResult objects.
        format: Output format - 'json', 'csv', or 'txt'.
        output_path: Optional file path to write the report to.

    Returns:
        The formatted report string.

    Raises:
        ValueError: If the format is not supported.
    """
    data = [r.to_dict() for r in results]

    report_data = {
        "report_type": "password_audit",
        "generated_at": _get_timestamp(),
        "total_passwords": len(results),
        "results": data,
    }

    if format == "json":
        return export_json(report_data, output_path)
    elif format == "csv":
        flat_data = []
        for item in data:
            flat = {
                "password_masked": item["password_masked"],
                "overall_status": item["overall_status"],
                "passed": item["passed"],
                "failed": item["failed"],
                "warnings": item["warnings"],
            }
            flat_data.append(flat)

        fields = ["password_masked", "overall_status", "passed", "failed", "warnings"]
        return export_csv(flat_data, output_path, fields)
    elif format == "txt":
        return export_text(data, output_path, "Password Audit Report")
    else:
        raise ValueError(f"Unsupported format: '{format}'. Use 'json', 'csv', or 'txt'.")


def export_breach_results(
    results: List[BreachCheckResult],
    format: str = "json",
    output_path: Optional[str] = None,
) -> str:
    """Export breach check results to the specified format.

    Args:
        results: A list of BreachCheckResult objects.
        format: Output format - 'json', 'csv', or 'txt'.
        output_path: Optional file path to write the report to.

    Returns:
        The formatted report string.

    Raises:
        ValueError: If the format is not supported.
    """
    data = [r.to_dict() for r in results]

    report_data = {
        "report_type": "breach_check",
        "generated_at": _get_timestamp(),
        "total_passwords": len(results),
        "breached_count": sum(1 for r in results if r.found),
        "safe_count": sum(1 for r in results if not r.found),
        "results": data,
    }

    if format == "json":
        return export_json(report_data, output_path)
    elif format == "csv":
        fields = ["password_masked", "sha1_prefix", "found", "occurrences", "message"]
        flat_data = []
        for item in data:
            flat_data.append(item)
        return export_csv(flat_data, output_path, fields)
    elif format == "txt":
        return export_text(data, output_path, "Breach Check Report")
    else:
        raise ValueError(f"Unsupported format: '{format}'. Use 'json', 'csv', or 'txt'.")
