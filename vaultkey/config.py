"""
Configuration management module for VaultKey.

Handles loading, saving, and managing user configuration stored in
~/.vaultkey/config.json. Provides default settings and policy templates.
"""

import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional


DEFAULT_CONFIG_DIR = Path.home() / ".vaultkey"
DEFAULT_CONFIG_FILE = DEFAULT_CONFIG_DIR / "config.json"

# Default password generation settings
DEFAULT_GENERATION = {
    "length": 16,
    "uppercase": True,
    "lowercase": True,
    "digits": True,
    "symbols": True,
    "exclude_ambiguous": False,
    "no_repeating": False,
    "min_length": 8,
    "max_length": 128,
}

# Default passphrase settings
DEFAULT_PASSPHRASE = {
    "num_words": 4,
    "separator": "-",
    "capitalize": False,
}

# Default PIN settings
DEFAULT_PIN = {
    "length": 4,
}

# Default analysis settings
DEFAULT_ANALYSIS = {
    "scoring_standard": "nist",
}

# Default audit settings
DEFAULT_AUDIT = {
    "policy": "custom",
}

# Policy templates
POLICY_TEMPLATES: Dict[str, Dict[str, Any]] = {
    "nist": {
        "name": "NIST SP 800-63B",
        "description": "NIST Special Publication 800-63B guidelines",
        "min_length": 8,
        "max_length": 64,
        "require_uppercase": False,
        "require_lowercase": False,
        "require_digits": False,
        "require_symbols": False,
        "block_common_passwords": True,
        "block_username": True,
        "block_sequential": True,
        "block_repeated": True,
        "min_entropy": 0,
    },
    "pci-dss": {
        "name": "PCI-DSS v3.2.1",
        "description": "Payment Card Industry Data Security Standard",
        "min_length": 12,
        "max_length": 128,
        "require_uppercase": True,
        "require_lowercase": True,
        "require_digits": True,
        "require_symbols": True,
        "block_common_passwords": True,
        "block_username": True,
        "block_sequential": True,
        "block_repeated": True,
        "min_entropy": 60,
    },
    "strict": {
        "name": "Strict",
        "description": "Maximum security policy",
        "min_length": 16,
        "max_length": 128,
        "require_uppercase": True,
        "require_lowercase": True,
        "require_digits": True,
        "require_symbols": True,
        "block_common_passwords": True,
        "block_username": True,
        "block_sequential": True,
        "block_repeated": True,
        "min_entropy": 80,
    },
    "custom": {
        "name": "Custom",
        "description": "User-defined policy",
        "min_length": 8,
        "max_length": 128,
        "require_uppercase": False,
        "require_lowercase": False,
        "require_digits": False,
        "require_symbols": False,
        "block_common_passwords": True,
        "block_username": True,
        "block_sequential": False,
        "block_repeated": False,
        "min_entropy": 0,
    },
}


class ConfigManager:
    """Manages VaultKey configuration loading, saving, and access.

    Attributes:
        config_path: Path to the configuration file.
        config: The current configuration dictionary.
    """

    def __init__(self, config_path: Optional[Path] = None) -> None:
        """Initialize the ConfigManager.

        Args:
            config_path: Optional path to the configuration file.
                         Defaults to ~/.vaultkey/config.json.
        """
        self.config_path = config_path or DEFAULT_CONFIG_FILE
        self.config: Dict[str, Any] = self._load_config()

    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from file, or create default if not exists.

        Returns:
            The configuration dictionary.
        """
        if self.config_path.exists():
            try:
                with open(self.config_path, "r", encoding="utf-8") as f:
                    loaded = json.load(f)
                # Merge with defaults to ensure all keys exist
                return self._merge_with_defaults(loaded)
            except (json.JSONDecodeError, IOError):
                return self._default_config()
        return self._default_config()

    def _default_config(self) -> Dict[str, Any]:
        """Return the default configuration dictionary.

        Returns:
            A dictionary containing all default settings.
        """
        return {
            "generation": dict(DEFAULT_GENERATION),
            "passphrase": dict(DEFAULT_PASSPHRASE),
            "pin": dict(DEFAULT_PIN),
            "analysis": dict(DEFAULT_ANALYSIS),
            "audit": dict(DEFAULT_AUDIT),
            "policies": POLICY_TEMPLATES,
        }

    def _merge_with_defaults(self, loaded: Dict[str, Any]) -> Dict[str, Any]:
        """Merge loaded configuration with defaults to fill missing keys.

        Args:
            loaded: The configuration loaded from file.

        Returns:
            A merged configuration dictionary with all keys present.
        """
        defaults = self._default_config()
        for key in defaults:
            if key not in loaded:
                loaded[key] = defaults[key]
            elif isinstance(defaults[key], dict) and isinstance(loaded[key], dict):
                for subkey in defaults[key]:
                    if subkey not in loaded[key]:
                        loaded[key][subkey] = defaults[key][subkey]
        return loaded

    def save(self) -> None:
        """Save the current configuration to file.

        Creates the config directory if it does not exist.
        """
        self.config_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.config_path, "w", encoding="utf-8") as f:
            json.dump(self.config, f, indent=2, ensure_ascii=False)

    def get(self, key: str, default: Any = None) -> Any:
        """Get a configuration value by key.

        Args:
            key: The configuration key (supports dot notation, e.g. 'generation.length').
            default: Default value if key is not found.

        Returns:
            The configuration value, or the default.
        """
        keys = key.split(".")
        value: Any = self.config
        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default
        return value

    def set(self, key: str, value: Any) -> None:
        """Set a configuration value by key.

        Args:
            key: The configuration key (supports dot notation, e.g. 'generation.length').
            value: The value to set.
        """
        keys = key.split(".")
        config = self.config
        for k in keys[:-1]:
            if k not in config or not isinstance(config[k], dict):
                config[k] = {}
            config = config[k]
        config[keys[-1]] = value

    def get_policy(self, policy_name: str) -> Dict[str, Any]:
        """Get a policy template by name.

        Args:
            policy_name: The name of the policy (e.g. 'nist', 'pci-dss').

        Returns:
            The policy dictionary.

        Raises:
            ValueError: If the policy name is not found.
        """
        policies = self.config.get("policies", POLICY_TEMPLATES)
        if policy_name not in policies:
            available = ", ".join(policies.keys())
            raise ValueError(
                f"Unknown policy '{policy_name}'. Available policies: {available}"
            )
        return dict(policies[policy_name])

    def list_policies(self) -> List[Dict[str, str]]:
        """List all available policy templates.

        Returns:
            A list of dictionaries with policy name and description.
        """
        policies = self.config.get("policies", POLICY_TEMPLATES)
        return [
            {"name": name, "description": info.get("description", "")}
            for name, info in policies.items()
        ]

    def show(self) -> Dict[str, Any]:
        """Return the full current configuration.

        Returns:
            The complete configuration dictionary.
        """
        return dict(self.config)
