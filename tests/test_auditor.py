"""
Tests for the password auditor module.
"""

import os
import tempfile
import unittest

from vaultkey.auditor import (
    AuditStatus,
    PasswordAuditor,
)
from vaultkey.config import POLICY_TEMPLATES


class TestPasswordAuditor(unittest.TestCase):
    """Test cases for the PasswordAuditor class."""

    def setUp(self):
        """Set up test fixtures."""
        self.custom_policy = POLICY_TEMPLATES["custom"]
        self.nist_policy = POLICY_TEMPLATES["nist"]
        self.auditor = PasswordAuditor(self.custom_policy)

    def test_empty_password_fails(self):
        """Test that empty password fails audit."""
        result = self.auditor.audit("")
        self.assertEqual(result.overall_status, AuditStatus.FAIL)
        self.assertGreater(result.failed, 0)

    def test_short_password_fails_min_length(self):
        """Test that a too-short password fails minimum length check."""
        result = self.auditor.audit("abc")
        check_names = [c.name for c in result.checks]
        self.assertIn("Minimum Length", check_names)
        min_len_check = next(c for c in result.checks if c.name == "Minimum Length")
        self.assertEqual(min_len_check.status, AuditStatus.FAIL)

    def test_long_enough_password_passes_min_length(self):
        """Test that a sufficiently long password passes minimum length."""
        result = self.auditor.audit("abcdefgh")
        min_len_check = next(c for c in result.checks if c.name == "Minimum Length")
        self.assertEqual(min_len_check.status, AuditStatus.PASS)

    def test_common_password_detected(self):
        """Test that common passwords are detected."""
        result = self.auditor.audit("123456")
        common_check = next(
            (c for c in result.checks if c.name == "Common Password"), None
        )
        self.assertIsNotNone(common_check)
        self.assertEqual(common_check.status, AuditStatus.FAIL)

    def test_non_common_password_passes(self):
        """Test that non-common passwords pass the common check."""
        result = self.auditor.audit("Xk9#mLp2$vRnQw")
        common_check = next(
            (c for c in result.checks if c.name == "Common Password"), None
        )
        if common_check:
            self.assertEqual(common_check.status, AuditStatus.PASS)

    def test_username_in_password_detected(self):
        """Test that username in password is detected."""
        auditor = PasswordAuditor({
            **self.custom_policy,
            "block_username": True,
        })
        result = auditor.audit("myuser123", username="myuser")
        username_check = next(
            (c for c in result.checks if c.name == "Username Check"), None
        )
        self.assertIsNotNone(username_check)
        self.assertEqual(username_check.status, AuditStatus.FAIL)

    def test_username_not_in_password_passes(self):
        """Test that password without username passes."""
        auditor = PasswordAuditor({
            **self.custom_policy,
            "block_username": True,
        })
        result = auditor.audit("randompass123", username="myuser")
        username_check = next(
            (c for c in result.checks if c.name == "Username Check"), None
        )
        if username_check:
            self.assertEqual(username_check.status, AuditStatus.PASS)

    def test_uppercase_requirement(self):
        """Test uppercase requirement enforcement."""
        auditor = PasswordAuditor({
            **self.custom_policy,
            "require_uppercase": True,
        })
        result = auditor.audit("abcdefgh")
        upper_check = next(
            (c for c in result.checks if c.name == "Uppercase Required"), None
        )
        self.assertIsNotNone(upper_check)
        self.assertEqual(upper_check.status, AuditStatus.FAIL)

    def test_uppercase_requirement_pass(self):
        """Test that password with uppercase passes uppercase requirement."""
        auditor = PasswordAuditor({
            **self.custom_policy,
            "require_uppercase": True,
        })
        result = auditor.audit("Abcdefgh")
        upper_check = next(
            (c for c in result.checks if c.name == "Uppercase Required"), None
        )
        self.assertIsNotNone(upper_check)
        self.assertEqual(upper_check.status, AuditStatus.PASS)

    def test_nist_policy(self):
        """Test auditing with NIST policy."""
        auditor = PasswordAuditor(self.nist_policy)
        result = auditor.audit("12345678")
        # NIST doesn't require specific char types, but blocks common passwords
        common_check = next(
            (c for c in result.checks if c.name == "Common Password"), None
        )
        self.assertIsNotNone(common_check)

    def test_pci_dss_policy(self):
        """Test auditing with PCI-DSS policy."""
        pci_policy = POLICY_TEMPLATES["pci-dss"]
        auditor = PasswordAuditor(pci_policy)
        # Short password should fail multiple checks
        result = auditor.audit("short")
        self.assertEqual(result.overall_status, AuditStatus.FAIL)

    def test_strict_policy_strong_password(self):
        """Test that a strong password passes the strict policy."""
        strict_policy = POLICY_TEMPLATES["strict"]
        auditor = PasswordAuditor(strict_policy)
        result = auditor.audit("X#9kL!mP2$vR@nQ7w")
        # Should have no failures (might have warnings)
        self.assertEqual(result.failed, 0)

    def test_batch_audit(self):
        """Test batch auditing of multiple passwords."""
        passwords = ["abc", "12345678", "StrongP@ss1!"]
        results = self.auditor.audit_batch(passwords)
        self.assertEqual(len(results), 3)

    def test_audit_file(self):
        """Test auditing passwords from a file."""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".txt", delete=False, encoding="utf-8"
        ) as f:
            f.write("password1\n")
            f.write("StrongP@ss1!\n")
            f.write("123456\n")
            filepath = f.name

        try:
            results = self.auditor.audit_file(filepath)
            self.assertEqual(len(results), 3)
        finally:
            os.unlink(filepath)

    def test_result_to_dict(self):
        """Test that AuditResult.to_dict returns a valid dictionary."""
        result = self.auditor.audit("testpassword")
        d = result.to_dict()
        self.assertIsInstance(d, dict)
        self.assertIn("overall_status", d)
        self.assertIn("passed", d)
        self.assertIn("failed", d)
        self.assertIn("warnings", d)
        self.assertIn("checks", d)

    def test_set_policy(self):
        """Test that set_policy changes the active policy."""
        self.auditor.set_policy(self.nist_policy)
        result = self.auditor.audit("testpassword123")
        # Verify checks are based on NIST policy
        check_names = [c.name for c in result.checks]
        self.assertIn("Minimum Length", check_names)

    def test_keyboard_pattern_warning(self):
        """Test that keyboard patterns generate a warning."""
        result = self.auditor.audit("qwertyuiop")
        kb_check = next(
            (c for c in result.checks if c.name == "Keyboard Pattern"), None
        )
        self.assertIsNotNone(kb_check)
        self.assertEqual(kb_check.status, AuditStatus.WARN)


if __name__ == "__main__":
    unittest.main()
