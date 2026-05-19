"""
Tests for the entropy calculation module.
"""

import math
import unittest

from vaultkey.entropy import (
    EntropyResult,
    charset_entropy,
    effective_entropy,
    shannon_entropy,
)


class TestShannonEntropy(unittest.TestCase):
    """Test cases for the shannon_entropy function."""

    def test_empty_string(self):
        """Test that empty string returns 0 entropy."""
        self.assertEqual(shannon_entropy(""), 0.0)

    def test_single_char(self):
        """Test that single character returns 0 entropy (no uncertainty)."""
        self.assertEqual(shannon_entropy("a"), 0.0)

    def test_repeated_char(self):
        """Test that repeated characters return 0 entropy."""
        self.assertEqual(shannon_entropy("aaaaaa"), 0.0)

    def test_two_unique_chars(self):
        """Test entropy with two equally likely characters."""
        # For "ab", each has probability 0.5
        # H = -2 * (0.5 * log2(0.5)) = 1.0
        result = shannon_entropy("ab")
        self.assertAlmostEqual(result, 1.0, places=5)

    def test_uniform_distribution(self):
        """Test entropy with uniform distribution over full alphabet."""
        # All 26 lowercase letters should give close to log2(26) ~ 4.7
        result = shannon_entropy("abcdefghijklmnopqrstuvwxyz")
        self.assertAlmostEqual(result, math.log2(26), places=2)

    def test_non_negative(self):
        """Test that entropy is always non-negative."""
        for s in ["a", "ab", "abc", "aabbcc", "xyz123"]:
            self.assertGreaterEqual(shannon_entropy(s), 0.0)

    def test_max_entropy_per_char(self):
        """Test that entropy never exceeds log2(charset_size)."""
        import string
        all_chars = string.ascii_letters + string.digits + string.punctuation
        result = shannon_entropy(all_chars)
        self.assertLessEqual(result, math.log2(len(all_chars)) + 0.01)


class TestCharsetEntropy(unittest.TestCase):
    """Test cases for the charset_entropy function."""

    def test_empty_string(self):
        """Test that empty string returns 0 entropy."""
        self.assertEqual(charset_entropy(""), 0.0)

    def test_lowercase_only(self):
        """Test entropy for lowercase-only password."""
        # 8 lowercase chars: 8 * log2(26) ~ 37.6
        result = charset_entropy("abcdefgh")
        expected = 8 * math.log2(26)
        self.assertAlmostEqual(result, expected, places=2)

    def test_digits_only(self):
        """Test entropy for digits-only password."""
        # 6 digits: 6 * log2(10) ~ 19.93
        result = charset_entropy("123456")
        expected = 6 * math.log2(10)
        self.assertAlmostEqual(result, expected, places=2)

    def test_mixed_charset(self):
        """Test entropy for mixed character types."""
        # "Ab1!" has uppercase, lowercase, digits, symbols
        # charset_size = 26 + 26 + 10 + 29 = 91
        result = charset_entropy("Ab1!")
        expected = 4 * math.log2(91)
        self.assertAlmostEqual(result, expected, places=2)

    def test_longer_password_higher_entropy(self):
        """Test that longer passwords have higher entropy."""
        short = charset_entropy("abc")
        long = charset_entropy("abcdefghijklmnopqrstuvwxyz")
        self.assertGreater(long, short)


class TestEffectiveEntropy(unittest.TestCase):
    """Test cases for the effective_entropy function."""

    def test_empty_string(self):
        """Test that empty string returns 0 effective entropy."""
        result = effective_entropy("")
        self.assertEqual(result.effective_entropy, 0.0)
        self.assertEqual(result.charset_size, 0)

    def test_returns_entropy_result(self):
        """Test that effective_entropy returns an EntropyResult."""
        result = effective_entropy("test123")
        self.assertIsInstance(result, EntropyResult)

    def test_strong_password_higher_entropy(self):
        """Test that strong password has higher effective entropy."""
        strong = effective_entropy("X#9kL!mP2$vR@nQ7w")
        weak = effective_entropy("aaaaaa")
        self.assertGreater(strong.effective_entropy, weak.effective_entropy)

    def test_sequential_pattern_reduces_entropy(self):
        """Test that sequential patterns reduce effective entropy."""
        normal = effective_entropy("xk9mlp2vrnqw")
        sequential = effective_entropy("abcdefghij")
        self.assertLess(sequential.effective_entropy, normal.effective_entropy)

    def test_keyboard_pattern_reduces_entropy(self):
        """Test that keyboard patterns reduce effective entropy."""
        normal = effective_entropy("xk9mlp2vrnqw")
        keyboard = effective_entropy("qwertyuiop")
        self.assertLess(keyboard.effective_entropy, normal.effective_entropy)

    def test_repeated_chars_reduce_entropy(self):
        """Test that repeated characters reduce effective entropy."""
        # Use a password with repeated chars but no sequential patterns
        normal = effective_entropy("xk9mlp2vrnqw")
        repeated = effective_entropy("xxk9mlp2vrnq")
        self.assertLess(repeated.effective_entropy, normal.effective_entropy)

    def test_entropy_non_negative(self):
        """Test that effective entropy is never negative."""
        for pwd in ["a", "abc", "qwerty", "12345678", "Abc!@#"]:
            result = effective_entropy(pwd)
            self.assertGreaterEqual(result.effective_entropy, 0.0)

    def test_charset_size_detected(self):
        """Test that charset size is correctly detected."""
        # Lowercase only: 26
        result = effective_entropy("abc")
        self.assertEqual(result.charset_size, 26)

        # Lowercase + digits: 36
        result = effective_entropy("abc123")
        self.assertEqual(result.charset_size, 36)

    def test_to_dict(self):
        """Test that EntropyResult.to_dict returns a valid dictionary."""
        result = effective_entropy("test123")
        d = result.to_dict()
        self.assertIsInstance(d, dict)
        self.assertIn("shannon_entropy", d)
        self.assertIn("charset_entropy", d)
        self.assertIn("effective_entropy", d)
        self.assertIn("charset_size", d)
        self.assertIn("pattern_deductions", d)

    def test_pattern_deductions_list(self):
        """Test that pattern deductions are returned as a list."""
        result = effective_entropy("qwerty")
        self.assertIsInstance(result.pattern_deductions, list)


if __name__ == "__main__":
    unittest.main()
