"""
Tests for the password analyzer module.
"""

import unittest

from vaultkey.analyzer import (
    COMMON_PASSWORDS,
    analyze_batch,
    analyze_password,
    AnalysisResult,
)


class TestAnalyzePassword(unittest.TestCase):
    """Test cases for the analyze_password function."""

    def test_empty_password(self):
        """Test analysis of an empty password."""
        result = analyze_password("")
        self.assertEqual(result.score, 0)
        self.assertEqual(result.grade, "F")
        self.assertEqual(result.length, 0)

    def test_common_password_low_score(self):
        """Test that common passwords get low scores."""
        result = analyze_password("123456")
        self.assertLess(result.score, 20)
        self.assertTrue(result.is_common)

    def test_strong_password_high_score(self):
        """Test that a strong password gets a high score."""
        result = analyze_password("X#9kL!mP2$vR@nQ7w")
        self.assertGreater(result.score, 70)
        self.assertFalse(result.is_common)

    def test_password_length(self):
        """Test that length is correctly reported."""
        result = analyze_password("abc123")
        self.assertEqual(result.length, 6)

    def test_has_uppercase(self):
        """Test uppercase detection."""
        result = analyze_password("Abc123")
        self.assertTrue(result.has_uppercase)

    def test_no_uppercase(self):
        """Test absence of uppercase detection."""
        result = analyze_password("abc123")
        self.assertFalse(result.has_uppercase)

    def test_has_lowercase(self):
        """Test lowercase detection."""
        result = analyze_password("ABC123a")
        self.assertTrue(result.has_lowercase)

    def test_has_digits(self):
        """Test digit detection."""
        result = analyze_password("abcdef123")
        self.assertTrue(result.has_digits)

    def test_no_digits(self):
        """Test absence of digit detection."""
        result = analyze_password("abcdef")
        self.assertFalse(result.has_digits)

    def test_has_symbols(self):
        """Test symbol detection."""
        result = analyze_password("abc@123")
        self.assertTrue(result.has_symbols)

    def test_no_symbols(self):
        """Test absence of symbol detection."""
        result = analyze_password("abc123")
        self.assertFalse(result.has_symbols)

    def test_sequential_detection(self):
        """Test that sequential patterns are detected."""
        result = analyze_password("abcdef")
        self.assertGreater(len(result.sequential_found), 0)

    def test_keyboard_pattern_detection(self):
        """Test that keyboard patterns are detected."""
        result = analyze_password("qwerty")
        self.assertGreater(len(result.keyboard_found), 0)

    def test_repeated_chars_detection(self):
        """Test that repeated characters are detected."""
        result = analyze_password("aaabbb")
        self.assertGreater(len(result.repeated_found), 0)

    def test_score_range(self):
        """Test that score is always between 0 and 100."""
        for pwd in ["a", "abc", "abcdef", "Password1!", "X#9kL!mP2$vR@nQ7wZ"]:
            result = analyze_password(pwd)
            self.assertGreaterEqual(result.score, 0)
            self.assertLessEqual(result.score, 100)

    def test_grade_assignment(self):
        """Test that grades are correctly assigned."""
        # Very weak
        result = analyze_password("123456")
        self.assertIn(result.grade, ["D", "F"])
        # Strong
        result = analyze_password("X#9kL!mP2$vR@nQ7w")
        self.assertIn(result.grade, ["A", "B"])

    def test_entropy_bits_positive(self):
        """Test that entropy is positive for non-empty passwords."""
        result = analyze_password("abc123")
        self.assertGreater(result.entropy_bits, 0)

    def test_crack_time_not_empty(self):
        """Test that crack time is reported."""
        result = analyze_password("abc123")
        self.assertTrue(len(result.crack_time) > 0)

    def test_to_dict(self):
        """Test that to_dict returns a valid dictionary."""
        result = analyze_password("test123")
        d = result.to_dict()
        self.assertIsInstance(d, dict)
        self.assertIn("score", d)
        self.assertIn("length", d)
        self.assertIn("grade", d)
        self.assertIn("strength", d)

    def test_password_case_insensitive_common(self):
        """Test that common password check is case-insensitive."""
        result_lower = analyze_password("password")
        result_upper = analyze_password("PASSWORD")
        self.assertTrue(result_lower.is_common)
        self.assertTrue(result_upper.is_common)


class TestAnalyzeBatch(unittest.TestCase):
    """Test cases for batch password analysis."""

    def test_batch_returns_correct_count(self):
        """Test that batch analysis returns correct number of results."""
        passwords = ["abc", "123456", "StrongP@ss1"]
        results = analyze_batch(passwords)
        self.assertEqual(len(results), 3)

    def test_batch_all_analysis_results(self):
        """Test that all batch results are AnalysisResult instances."""
        passwords = ["a", "bb", "ccc"]
        results = analyze_batch(passwords)
        for result in results:
            self.assertIsInstance(result, AnalysisResult)


class TestCommonPasswordsList(unittest.TestCase):
    """Test cases for the common passwords list."""

    def test_list_not_empty(self):
        """Test that the common passwords list is not empty."""
        self.assertGreater(len(COMMON_PASSWORDS), 0)

    def test_list_minimum_size(self):
        """Test that the common passwords list has at least 100 entries."""
        self.assertGreaterEqual(len(COMMON_PASSWORDS), 100)

    def test_all_strings(self):
        """Test that all entries are strings."""
        for pwd in COMMON_PASSWORDS:
            self.assertIsInstance(pwd, str)

    def test_no_empty_strings(self):
        """Test that no entry is an empty string."""
        for pwd in COMMON_PASSWORDS:
            self.assertTrue(len(pwd) > 0)


if __name__ == "__main__":
    unittest.main()
