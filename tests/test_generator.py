"""
Tests for the password generator module.
"""

import string
import unittest

from vaultkey.generator import (
    generate_batch,
    generate_passphrase,
    generate_password,
    generate_pin,
    WORD_LIST,
)


class TestGeneratePassword(unittest.TestCase):
    """Test cases for the generate_password function."""

    def test_default_length(self):
        """Test that default password generation returns correct length."""
        password = generate_password()
        self.assertEqual(len(password), 16)

    def test_custom_length(self):
        """Test generating passwords with custom lengths."""
        for length in [8, 12, 20, 32, 64]:
            password = generate_password(length=length)
            self.assertEqual(len(password), length)

    def test_minimum_length(self):
        """Test generating a password of length 1."""
        password = generate_password(length=1)
        self.assertEqual(len(password), 1)

    def test_zero_length_raises(self):
        """Test that zero length raises ValueError."""
        with self.assertRaises(ValueError):
            generate_password(length=0)

    def test_contains_uppercase(self):
        """Test that password contains uppercase when enabled."""
        password = generate_password(
            length=20,
            charset_config={"uppercase": True, "lowercase": False, "digits": False, "symbols": False},
        )
        self.assertTrue(any(c.isupper() for c in password))
        self.assertTrue(all(c.isupper() for c in password))

    def test_contains_lowercase(self):
        """Test that password contains lowercase when enabled."""
        password = generate_password(
            length=20,
            charset_config={"uppercase": False, "lowercase": True, "digits": False, "symbols": False},
        )
        self.assertTrue(any(c.islower() for c in password))

    def test_contains_digits(self):
        """Test that password contains digits when enabled."""
        password = generate_password(
            length=20,
            charset_config={"uppercase": False, "lowercase": False, "digits": True, "symbols": False},
        )
        self.assertTrue(any(c.isdigit() for c in password))

    def test_contains_symbols(self):
        """Test that password contains symbols when enabled."""
        password = generate_password(
            length=20,
            charset_config={"uppercase": False, "lowercase": False, "digits": False, "symbols": True},
        )
        self.assertTrue(any(c in "!@#$%^&*()-_=+[]{}|;:,.<>?/~`" for c in password))

    def test_exclude_ambiguous(self):
        """Test that ambiguous characters are excluded when requested."""
        ambiguous = {"0", "O", "o", "1", "l", "I", "|", "`", "'", '"'}
        password = generate_password(length=50, exclude_ambiguous=True)
        for c in password:
            self.assertNotIn(c, ambiguous)

    def test_no_repeating(self):
        """Test that no consecutive repeating characters when enabled."""
        password = generate_password(length=20, no_repeating=True)
        for i in range(1, len(password)):
            self.assertNotEqual(password[i], password[i - 1])

    def test_no_repeating_small_charset_raises(self):
        """Test that no_repeating with too small charset raises ValueError."""
        with self.assertRaises(ValueError):
            generate_password(
                length=30,
                no_repeating=True,
                charset_config={"uppercase": True, "lowercase": False, "digits": False, "symbols": False},
            )

    def test_no_charset_enabled_raises(self):
        """Test that disabling all charsets raises ValueError."""
        with self.assertRaises(ValueError):
            generate_password(
                charset_config={"uppercase": False, "lowercase": False, "digits": False, "symbols": False},
            )

    def test_all_charsets_coverage(self):
        """Test that all enabled charsets are represented in password."""
        for _ in range(20):  # Run multiple times due to randomness
            password = generate_password(length=30)
            self.assertTrue(any(c.isupper() for c in password), "Missing uppercase")
            self.assertTrue(any(c.islower() for c in password), "Missing lowercase")
            self.assertTrue(any(c.isdigit() for c in password), "Missing digits")
            self.assertTrue(
                any(c in "!@#$%^&*()-_=+[]{}|;:,.<>?/~`" for c in password),
                "Missing symbols",
            )

    def test_uniqueness(self):
        """Test that generated passwords are not all identical."""
        passwords = set()
        for _ in range(20):
            passwords.add(generate_password(length=16))
        self.assertGreater(len(passwords), 1)

    def test_charset_config_none_uses_default(self):
        """Test that None charset_config uses all charsets."""
        password = generate_password(length=30, charset_config=None)
        self.assertTrue(any(c.isupper() for c in password))
        self.assertTrue(any(c.islower() for c in password))
        self.assertTrue(any(c.isdigit() for c in password))


class TestGeneratePassphrase(unittest.TestCase):
    """Test cases for the generate_passphrase function."""

    def test_default_words(self):
        """Test that default passphrase has 4 words."""
        passphrase = generate_passphrase()
        words = passphrase.split("-")
        self.assertEqual(len(words), 4)

    def test_custom_word_count(self):
        """Test passphrase with custom word count."""
        for count in [3, 5, 8]:
            passphrase = generate_passphrase(num_words=count)
            words = passphrase.split("-")
            self.assertEqual(len(words), count)

    def test_custom_separator(self):
        """Test passphrase with custom separator."""
        passphrase = generate_passphrase(separator="_")
        words = passphrase.split("_")
        self.assertEqual(len(words), 4)

    def test_capitalize(self):
        """Test that capitalize option capitalizes each word."""
        passphrase = generate_passphrase(capitalize=True)
        words = passphrase.split("-")
        for word in words:
            self.assertTrue(word[0].isupper())

    def test_no_capitalize(self):
        """Test that words are lowercase by default."""
        passphrase = generate_passphrase()
        words = passphrase.split("-")
        for word in words:
            self.assertTrue(word.islower())

    def test_single_word(self):
        """Test passphrase with 1 word."""
        passphrase = generate_passphrase(num_words=1)
        self.assertIn(passphrase, WORD_LIST)

    def test_zero_words_raises(self):
        """Test that zero words raises ValueError."""
        with self.assertRaises(ValueError):
            generate_passphrase(num_words=0)

    def test_too_many_words_raises(self):
        """Test that requesting more words than available raises ValueError."""
        with self.assertRaises(ValueError):
            generate_passphrase(num_words=len(WORD_LIST) + 1)


class TestGeneratePin(unittest.TestCase):
    """Test cases for the generate_pin function."""

    def test_default_pin(self):
        """Test default PIN generation."""
        pin = generate_pin()
        self.assertEqual(len(pin), 4)
        self.assertTrue(pin.isdigit())

    def test_custom_length(self):
        """Test PIN with custom length."""
        for length in [4, 6, 8]:
            pin = generate_pin(length=length)
            self.assertEqual(len(pin), length)
            self.assertTrue(pin.isdigit())

    def test_zero_length_raises(self):
        """Test that zero length raises ValueError."""
        with self.assertRaises(ValueError):
            generate_pin(length=0)

    def test_too_long_raises(self):
        """Test that length > 32 raises ValueError."""
        with self.assertRaises(ValueError):
            generate_pin(length=33)


class TestGenerateBatch(unittest.TestCase):
    """Test cases for the generate_batch function."""

    def test_batch_passwords(self):
        """Test batch password generation."""
        passwords = generate_batch(count=5, mode="password", length=16)
        self.assertEqual(len(passwords), 5)
        for pwd in passwords:
            self.assertEqual(len(pwd), 16)

    def test_batch_passphrases(self):
        """Test batch passphrase generation."""
        phrases = generate_batch(count=3, mode="passphrase", num_words=3)
        self.assertEqual(len(phrases), 3)

    def test_batch_pins(self):
        """Test batch PIN generation."""
        pins = generate_batch(count=10, mode="pin", length=6)
        self.assertEqual(len(pins), 10)
        for pin in pins:
            self.assertEqual(len(pin), 6)
            self.assertTrue(pin.isdigit())

    def test_zero_count_raises(self):
        """Test that zero count raises ValueError."""
        with self.assertRaises(ValueError):
            generate_batch(count=0, mode="password")

    def test_invalid_mode_raises(self):
        """Test that invalid mode raises ValueError."""
        with self.assertRaises(ValueError):
            generate_batch(count=1, mode="invalid")

    def test_batch_uniqueness(self):
        """Test that batch passwords are not all identical."""
        passwords = generate_batch(count=20, mode="password", length=16)
        self.assertGreater(len(set(passwords)), 1)


if __name__ == "__main__":
    unittest.main()
