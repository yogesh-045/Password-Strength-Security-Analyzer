"""
Unit tests for Password Strength & Security Analyzer.

Run:
    python -m unittest test_password_checker.py
"""

import unittest

from password_checker import (
    calculate_character_pool,
    calculate_entropy,
    detect_common_password,
    detect_patterns,
    calculate_score,
    classify_strength,
    generate_recommendations,
    analyze_password,
)


class TestPasswordChecker(unittest.TestCase):

    def test_empty_password_entropy(self):
        self.assertEqual(
            calculate_entropy(""),
            0.0
        )

    def test_character_pool_lowercase(self):
        self.assertEqual(
            calculate_character_pool("abcdef"),
            26
        )

    def test_character_pool_uppercase(self):
        self.assertEqual(
            calculate_character_pool("ABCDEF"),
            26
        )

    def test_character_pool_digits(self):
        self.assertEqual(
            calculate_character_pool("123456"),
            10
        )

    def test_character_pool_mixed(self):
        self.assertEqual(
            calculate_character_pool("Abc123!"),
            95
        )

    def test_entropy_increases_with_length(self):
        short_entropy = calculate_entropy("abc")
        long_entropy = calculate_entropy("abcdefghijk")

        self.assertGreater(
            long_entropy,
            short_entropy
        )

    def test_common_password_detection(self):
        self.assertTrue(
            detect_common_password("password")
        )

    def test_common_password_case_insensitive(self):
        self.assertTrue(
            detect_common_password("PASSWORD")
        )

    def test_non_common_password(self):
        self.assertFalse(
            detect_common_password(
                "A7$xK92!mQp4"
            )
        )

    def test_repeated_character_detection(self):
        patterns = detect_patterns("aaaPassword123!")

        self.assertIn(
            "Repeated characters detected",
            patterns
        )

    def test_sequential_number_detection(self):
        patterns = detect_patterns("Secure123Password!")

        self.assertIn(
            "Sequential numbers detected",
            patterns
        )

    def test_keyboard_pattern_detection(self):
        patterns = detect_patterns("QwertyPassword123!")

        self.assertIn(
            "Keyboard pattern detected",
            patterns
        )

    def test_secure_password_has_multiple_character_types(self):
        result = analyze_password(
            "V9!xK7@pL2#qM8"
        )

        self.assertTrue(result["has_uppercase"])
        self.assertTrue(result["has_lowercase"])
        self.assertTrue(result["has_digit"])
        self.assertTrue(result["has_special"])

    def test_short_password_is_very_weak(self):
        result = analyze_password("abc")

        self.assertEqual(
            result["strength"],
            "Very Weak"
        )

    def test_common_password_penalty(self):
        common_result = analyze_password("password")
        uncommon_result = analyze_password(
            "A9$xK7!mQ2#zL8"
        )

        self.assertLess(
            common_result["score"],
            uncommon_result["score"]
        )

    def test_score_range(self):
        result = analyze_password(
            "A9$xK7!mQ2#zL8"
        )

        self.assertGreaterEqual(
            result["score"],
            0
        )

        self.assertLessEqual(
            result["score"],
            100
        )

    def test_strength_classification(self):
        self.assertEqual(
            classify_strength(20, "abcdefgh"),
            "Weak"
        )

        self.assertEqual(
            classify_strength(50, "Abcdef1234"),
            "Moderate"
        )

        self.assertEqual(
            classify_strength(70, "Abcdef1234!"),
            "Strong"
        )

        self.assertEqual(
            classify_strength(90, "Abcdef1234!xyz"),
            "Very Strong"
        )

    def test_recommendations_for_weak_password(self):
        result = analyze_password("abc")

        self.assertGreater(
            len(result["recommendations"]),
            0
        )

    def test_recommendations_for_secure_password(self):
        recommendations = generate_recommendations(
            "A9$xK7!mQ2#zL8",
            False,
            [],
            80,
        )

        self.assertEqual(
            recommendations,
            [
                "Password meets the analyzer's security criteria."
            ]
        )

    def test_analyze_password_returns_expected_keys(self):
        result = analyze_password(
            "TestPassword123!"
        )

        expected_keys = {
            "length",
            "has_uppercase",
            "has_lowercase",
            "has_digit",
            "has_special",
            "character_pool",
            "entropy",
            "common_password",
            "patterns",
            "score",
            "strength",
            "recommendations",
        }

        self.assertEqual(
            set(result.keys()),
            expected_keys
        )

    def test_non_string_password(self):
        with self.assertRaises(TypeError):
            analyze_password(123456)


if __name__ == "__main__":
    unittest.main()
