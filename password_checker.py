"""
Password Strength & Security Analyzer

Educational cybersecurity tool that evaluates password security
using length, character diversity, entropy estimation, common
password detection, pattern detection, and security recommendations.

No passwords are stored, logged, or transmitted.
"""

import math
import re
import getpass


# Common passwords used for basic educational detection.
COMMON_PASSWORDS = {
    "password",
    "password123",
    "123456",
    "12345678",
    "123456789",
    "1234567890",
    "qwerty",
    "qwerty123",
    "admin",
    "admin123",
    "letmein",
    "welcome",
    "welcome123",
    "iloveyou",
    "monkey",
    "dragon",
    "football",
    "abc123",
    "password1",
    "passw0rd",
}


def calculate_character_pool(password: str) -> int:
    """
    Estimate the character pool size based on character classes used.
    """

    pool_size = 0

    if re.search(r"[a-z]", password):
        pool_size += 26

    if re.search(r"[A-Z]", password):
        pool_size += 26

    if re.search(r"[0-9]", password):
        pool_size += 10

    if re.search(r"[^A-Za-z0-9]", password):
        pool_size += 33

    return pool_size


def calculate_entropy(password: str) -> float:
    """
    Estimate password entropy in bits.

    Formula:
        Entropy = log2(pool_size ^ password_length)

    Equivalent to:
        password_length * log2(pool_size)

    This is an estimate, not a guarantee of real-world password security.
    """

    if not password:
        return 0.0

    pool_size = calculate_character_pool(password)

    if pool_size == 0:
        return 0.0

    return len(password) * math.log2(pool_size)


def detect_common_password(password: str) -> bool:
    """
    Check whether the password is present in the local common-password list.
    """

    normalized = password.lower()

    return normalized in COMMON_PASSWORDS


def detect_patterns(password: str) -> list[str]:
    """
    Detect common weak password patterns.
    """

    patterns = []

    # Repeated character pattern: aaa, 111, !!!
    if re.search(r"(.)\1{2,}", password):
        patterns.append("Repeated characters detected")

    # Sequential numeric pattern: 123, 456, 789
    if re.search(r"(012|123|234|345|456|567|678|789)", password):
        patterns.append("Sequential numbers detected")

    # Sequential alphabetic pattern.
    lowered = password.lower()

    alphabet_sequences = [
        "abc",
        "bcd",
        "cde",
        "def",
        "efg",
        "fgh",
        "ghi",
        "hij",
        "ijk",
        "jkl",
        "klm",
        "lmn",
        "mno",
        "nop",
        "opq",
        "pqr",
        "qrs",
        "rst",
        "stu",
        "tuv",
        "uvw",
        "vwx",
        "wxy",
        "xyz",
    ]

    if any(sequence in lowered for sequence in alphabet_sequences):
        patterns.append("Sequential letters detected")

    # Very common keyboard pattern.
    keyboard_patterns = [
        "qwerty",
        "asdf",
        "zxcv",
        "qaz",
        "wsx",
    ]

    if any(pattern in lowered for pattern in keyboard_patterns):
        patterns.append("Keyboard pattern detected")

    return patterns


def calculate_score(
    password: str,
    entropy: float,
    common_password: bool,
    patterns: list[str],
) -> int:
    """
    Calculate a security score from 0 to 100.
    """

    score = 0

    # Length scoring.
    if len(password) >= 8:
        score += 15

    if len(password) >= 12:
        score += 10

    if len(password) >= 16:
        score += 10

    # Character diversity.
    if re.search(r"[a-z]", password):
        score += 10

    if re.search(r"[A-Z]", password):
        score += 10

    if re.search(r"[0-9]", password):
        score += 10

    if re.search(r"[^A-Za-z0-9]", password):
        score += 10

    # Entropy contribution.
    if entropy >= 40:
        score += 5

    if entropy >= 60:
        score += 5

    if entropy >= 80:
        score += 5

    # Security penalties.
    if common_password:
        score -= 35

    score -= len(patterns) * 10

    return max(0, min(score, 100))


def classify_strength(score: int, password: str) -> str:
    """
    Classify password strength using score and password length.
    """

    if len(password) < 8:
        return "Very Weak"

    if score < 40:
        return "Weak"

    if score < 60:
        return "Moderate"

    if score < 80:
        return "Strong"

    return "Very Strong"


def generate_recommendations(
    password: str,
    common_password: bool,
    patterns: list[str],
    entropy: float,
) -> list[str]:
    """
    Generate actionable password-security recommendations.
    """

    recommendations = []

    if len(password) < 12:
        recommendations.append(
            "Use at least 12 characters; longer passphrases are preferable."
        )

    if not re.search(r"[A-Z]", password):
        recommendations.append(
            "Add uppercase letters."
        )

    if not re.search(r"[a-z]", password):
        recommendations.append(
            "Add lowercase letters."
        )

    if not re.search(r"[0-9]", password):
        recommendations.append(
            "Add numbers."
        )

    if not re.search(r"[^A-Za-z0-9]", password):
        recommendations.append(
            "Add special characters."
        )

    if common_password:
        recommendations.append(
            "Avoid common or easily guessed passwords."
        )

    if patterns:
        recommendations.append(
            "Avoid predictable sequences, repeated characters, and keyboard patterns."
        )

    if entropy < 40:
        recommendations.append(
            "Increase password length and unpredictability."
        )

    if not recommendations:
        recommendations.append(
            "Password meets the analyzer's security criteria."
        )

    return recommendations


def analyze_password(password: str) -> dict:
    """
    Analyze a password and return security-related metrics.
    """

    if not isinstance(password, str):
        raise TypeError("Password must be a string.")

    entropy = calculate_entropy(password)
    common_password = detect_common_password(password)
    patterns = detect_patterns(password)

    score = calculate_score(
        password,
        entropy,
        common_password,
        patterns,
    )

    strength = classify_strength(score, password)

    recommendations = generate_recommendations(
        password,
        common_password,
        patterns,
        entropy,
    )

    return {
        "length": len(password),
        "has_uppercase": bool(re.search(r"[A-Z]", password)),
        "has_lowercase": bool(re.search(r"[a-z]", password)),
        "has_digit": bool(re.search(r"[0-9]", password)),
        "has_special": bool(re.search(r"[^A-Za-z0-9]", password)),
        "character_pool": calculate_character_pool(password),
        "entropy": round(entropy, 2),
        "common_password": common_password,
        "patterns": patterns,
        "score": score,
        "strength": strength,
        "recommendations": recommendations,
    }


def display_analysis(result: dict) -> None:
    """
    Display password analysis without printing the password itself.
    """

    print("\n" + "=" * 60)
    print("          PASSWORD SECURITY ANALYSIS")
    print("=" * 60)

    print(f"\nPassword Length       : {result['length']}")
    print(
        f"Uppercase Letters    : "
        f"{'Yes' if result['has_uppercase'] else 'No'}"
    )
    print(
        f"Lowercase Letters    : "
        f"{'Yes' if result['has_lowercase'] else 'No'}"
    )
    print(
        f"Numbers              : "
        f"{'Yes' if result['has_digit'] else 'No'}"
    )
    print(
        f"Special Characters   : "
        f"{'Yes' if result['has_special'] else 'No'}"
    )

    print(f"Character Pool       : {result['character_pool']}")
    print(f"Estimated Entropy    : {result['entropy']} bits")
    print(
        f"Common Password      : "
        f"{'Yes' if result['common_password'] else 'No'}"
    )

    print(
        f"Detected Patterns    : "
        f"{len(result['patterns'])}"
    )

    if result["patterns"]:
        for pattern in result["patterns"]:
            print(f"  - {pattern}")

    print(f"\nSecurity Score       : {result['score']}/100")
    print(f"Password Strength    : {result['strength']}")

    print("\nRecommendations:")
    for recommendation in result["recommendations"]:
        print(f"  - {recommendation}")

    print("\n" + "=" * 60)


def main() -> None:
    """
    Main command-line interface.
    """

    print("=" * 60)
    print("       PASSWORD STRENGTH & SECURITY ANALYZER")
    print("=" * 60)

    print("\nThis tool analyzes password security locally.")
    print("Passwords are not stored, logged, or transmitted.")

    try:
        password = getpass.getpass(
            "\nEnter password to analyze: "
        )

        if not password:
            print("\nError: Password cannot be empty.")
            return

        result = analyze_password(password)

        display_analysis(result)

    except (KeyboardInterrupt, EOFError):
        print("\n\nOperation cancelled.")

    except TypeError as error:
        print(f"\nError: {error}")


if __name__ == "__main__":
    main()
