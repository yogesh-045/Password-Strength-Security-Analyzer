# Password Strength & Security Analyzer

A Python-based cybersecurity tool demonstrating **password strength analysis, entropy estimation, common-password detection, predictable-pattern detection, security scoring, and security recommendations**.

This project was developed as part of the **PRODIGY InfoTech Cyber Security Internship - Task 03** and enhanced into a practical password-security analysis tool.

---

## 🔐 Project Overview

Weak and predictable passwords are a common security risk.

This project analyzes a password locally and evaluates multiple security characteristics instead of relying only on a simple uppercase/lowercase/digit checklist.

The analyzer evaluates:

* Password length
* Uppercase letters
* Lowercase letters
* Numbers
* Special characters
* Character pool size
* Estimated entropy
* Common-password usage
* Repeated characters
* Sequential characters
* Keyboard patterns
* Overall security score
* Password strength
* Security recommendations

The password is analyzed locally and is **not stored, logged, or transmitted** by the program.

---

## 🛠️ Technologies & Security Concepts

This project demonstrates practical experience with:

![Python](https://img.shields.io/badge/Python-Programming-blue)
![Cybersecurity](https://img.shields.io/badge/Cybersecurity-Security-red)
![Password Security](https://img.shields.io/badge/Password%20Security-Authentication-orange)
![Cryptography](https://img.shields.io/badge/Cryptography-Security-purple)
![Entropy Analysis](https://img.shields.io/badge/Entropy-Analysis-yellow)
![Brute Force](https://img.shields.io/badge/Brute%20Force-Attack-critical)
![Dictionary Attack](https://img.shields.io/badge/Dictionary%20Attack-Security-blueviolet)
![Pattern Detection](https://img.shields.io/badge/Pattern%20Detection-Analysis-teal)
![Regex](https://img.shields.io/badge/Regex-Pattern%20Matching-green)
![Input Validation](https://img.shields.io/badge/Input%20Validation-Security-success)
![Unit Testing](https://img.shields.io/badge/Unit%20Testing-Python-blue)
![GitHub](https://img.shields.io/badge/GitHub-Project-black)

---

## 🚀 Features

* Password length analysis
* Uppercase character detection
* Lowercase character detection
* Number detection
* Special-character detection
* Character pool estimation
* Entropy estimation
* Common-password detection
* Repeated-character detection
* Sequential-number detection
* Sequential-letter detection
* Keyboard-pattern detection
* Security score from 0–100
* Strength classification
* Actionable security recommendations
* Secure password input using `getpass`
* Input validation
* Exception handling
* Automated unit testing
* Pure Python implementation
* No external dependencies

---

## 📂 Project Structure

```text
Password-Strength-Security-Analyzer/
│
├── password_checker.py
├── test_password_checker.py
└── README.md
```

### Files

| File                       | Description                     |
| -------------------------- | ------------------------------- |
| `password_checker.py`      | Main password security analyzer |
| `test_password_checker.py` | Automated unit tests            |
| `README.md`                | Project documentation           |

---

# 🧠 How Password Security Analysis Works

The analyzer evaluates several properties of a password.

### 1. Password Length

Longer passwords generally provide a larger search space.

The analyzer gives additional scoring for passwords reaching:

```text
8+ characters
12+ characters
16+ characters
```

---

### 2. Character Diversity

The analyzer checks whether the password contains:

```text
Lowercase letters
Uppercase letters
Numbers
Special characters
```

Example:

```text
hello
```

has less character diversity than:

```text
Hello123!
```

However, character diversity alone does not guarantee security.

---

# 🔢 Entropy Estimation

The project estimates password entropy using the size of the possible character pool.

The basic model is:

```text
Entropy = log2(R^L)
```

Equivalent form:

```text
Entropy = L × log2(R)
```

Where:

* `L` = password length
* `R` = estimated character pool size

A password using lowercase, uppercase, numbers, and special characters has a larger estimated character pool than a password using lowercase letters only.

### Important

Entropy reported by this tool is an **educational estimate**.

Real-world password strength depends on factors such as:

* Human-generated patterns
* Password reuse
* Dictionary words
* Credential stuffing
* Breached-password databases
* Attacker password models
* Hashing and authentication architecture

---

# 💥 Common Password Detection

The tool checks the password against a small local list of commonly used passwords.

Examples include:

```text
password
123456
qwerty
admin
welcome
password123
```

A password can contain uppercase letters, numbers, and special characters while still being predictable.

Therefore, complexity rules alone are insufficient.

---

# 🔍 Pattern Detection

The analyzer attempts to identify common predictable patterns.

### Repeated Characters

Example:

```text
aaa
111
!!!
```

### Sequential Numbers

Example:

```text
123
456
789
```

### Sequential Letters

Example:

```text
abc
def
xyz
```

### Keyboard Patterns

Example:

```text
qwerty
asdf
zxcv
```

Predictable patterns reduce the practical security of a password.

---

# 📊 Security Score

The analyzer calculates a score from:

```text
0 – 100
```

The score considers:

* Password length
* Character diversity
* Estimated entropy
* Common-password usage
* Predictable patterns

The score is intended for **educational analysis**, not as a standardized industry password-strength metric.

---

# 🏷️ Strength Classification

The analyzer classifies passwords into:

| Score / Condition      | Classification |
| ---------------------- | -------------- |
| Less than 8 characters | Very Weak      |
| Low score              | Weak           |
| Medium score           | Moderate       |
| High score             | Strong         |
| Very high score        | Very Strong    |

The exact classification is determined by the analyzer's scoring logic.

---

# 🛡️ Security Recommendations

The analyzer provides recommendations such as:

* Increase password length
* Add uppercase letters
* Add lowercase letters
* Add numbers
* Add special characters
* Avoid common passwords
* Avoid predictable sequences
* Avoid repeated characters
* Increase unpredictability

For real-world account security, users should also consider using a **password manager** and unique passwords for every account.

---

# 🔒 Secure Input Handling

The application uses Python's `getpass` module instead of the normal `input()` function.

This prevents the password from being displayed directly while entering it in a compatible terminal.

The application does not:

* Store passwords
* Write passwords to files
* Print the password
* Send passwords to external services
* Upload passwords to the internet

---

# ▶️ Installation

Clone the repository:

```bash
git clone https://github.com/yogesh-045/PRODIGY_CYBERSECURITY_Task-03.git
```

Navigate to the project directory:

```bash
cd PRODIGY_CYBERSECURITY_Task-03
```

---

# 🛠️ Requirements

Python 3.9 or newer is recommended.

No external Python packages are required.

Check your Python version:

```bash
python --version
```

---

# ▶️ Usage

Run the analyzer:

```bash
python password_checker.py
```

The application will display:

```text
============================================================
       PASSWORD STRENGTH & SECURITY ANALYZER
============================================================

This tool analyzes password security locally.
Passwords are not stored, logged, or transmitted.

Enter password to analyze:
```

The password is entered without being displayed in a compatible terminal.

---

# 💡 Example Analysis

Example password:

```text
TestPassword123!
```

The analyzer evaluates:

```text
Password Length
Uppercase Letters
Lowercase Letters
Numbers
Special Characters
Character Pool
Estimated Entropy
Common Password Status
Detected Patterns
Security Score
Password Strength
Security Recommendations
```

The exact entropy and score depend on the password and analyzer rules.

---

# 🧪 Testing

Run the automated tests:

```bash
python -m unittest test_password_checker.py
```

Expected output:

```text
...................
----------------------------------------------------------------------
Ran 19 tests in 0.00s

OK
```

The tests verify:

* Character pool calculation
* Entropy calculation
* Password length behavior
* Common-password detection
* Case-insensitive detection
* Repeated-character detection
* Sequential-number detection
* Keyboard-pattern detection
* Character diversity
* Score range
* Strength classification
* Security recommendations
* Analysis output structure
* Invalid input handling

---

# 🔍 Cybersecurity Concepts Demonstrated

### 1. Password Security

Understanding characteristics of stronger and weaker passwords.

### 2. Entropy

Understanding how password length and character pool affect theoretical search space.

### 3. Brute-Force Resistance

Understanding why larger password search spaces increase the number of guesses required.

### 4. Dictionary Attacks

Understanding why common passwords are vulnerable to dictionary-based guessing.

### 5. Pattern Analysis

Identifying predictable human password-generation behavior.

### 6. Input Security

Using hidden terminal input to reduce accidental password exposure.

### 7. Secure Handling

Avoiding password storage, logging, or transmission.

### 8. Automated Testing

Using Python unit tests to verify security-analysis functionality.

---

# 📊 Complexity

For most password-analysis operations:

```text
Time Complexity:  O(n)
Space Complexity: O(n)
```

Where `n` is the password length.

The common-password lookup uses a Python set, providing approximately constant-time membership checking for the local list.

---

# ⚠️ Security Limitations

This project is an **educational password-strength analyzer**, not a production authentication security system.

The entropy calculation is theoretical and assumes a simplified character-selection model.

It does not perform:

* Real credential breach checking
* Online password testing
* Hash cracking
* Dictionary attack execution
* Credential stuffing
* Authentication testing
* Password database analysis

For real-world authentication systems, password security should also involve:

* Strong password hashing
* Unique salts
* Modern password hashing algorithms such as Argon2id, scrypt, or bcrypt
* Rate limiting
* Multi-factor authentication
* Credential breach detection
* Secure session management

---

# 🚧 Future Improvements

Possible future enhancements:

* Larger offline common-password dataset
* Password strength visualization
* Diceware-style passphrase analysis
* More advanced pattern detection
* zxcvbn-style password scoring
* Offline breached-password hash checking
* CLI arguments using `argparse`
* JSON report generation
* CSV report generation
* GUI interface
* Password-manager integration
* Configurable security policies

---

# 🎯 Learning Objectives

After completing this project, you should understand:

* Password complexity
* Password entropy
* Character pools
* Brute-force concepts
* Dictionary attacks
* Predictable password patterns
* Password security scoring
* Secure input handling
* Python regular expressions
* Exception handling
* Unit testing
* Basic cybersecurity risk analysis

---

# ⚠️ Disclaimer

This project is intended strictly for **educational and cybersecurity learning purposes**.

The score and entropy values are simplified educational metrics and should not be treated as a guarantee of password security.

Never use this project as a replacement for professionally designed authentication and password-management systems.

---

# 👨‍💻 Author

**Yogesh**

Cybersecurity enthusiast interested in:

* SOC Operations
* Network Security
* Threat Detection
* Malware Analysis
* Ethical Hacking
* Cryptography
* Cybersecurity Automation

---

# 📜 License

This project is provided for educational purposes.

You are free to study, modify, and use the code for learning and experimentation.
