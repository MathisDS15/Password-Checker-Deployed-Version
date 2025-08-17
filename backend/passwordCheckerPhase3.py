import requests
import hashlib
import math
from enum import Enum

SPECIAL_CHARS = "!@#$%^&*()-_=+[]{}|;:',.<>?/"
MIN_LENGTH = 8

class PasswordStrength(Enum):

    VeryWeak = "Very Weak"
    Weak = "Weak"
    Medium = "Medium"
    Strong = "Strong"
    VeryStrong = "Very Strong"


# This function checks the password and calculates its entropy
def passwordChecker(password : str) -> dict:

    password_checker_info = {
        "valid": True,
        "errors": [],
        "strength": PasswordStrength.Weak.value,
        "pwned": False,
        "entropy": 0.0
    }

    lowercase_count = 0
    uppercase_count = 0
    digits_count = 0
    special_count = 0

    # Check if the password contains at least one lowercase letter, one uppercase letter,
    # one digit, and one special character
    for char in password:
        if char.islower():
            lowercase_count += 1
        elif char.isupper():
            uppercase_count += 1
        elif char.isdigit():
            digits_count += 1
        elif char in SPECIAL_CHARS:
            special_count += 1

    # Check if the password contains at least 8 characters
    if len(password) < MIN_LENGTH:
        password_checker_info["valid"] = False
        password_checker_info["errors"].append(f"Password too short. Password must be"
                                               f" at least {MIN_LENGTH} characters long.")


    if password_checker_info["valid"]:
        char_size = 0
        if lowercase_count > 0:
            char_size += 26
        if uppercase_count > 0:
            char_size += 26
        if digits_count > 0:
            char_size += 10
        if special_count > 0:
            char_size += 33

        # Calculate the entropy of the password
        password_checker_info["entropy"] = len(password) * math.log2(char_size)

        if password_checker_info["entropy"] >= 125:
            password_checker_info["strength"] = PasswordStrength.VeryStrong.value
        elif password_checker_info["entropy"] >= 60:
            password_checker_info["strength"] = PasswordStrength.Strong.value
        elif password_checker_info["entropy"] >= 33:
            password_checker_info["strength"] = PasswordStrength.Medium.value
        elif password_checker_info["entropy"] >= 28:
            password_checker_info["strength"] = PasswordStrength.Weak.value
        else:
            password_checker_info["strength"] = PasswordStrength.VeryWeak.value

        if isPasswordPwned(password):
            password_checker_info["pwned"] = True
            password_checker_info["errors"].append(f"Password is pwned. Password must be not found in the pwned "
                                                   f"password database.")

    return password_checker_info

# This function
def isPasswordPwned(password : str) -> bool:

    # sha1 is a method to hash the password
    sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix = sha1_hash[:5]
    suffix = sha1_hash[5:]

    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    response = requests.get(url)

    if response.status_code != 200:
        print("Error fetching data from the API.")
        return False

    for line in response.text.splitlines():
        hash_suffix, count = line.split(':')
        if hash_suffix == suffix:
            return int(count) > 0

    for returned_suffix in response.text.splitlines():
        if returned_suffix == suffix:
            return True

    return False

# Calculate the number of possible characters in the password
def displayPasswordCheck(password : str) -> None:

    display = passwordChecker(password)
    print(f"Analyse this password: {password}")
    print(f"Validity: {"Valid" if display["valid"] else "Invalid "}")
    print(f"Strength: {display['strength']}")
    print(f"Entropy: {display['entropy']:.3f}")
    print (f"Pwned: {'Yes' if display['pwned'] else 'No'}\n\n")

displayPasswordCheck("da3de5_!jeff")
displayPasswordCheck("12345678")
displayPasswordCheck("A1b2C4!")
