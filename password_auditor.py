import secrets
import string


MIN_PASSWORD_LENGTH = 12
GENERATED_PASSWORD_LENGTH = 16


def generate_password():
    """Generate a password that satisfies the current policy."""
    characters = [
        secrets.choice(string.ascii_uppercase),
        secrets.choice(string.ascii_lowercase),
        secrets.choice(string.digits),
    ]
    alphabet = string.ascii_letters + string.digits
    characters.extend(
        secrets.choice(alphabet)
        for _ in range(GENERATED_PASSWORD_LENGTH - len(characters))
    )
    secrets.SystemRandom().shuffle(characters)
    return "".join(characters)


print("Password Strength and Policy Auditor")

choice = input("Choose an option: [1] Check a password [2] Generate a password: ")
if choice == "1":
    password = input("Enter a password: ")
elif choice == "2":
    password = generate_password()
    print(f"Generated password: {password}")
else:
    print("Invalid option. Choose 1 or 2.")
    raise SystemExit(1)

# Length Check
if len(password) >= MIN_PASSWORD_LENGTH:
    print("✅ Length requirement met")
else:
    print("❌ Password must be at least 12 characters")

# Uppercase Check
if any(char.isupper() for char in password):
    print("✅ Contains uppercase letter")
else:
    print("❌ Missing uppercase letter")

# Lowercase Check
if any(char.islower() for char in password):
    print("✅ Contains lowercase letter")
else:
    print("❌ Missing lowercase letter")

# Number Check
if any(char.isdigit() for char in password):
    print("✅ Contains number")
else:
    print("❌ Missing number")
