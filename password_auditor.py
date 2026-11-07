print("Password Strength and Policy Auditor")

password = input("Enter a password: ")

# Length Check
if len(password) >= 12:
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
