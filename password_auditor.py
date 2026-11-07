print("Password Strength and Policy Auditor")

password = input("Enter a password: ")

if len(password) >= 12:
    print("✅ Length requirement met")
else:
    print("❌ Password must be at least 12 characters")
