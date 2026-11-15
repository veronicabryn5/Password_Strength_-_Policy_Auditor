# Password Strength and Policy Auditor

A Python program that evaluates password strength using security engineering principles.

Run `python password_auditor.py`, then choose whether to check a password or generate
a password built around two distinct words. Four random digits or symbols are inserted
inside the words, and an 8-character random suffix is grouped into two chunks. The
first word is capitalized, and the suffix always includes a digit. It stays within
28 characters while retaining recognizable words.

The auditor estimates entered-password entropy using
`password length × log2(character pool size)`. For generated passwords, it reports
entropy from the actual word, insertion-position, and random-character choices; the
generated password meets the 80-bit target. Estimates for manually entered passwords
do not detect common patterns or breached passwords and can overstate real-world
strength.

Planned Features:
- Password strength analysis
- Detection of common password patterns
- Password improvement suggestions

Authors: Dallas Hanson-Richart, Colin Barrett, Veronica Brynczka
