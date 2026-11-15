import math
import secrets
import string


MIN_PASSWORD_LENGTH = 12
TARGET_ENTROPY_BITS = 80
MAX_GENERATED_PASSWORD_LENGTH = 28
GENERATED_WORD_COUNT = 2
GENERATED_SUFFIX_LENGTH = 8
GENERATED_SUFFIX_GROUP_LENGTH = 4
GENERATED_EMBEDDED_CHARACTER_COUNT = 4
GENERATED_EMBEDDED_CHARACTERS = string.digits + string.punctuation.replace("-", "")
GENERATED_SUFFIX_GROUP_COUNT = (
    GENERATED_SUFFIX_LENGTH + GENERATED_SUFFIX_GROUP_LENGTH - 1
) // GENERATED_SUFFIX_GROUP_LENGTH
MAX_GENERATED_WORD_LENGTH = (
    MAX_GENERATED_PASSWORD_LENGTH
    - GENERATED_SUFFIX_LENGTH
    - GENERATED_EMBEDDED_CHARACTER_COUNT
    - GENERATED_WORD_COUNT
    - GENERATED_SUFFIX_GROUP_COUNT
    + 1
) // GENERATED_WORD_COUNT
GENERATED_CHARACTERS = string.ascii_letters + string.digits + string.punctuation
WORDS = (
    "acorn", "amber", "apron", "arctic", "artist", "aspen", "atlas", "basin",
    "beacon", "birch", "bison", "breeze", "brook", "cactus", "canvas", "cedar",
    "cherry", "cinder", "citrus", "clover", "cobalt", "comet", "coral", "daisy",
    "delta", "desert", "eagle", "echo", "ember", "falcon", "fern",
    "fig", "forest", "fossil", "galaxy", "garlic", "garden", "ginger",
    "goblet", "harbor", "hazel", "honey", "igloo", "indigo", "island",
    "jigsaw", "kettle", "kiwi", "lemon", "locust", "marble", "meadow",
    "nectar", "north", "ocean", "olive", "onyx", "orchid", "otter", "paper",
    "pebble", "pepper", "petal", "picnic", "pine", "planet", "plum", "pocket",
    "pollen", "poppy", "puzzle", "quartz", "radish", "raven", "river", "robin",
    "sandal", "shadow", "silver", "sprout", "spruce", "teacup", "timber", "tulip",
)
GENERATABLE_WORDS = tuple(
    word for word in WORDS if len(word) <= MAX_GENERATED_WORD_LENGTH
)


def generate_password():
    """Generate a word-anchored password with random characters embedded in words."""
    randomizer = secrets.SystemRandom()
    words = randomizer.sample(GENERATABLE_WORDS, GENERATED_WORD_COUNT)
    words[0] = words[0].capitalize()

    embedded_characters = [
        randomizer.choice(GENERATED_EMBEDDED_CHARACTERS)
        for _ in range(GENERATED_EMBEDDED_CHARACTER_COUNT)
    ]
    for word_index, word in enumerate(words):
        insertion_positions = sorted(
            randomizer.sample(
                range(1, len(word)),
                GENERATED_EMBEDDED_CHARACTER_COUNT // GENERATED_WORD_COUNT,
            ),
            reverse=True,
        )
        for position in insertion_positions:
            char = embedded_characters.pop()
            word = word[:position] + char + word[position:]
        words[word_index] = word

    while True:
        suffix = "".join(
            randomizer.choice(GENERATED_CHARACTERS)
            for _ in range(GENERATED_SUFFIX_LENGTH)
        )
        if any(char in string.digits for char in suffix):
            break
    grouped_suffix = "-".join(
        suffix[index:index + GENERATED_SUFFIX_GROUP_LENGTH]
        for index in range(0, GENERATED_SUFFIX_LENGTH, GENERATED_SUFFIX_GROUP_LENGTH)
    )
    return "-".join([*words, grouped_suffix])


def generated_password_entropy():
    """Estimate entropy from word, insertion-position, and character choices."""
    word_choice_count = math.factorial(len(GENERATABLE_WORDS)) // math.factorial(
        len(GENERATABLE_WORDS) - GENERATED_WORD_COUNT
    )
    average_position_entropy = (
        GENERATED_WORD_COUNT
        * sum(
            math.log2(
                math.comb(
                    len(word) - 1,
                    GENERATED_EMBEDDED_CHARACTER_COUNT // GENERATED_WORD_COUNT,
                )
            )
            for word in GENERATABLE_WORDS
        )
        / len(GENERATABLE_WORDS)
    )
    embedded_character_entropy = (
        GENERATED_EMBEDDED_CHARACTER_COUNT
        * math.log2(len(GENERATED_EMBEDDED_CHARACTERS))
    )
    suffix_choice_count = (
        len(GENERATED_CHARACTERS) ** GENERATED_SUFFIX_LENGTH
        - (len(GENERATED_CHARACTERS) - len(string.digits)) ** GENERATED_SUFFIX_LENGTH
    )
    return (
        math.log2(word_choice_count)
        + average_position_entropy
        + embedded_character_entropy
        + math.log2(suffix_choice_count)
    )


def estimate_password_entropy(password):
    """Estimate entropy from character classes; this does not detect patterns."""
    character_pool_size = 0
    if any(char in string.ascii_lowercase for char in password):
        character_pool_size += len(string.ascii_lowercase)
    if any(char in string.ascii_uppercase for char in password):
        character_pool_size += len(string.ascii_uppercase)
    if any(char in string.digits for char in password):
        character_pool_size += len(string.digits)
    if any(char in string.punctuation for char in password):
        character_pool_size += len(string.punctuation)

    if not password or character_pool_size == 0:
        return 0.0
    return len(password) * math.log2(character_pool_size)


def report_entropy(entropy_bits, estimate_type):
    print(
        f"Entropy estimate ({estimate_type}): {entropy_bits:.1f} bits"
    )
    if entropy_bits >= TARGET_ENTROPY_BITS:
        print(f"Strength estimate: Meets the {TARGET_ENTROPY_BITS}-bit target")
    else:
        print(f"Strength estimate: Below the {TARGET_ENTROPY_BITS}-bit target")
    if estimate_type == "character-set estimate":
        print(
            "Note: This estimate does not account for predictable patterns "
            "or breached passwords."
        )


print("Password Strength and Policy Auditor")

choice = input("Choose an option: [1] Check a password [2] Generate a password: ")
if choice == "1":
    password = input("Enter a password: ")
    entropy_bits = estimate_password_entropy(password)
    estimate_type = "character-set estimate (length × log₂(pool size))"
elif choice == "2":
    password = generate_password()
    entropy_bits = generated_password_entropy()
    estimate_type = "passphrase generation choices"
    print(f"Generated password: {password}")
else:
    print("Invalid option. Choose 1 or 2.")
    raise SystemExit(1)

report_entropy(entropy_bits, estimate_type)

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
