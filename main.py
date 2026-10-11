"""SNAYZA Cybersecurity Toolkit
A small, educational cybersecurity toolkit that runs in the terminal.
"""

import re
from urllib.parse import urlparse

# ANSI colors (supported by modern Windows Terminal, macOS Terminal, and Linux terminals)
RED = "\033[91m"
DARK_RED = "\033[31m"
WHITE = "\033[97m"
GRAY = "\033[90m"
RESET = "\033[0m"

BANNER = r"""
  ____  _   _    _   __   __ _____ ____
 / ___|| \ | |  / \  \ \ / /| ____|  _ \
 \___ \|  \| | / _ \  \ V / |  _| | |_) |
  ___) | |\  |/ ___ \  | |  | |___|  _ <
 |____/|_| \_/_/   \_\ |_|  |_____|_| \_\

      S N A Y Z A  |  CYBERSECURITY TOOLKIT
"""

TIPS = [
    "Use a different, long password for every account.",
    "Turn on multi-factor authentication (MFA) wherever possible.",
    "Check the full domain before signing in or entering payment details.",
    "Do not open unexpected attachments or links from unknown senders.",
    "Keep your operating system, browser, and apps updated.",
    "Back up important files and protect backups from unauthorized access.",
]


def assess_password(password: str) -> tuple[str, list[str]]:
    """Return a rough password rating and suggestions; never store the password."""
    score = 0
    feedback = []

    if len(password) >= 12:
        score += 2
    elif len(password) >= 8:
        score += 1
    else:
        feedback.append("Use at least 12 characters when practical.")

    checks = [
        (r"[a-z]", "Add lowercase letters."),
        (r"[A-Z]", "Add uppercase letters."),
        (r"\d", "Add numbers."),
        (r"[^A-Za-z0-9]", "Consider adding symbols."),
    ]
    for pattern, suggestion in checks:
        if re.search(pattern, password):
            score += 1
        else:
            feedback.append(suggestion)

    if len(set(password)) <= 3 and len(password) > 0:
        score = max(0, score - 2)
        feedback.append("Avoid repeating the same few characters.")

    if len(password) >= 16 and score >= 5:
        rating = "Strong (rough estimate)"
    elif score >= 4:
        rating = "Moderate (rough estimate)"
    else:
        rating = "Weak (rough estimate)"

    if not feedback:
        feedback.append("Good start. A password manager can help you use unique passwords.")
    return rating, feedback


def check_url(url: str) -> tuple[list[str], list[str]]:
    """Flag visible URL patterns for learning; this is not a reputation lookup."""
    flags = []
    notes = []
    candidate = url.strip()
    if not candidate:
        return ["No URL entered."], notes

    parsed_input = candidate if "://" in candidate else f"https://{candidate}"
    try:
        parsed = urlparse(parsed_input)
        hostname = parsed.hostname or ""
    except ValueError:
        return ["The URL could not be parsed. Check its format."], notes

    if not hostname or "." not in hostname:
        flags.append("The address does not look like a typical public domain.")
    if parsed.scheme.lower() != "https":
        flags.append("The URL does not use HTTPS.")
    if "@" in parsed.netloc:
        flags.append("The address contains '@', which can obscure the actual host.")
    if re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", hostname):
        flags.append("The host is an IP address rather than a familiar domain name.")
    if hostname.startswith("xn--") or ".xn--" in hostname:
        flags.append("The domain includes an internationalized (punycode) label.")
    if len(hostname) > 50:
        flags.append("The hostname is unusually long.")
    if hostname.count("-") >= 3:
        flags.append("The hostname contains several hyphens.")
    suspicious_words = ("login", "verify", "secure", "account", "update", "password")
    if any(word in (hostname + parsed.path).lower() for word in suspicious_words):
        flags.append("The address includes words sometimes used in login lures; context matters.")

    if not flags:
        notes.append("No simple warning pattern was detected by this basic checker.")
    notes.append("This tool does not visit the website or check threat-intelligence databases.")
    notes.append("A URL can still be malicious even when no warning appears. Do not enter sensitive data unless you trust the site.")
    return flags, notes


def password_checker() -> None:
    print("\n--- Password Strength Checker ---")
    print("Privacy note: the password is checked only in this running program and is not saved.")
    password = input("Enter a sample password (avoid using a password you actually use): ")
    rating, feedback = assess_password(password)
    print(f"\nEstimated rating: {rating}")
    for item in feedback:
        print(f"- {item}")


def url_checker() -> None:
    print("\n--- Phishing URL Checker ---")
    print("Paste a URL to inspect its visible structure. The site will not be opened.")
    url = input("URL: ")
    flags, notes = check_url(url)
    print("\nPotential warning signs:")
    for flag in flags:
        print(f"- {flag}")
    for note in notes:
        print(f"! {note}")


def show_tips() -> None:
    print("\n--- Cybersecurity Tips ---")
    for number, tip in enumerate(TIPS, start=1):
        print(f"{number}. {tip}")


def main() -> None:
    while True:
        print(f"{RED}{BANNER}{RESET}")
        print(f"{GRAY}  ─────────────────────────────────────────────────────{RESET}")
        print(f"  {RED}[1]{RESET} {WHITE}Password Strength Checker{RESET}")
        print(f"  {RED}[2]{RESET} {WHITE}Phishing URL Checker{RESET}")
        print(f"  {RED}[3]{RESET} {WHITE}Cybersecurity Tips{RESET}")
        print(f"  {RED}[4]{RESET} {WHITE}Exit{RESET}")
        print(f"{GRAY}  ─────────────────────────────────────────────────────{RESET}")
        choice = input(f"\n{RED}SNAYZA{RESET} {GRAY}»{RESET} Choose an option (1-4): ").strip()

        if choice == "1":
            password_checker()
        elif choice == "2":
            url_checker()
        elif choice == "3":
            show_tips()
        elif choice == "4":
            print(f"\n{RED}Stay safe online. Thanks for using SNAYZA Toolkit!{RESET}")
            break
        else:
            print(f"{RED}Invalid choice. Please enter 1, 2, 3, or 4.{RESET}")
        input("\nPress Enter to return to the menu...")
        print("\n" * 2)


if __name__ == "__main__":
    main()
