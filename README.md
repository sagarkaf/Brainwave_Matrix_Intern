
# Phishing Link Scanner

This is a Python-based tool I developed to detect suspicious URLs that could potentially be phishing links. The tool checks various characteristics of URLs that are commonly found in phishing attempts, such as suspicious keywords, domain reputation, lack of HTTPS, misleading characters, and more. This was created as part of an internship task provided by **Brainwave Matrix**.

## Features

The scanner performs the following checks on a given URL:
- **Suspicious Keywords**: Detects keywords like "login", "secure", "account", "banking", etc.
- **URL Length**: Flags URLs that are unusually long (over 75 characters).
- **Misleading Characters**: Identifies if the URL contains internationalized domain names (IDNs) with patterns like `xn--`.
- **Domain Reputation**: Checks the domain's registration date to identify newly registered domains.
- **HTTPS Check**: Verifies whether the URL uses HTTPS, which is essential for security.
- **Top-Level Domain (TLD)**: Flags suspicious TLDs such as `.xyz`, `.top`, `.club`, etc.
- **URL Encoding**: Flags URLs containing encoding (e.g., `%20`), which is often used to hide phishing elements.
- **Multiple Subdomains**: Identifies URLs with excessive subdomains, which may be used to obfuscate the real domain.
- **Domain Mismatch**: Flags possible domain mismatch or typo-squatting attempts.
- **Fake Subdomains**: Detects suspicious subdomains like `paypal.com.fake.site.com`.

## Requirements

Before using the tool, make sure to install the following Python libraries:

- `re`
- `whois`
- `tkinter`
- `urllib.parse`
- `datetime`
- `socket`

To install the required libraries, run the following command:

```bash
pip install python-whois
