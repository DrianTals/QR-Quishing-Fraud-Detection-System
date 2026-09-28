"""URL text cleanup and parsing shared by the QR and model pipelines."""

import re
from urllib.parse import urlparse

URL_PATTERN = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)


def extract_url_candidate(raw_text):
    if not isinstance(raw_text, str):
        return ""

    text = raw_text.strip()
    match = URL_PATTERN.search(text)
    if match:
        return match.group(0).rstrip(".,;")
    return text.splitlines()[0].strip() if text else ""


def safe_parse(raw_text):
    candidate = extract_url_candidate(raw_text)
    if not candidate:
        return None
    if not re.match(r"^https?://", candidate, re.IGNORECASE):
        candidate = "http://" + candidate

    try:
        parsed = urlparse(candidate)
        if not parsed.hostname or any(character.isspace() for character in parsed.hostname):
            return None
        parsed.port
        return parsed
    except ValueError:
        return None
