"""
Step: Fetch fresh live phishing URLs from PhishTank
--------------------------------------------------------
Tries PhishTank's public phish archive page first, and falls back
to the search-results page if the archive is blocked by bot
detection (PhishTank actively blocks some automated requests).
Extracts the listed phishing URLs into a plain text file.

PhishTank doesn't offer an open bulk CSV/API without a free
registered key, so this reads the same public pages a person
would see in their browser and pulls the URLs out of them.

SAFETY NOTE: These are real, currently-active malicious URLs.
Only ever copy/paste the text into the scanner or a text file.
Never open one directly in a browser.

Output: data/raw/phishtank_live_sample_<date>.txt
"""

import os
import re
import urllib.request
from datetime import date

# Tried in order — archive first, falls back to search if blocked
CANDIDATE_URLS = [
    "https://phishtank.org/phish_archive.php",
    "https://phishtank.org/phish_search.php?valid=y&active=All&Search=Search",
]

OUTPUT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "raw")

# Matches http(s):// URLs as they appear in PhishTank's results tables
URL_PATTERN = re.compile(r'https?://[^\s<>"\'\)]+')

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"
}


def fetch_page(url):
    req = urllib.request.Request(url, headers=HEADERS)
    with urllib.request.urlopen(req, timeout=15) as response:
        return response.read().decode("utf-8", errors="ignore")


def extract_phish_urls(html):
    found = URL_PATTERN.findall(html)
    urls = []
    seen = set()
    for u in found:
        if "phishtank.org" in u or "cisco.com" in u or "talosintelligence.com" in u:
            continue
        if u not in seen:
            seen.add(u)
            urls.append(u)
    return urls


def main():
    today = date.today().isoformat()
    output_path = os.path.join(OUTPUT_DIR, f"phishtank_live_sample_{today}.txt")
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    html = None
    source_used = None

    for url in CANDIDATE_URLS:
        print(f"Trying: {url}")
        try:
            html = fetch_page(url)
            source_used = url
            break
        except Exception as e:
            print(f"  Failed ({e}) -- trying next source if available...")

    if html is None:
        print("\nCould not fetch any PhishTank page -- all candidate sources failed.")
        print("This can happen if PhishTank's bot detection is blocking automated requests.")
        print("Fallback: open https://phishtank.org/phish_search.php?valid=y&active=All&Search=Search")
        print("in your browser and copy a few URLs manually instead.")
        return

    urls = extract_phish_urls(html)

    if not urls:
        print("Page fetched but no phishing URLs were found in it -- layout may have changed.")
        return

    with open(output_path, "w", encoding="utf-8") as f:
        f.write("# Live, verified phishing URLs pulled from PhishTank (valid + online)\n")
        f.write(f"# Source page used: {source_used}\n")
        f.write(f"# Pulled on: {today}\n")
        f.write("# SAFETY: text data only -- never open these directly in a browser.\n\n")
        for u in urls:
            f.write(u + "\n")

    print(f"\nSaved {len(urls)} live URLs to: {output_path}")
    print("Copy any one of these into the scanner's 'Paste URL' tab to test.")


if __name__ == "__main__":
    main()
