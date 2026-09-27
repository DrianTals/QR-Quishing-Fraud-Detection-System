"""
Step: Fetch fresh live phishing URLs for testing
----------------------------------------------------
Pulls the current OpenPhish feed and saves a handful of URLs
into a plain text file — useful for pasting into the scanner's
"Paste URL" tab to test against genuinely live, currently-active
phishing links.

SAFETY NOTE: These are real, currently-active malicious URLs.
Only ever copy/paste the text into the scanner or a text file.
Never open one directly in a browser.

Output: data/raw/openphish_live_sample_<date>.txt
"""

import os
import urllib.request
from datetime import date

FEED_URL = "https://openphish.com/feed.txt"
SAMPLE_SIZE = 15  # how many URLs to save

OUTPUT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "raw")


def main():
    today = date.today().isoformat()
    output_path = os.path.join(OUTPUT_DIR, f"openphish_live_sample_{today}.txt")
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    print("Fetching live OpenPhish feed...")
    try:
        with urllib.request.urlopen(FEED_URL, timeout=15) as response:
            raw = response.read().decode("utf-8", errors="ignore")
    except Exception as e:
        print(f"Failed to fetch feed: {e}")
        print("Check your internet connection, or try again in a moment (feed updates continuously).")
        return

    all_urls = [line.strip() for line in raw.splitlines() if line.strip()]
    if not all_urls:
        print("Feed returned no URLs — it may be temporarily empty or rate-limited. Try again shortly.")
        return

    sample = all_urls[:SAMPLE_SIZE]

    with open(output_path, "w", encoding="utf-8") as f:
        f.write("# Live phishing URLs pulled from OpenPhish\n")
        f.write(f"# Pulled on: {today}\n")
        f.write("# SAFETY: text data only — never open these directly in a browser.\n\n")
        for url in sample:
            f.write(url + "\n")

    print(f"Saved {len(sample)} live URLs to: {output_path}")
    print("Copy any one of these into the scanner's 'Paste URL' tab to test.")


if __name__ == "__main__":
    main()
