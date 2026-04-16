import feedparser
import requests
import re
import time
import html
from html.parser import HTMLParser
from datetime import datetime


# ── HTML cleaner ─────────────────────────────────────────────────────────────

class _MLStripper(HTMLParser):
    def __init__(self):
        super().__init__()
        self.reset()
        self.fed = []
    def handle_data(self, d):
        self.fed.append(d)
    def get_data(self):
        return ' '.join(self.fed)

def _clean_html(raw):
    if not raw:
        return 'No summary available.'
    s = _MLStripper()
    s.feed(raw)
    text = s.get_data()
    text = html.unescape(text)
    text = ' '.join(text.split())
    return text[:500] + '...' if len(text) > 500 else text


# ── Feeds & constants ─────────────────────────────────────────────────────────

CISA_ICS_FEED         = "https://www.cisa.gov/cybersecurity-advisories/ics-advisories.xml"
CISA_ICS_MEDICAL_FEED = "https://www.cisa.gov/cybersecurity-advisories/ics-medical-advisories.xml"

SECTOR_KEYWORDS = {
    "Energy":                 ["energy", "electric", "power", "grid", "utility", "utilities", "oil", "gas", "petroleum", "nuclear"],
    "Water":                  ["water", "wastewater", "drinking water", "sewage"],
    "Manufacturing":          ["manufacturing", "chemical", "pharmaceutical", "food", "beverage", "automotive"],
    "Transportation":         ["transportation", "aviation", "maritime", "rail", "pipeline"],
    "Healthcare":             ["healthcare", "medical", "hospital", "clinical", "health"],
    "Government":             ["government", "federal", "municipal", "defense", "military"],
    "Critical Infrastructure":["critical infrastructure", "scada", "ics", "industrial control"],
}

SEVERITY_BANDS = {
    "Critical": (9.0, 10.0),
    "High":     (7.0, 8.9),
    "Medium":   (4.0, 6.9),
    "Low":      (0.1, 3.9),
}


# ── NVD CVSS lookup ───────────────────────────────────────────────────────────

def fetch_cvss_from_nvd(cve_id, retries=3):
    for attempt in range(retries):
        try:
            url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
            response = requests.get(url, timeout=10)

            if response.status_code == 429:
                wait = 10 * (attempt + 1)
                print(f"[fetcher] NVD rate limited, waiting {wait}s...")
                time.sleep(wait)
                continue

            if response.status_code != 200:
                return None

            data = response.json()
            vulns = data.get("vulnerabilities", [])
            if not vulns:
                return None

            metrics = vulns[0]["cve"].get("metrics", {})
            for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                if key in metrics:
                    return metrics[key][0]["cvssData"]["baseScore"]

        except Exception as e:
            print(f"[fetcher] NVD error for {cve_id}: {e}")
            time.sleep(3)
            continue

    return None


# ── Parsers ───────────────────────────────────────────────────────────────────

def extract_cves(text):
    pattern = r'CVE-\d{4}-\d{4,}'
    return list(set(re.findall(pattern, text, re.IGNORECASE)))


def extract_cvss_score(text):
    patterns = [
        r'CVSS\s*v?3(?:\.\d)?\s*(?:base\s*)?score[:\s]+(\d+\.?\d*)',
        r'CVSSv3[:\s]+(\d+\.?\d*)',
        r'base\s*score[:\s]+(\d+\.?\d*)',
    ]
    scores = []
    for pattern in patterns:
        matches = re.findall(pattern, text, re.IGNORECASE)
        for m in matches:
            try:
                scores.append(float(m))
            except ValueError:
                pass
    return max(scores) if scores else None


def score_to_severity(score):
    if score is None:
        return "Unknown"
    for label, (low, high) in SEVERITY_BANDS.items():
        if low <= score <= high:
            return label
    return "Unknown"


def detect_sector(text):
    text_lower = text.lower()
    detected = []
    for sector, keywords in SECTOR_KEYWORDS.items():
        if any(kw in text_lower for kw in keywords):
            detected.append(sector)
    return detected if detected else ["Critical Infrastructure"]


def extract_vendor(title):
    two_word_vendors = [
        "Rockwell Automation", "Schneider Electric", "General Electric",
        "Emerson Electric", "Beckhoff Automation", "Phoenix Contact",
        "Mitsubishi Electric", "ABB Ltd", "Delta Electronics",
    ]
    for vendor in two_word_vendors:
        if title.lower().startswith(vendor.lower()):
            return vendor
    first_word = title.split()[0] if title.split() else "Unknown"
    skip_words = ["CISA", "ICS", "Advisory", "Multiple", "Update"]
    if first_word in skip_words:
        return "Multiple Vendors"
    return first_word


def parse_advisory(entry):
    title       = entry.get("title", "Untitled Advisory")
    summary     = entry.get("summary", "")
    link        = entry.get("link", "#")

    published_raw = entry.get("published_parsed")
    published = datetime(*published_raw[:6]).strftime("%Y-%m-%d") if published_raw else "Unknown"

    full_text = f"{title} {summary}"

    cves       = extract_cves(full_text)
    cvss_score = extract_cvss_score(full_text)

    # If RSS text had no score, ask NVD for the first CVE
    if cvss_score is None and cves:
        cvss_score = fetch_cvss_from_nvd(cves[0])
        time.sleep(1.0)   # respect NVD rate limit after every API call

    severity = score_to_severity(cvss_score)
    sectors  = detect_sector(full_text)
    vendor   = extract_vendor(title)

    return {
        "title":           title,
        "vendor":          vendor,
        "link":            link,
        "published":       published,
        "severity":        severity,
        "cvss_score":      cvss_score,
        "cves":            cves,
        "cve_count":       len(cves),
        "sectors":         sectors,
        "summary_snippet": _clean_html(summary),
    }


# ── Main fetch ────────────────────────────────────────────────────────────────

def fetch_advisories(limit=60):
    all_advisories = []

    for feed_url in [CISA_ICS_FEED, CISA_ICS_MEDICAL_FEED]:
        try:
            feed = feedparser.parse(feed_url)

            if feed.bozo:
                print(f"[fetcher] Warning: feed parsing issue for {feed_url}")

            for entry in feed.entries:
                parsed = parse_advisory(entry)
                all_advisories.append(parsed)

        except Exception as e:
            print(f"[fetcher] Error fetching {feed_url}: {e}")
            continue

    all_advisories.sort(key=lambda x: x["published"], reverse=True)
    return all_advisories[:limit]


# ── Stats ─────────────────────────────────────────────────────────────────────

def get_summary_stats(advisories):
    stats = {
        "total":    len(advisories),
        "Critical": 0,
        "High":     0,
        "Medium":   0,
        "Low":      0,
        "Unknown":  0,
        "sectors":  {},
        "vendors":  {},
    }

    for adv in advisories:
        severity = adv.get("severity", "Unknown")
        stats[severity] = stats.get(severity, 0) + 1

        for sector in adv.get("sectors", []):
            stats["sectors"][sector] = stats["sectors"].get(sector, 0) + 1

        vendor = adv.get("vendor", "Unknown")
        stats["vendors"][vendor] = stats["vendors"].get(vendor, 0) + 1

    stats["sectors"] = dict(
        sorted(stats["sectors"].items(), key=lambda x: x[1], reverse=True)
    )
    stats["top_vendors"] = dict(
        sorted(stats["vendors"].items(), key=lambda x: x[1], reverse=True)[:8]
    )

    return stats


# ── Quick terminal test ───────────────────────────────────────────────────────

if __name__ == "__main__":
    print("[*] Fetching CISA ICS advisories...")
    advisories = fetch_advisories(limit=10)

    print(f"\n[+] Got {len(advisories)} advisories\n")
    for adv in advisories:
        marker = {"Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🟢", "Unknown": "⚪"}.get(adv["severity"], "⚪")
        print(f"{marker} [{adv['published']}] {adv['vendor']} — {adv['title'][:60]}")
        if adv["cves"]:
            print(f"   CVEs: {', '.join(adv['cves'][:3])}")
        if adv["cvss_score"]:
            print(f"   CVSS: {adv['cvss_score']} ({adv['severity']})")
        print(f"   Sectors: {', '.join(adv['sectors'])}")
        print()

    stats = get_summary_stats(advisories)
    print(f"[STATS] Critical: {stats['Critical']} | High: {stats['High']} | Medium: {stats['Medium']} | Unknown: {stats['Unknown']}")
    print(f"[TOP SECTORS] {list(stats['sectors'].keys())[:4]}")