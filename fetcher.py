import feedparser
import requests
import re
from datetime import datetime
def fetch_cvss_from_nvd(cve_id):
    """
    Query the NVD API for a CVE's CVSS score.
    NVD = National Vulnerability Database — the authoritative source
    for CVSS scores. Free, no API key needed for basic use.
    Rate limit: 5 requests per 30 seconds without a key.
    """
    try:
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
        response = requests.get(url, timeout=8)
        if response.status_code != 200:
            return None
        data = response.json()
        vulns = data.get("vulnerabilities", [])
        if not vulns:
            return None
        metrics = vulns[0]["cve"].get("metrics", {})
        # Try CVSSv3.1 first, then v3.0, then v2
        for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            if key in metrics:
                return metrics[key][0]["cvssData"]["baseScore"]
    except Exception:
        return None
    return None

# CISA publishes two ICS advisory feeds — we pull both
CISA_ICS_FEED = "https://www.cisa.gov/cybersecurity-advisories/ics-advisories.xml"
CISA_ICS_MEDICAL_FEED = "https://www.cisa.gov/cybersecurity-advisories/ics-medical-advisories.xml"

# These are the exact sector tags CISA uses in their advisories
# Knowing these by heart is useful — you will see them referenced in Shieldworkz work
SECTOR_KEYWORDS = {
    "Energy": ["energy", "electric", "power", "grid", "utility", "utilities", "oil", "gas", "petroleum", "nuclear"],
    "Water": ["water", "wastewater", "drinking water", "sewage"],
    "Manufacturing": ["manufacturing", "chemical", "pharmaceutical", "food", "beverage", "automotive"],
    "Transportation": ["transportation", "aviation", "maritime", "rail", "pipeline"],
    "Healthcare": ["healthcare", "medical", "hospital", "clinical", "health"],
    "Government": ["government", "federal", "municipal", "defense", "military"],
    "Critical Infrastructure": ["critical infrastructure", "scada", "ics", "industrial control"],
}

# CVSS severity bands — same thresholds used in real SOC triage
# Critical = drop everything. High = same shift. Medium = queue it.
SEVERITY_BANDS = {
    "Critical": (9.0, 10.0),
    "High":     (7.0, 8.9),
    "Medium":   (4.0, 6.9),
    "Low":      (0.1, 3.9),
    "Unknown":  (0.0, 0.0),
}


def extract_cves(text):
    """Pull all CVE IDs out of free text using regex."""
    # CVE format: CVE-YYYY-NNNNN (4 digit year, 4+ digit number)
    pattern = r'CVE-\d{4}-\d{4,}'
    return list(set(re.findall(pattern, text, re.IGNORECASE)))


def extract_cvss_score(text):
    """
    CISA embeds CVSS scores in advisory text in formats like:
      'CVSS v3 score of 9.8'  or  'CVSSv3: 8.1'  or  'CVSS 3.0 Base Score: 7.5'
    We try to extract the highest one if multiple are present.
    """
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
    """Convert a numeric CVSS score to a human-readable severity label."""
    if score is None:
        return "Unknown"
    for label, (low, high) in SEVERITY_BANDS.items():
        if label == "Unknown":
            continue
        if low <= score <= high:
            return label
    return "Unknown"


def detect_sector(text):
    """
    Scan advisory text for sector keywords.
    In real threat intel work, this kind of tagging is done by the platform —
    you are replicating that logic manually here so you understand it.
    """
    text_lower = text.lower()
    detected = []
    for sector, keywords in SECTOR_KEYWORDS.items():
        if any(kw in text_lower for kw in keywords):
            detected.append(sector)
    return detected if detected else ["Critical Infrastructure"]


def extract_vendor(title):
    """
    CISA advisory titles usually start with the vendor name.
    Examples:
      'Siemens SINEMA Remote Connect Server' -> 'Siemens'
      'Rockwell Automation FactoryTalk' -> 'Rockwell Automation'
      'Schneider Electric EcoStruxure' -> 'Schneider Electric'
    These are the exact vendors you will encounter at Shieldworkz.
    """
    # Common two-word vendor names to preserve
    two_word_vendors = [
        "Rockwell Automation", "Schneider Electric", "General Electric",
        "Emerson Electric", "Beckhoff Automation", "Phoenix Contact",
        "Mitsubishi Electric", "ABB Ltd", "Delta Electronics",
    ]
    for vendor in two_word_vendors:
        if title.lower().startswith(vendor.lower()):
            return vendor

    # Fall back to first word of title
    first_word = title.split()[0] if title.split() else "Unknown"
    # Filter out non-vendor openers
    skip_words = ["CISA", "ICS", "Advisory", "Multiple", "Update"]
    if first_word in skip_words:
        return "Multiple Vendors"
    return first_word


def parse_advisory(entry):
    """
    Transform a raw feedparser entry into a clean advisory dict.
    This is the core function — every field here maps to something
    you will see on a real SOC dashboard or SIEM alert.
    """
    title = entry.get("title", "Untitled Advisory")
    summary = entry.get("summary", "")
    link = entry.get("link", "#")

    published_raw = entry.get("published_parsed")
    if published_raw:
        published = datetime(*published_raw[:6]).strftime("%Y-%m-%d")
    else:
        published = "Unknown"

    full_text = f"{title} {summary}"

    cves = extract_cves(full_text)
    cvss_score = extract_cvss_score(full_text)

    # If RSS text didn't have a score, ask NVD directly for the first CVE
    if cvss_score is None and cves:
        cvss_score = fetch_cvss_from_nvd(cves[0])

    severity = score_to_severity(cvss_score)
    sectors = detect_sector(full_text)
    vendor = extract_vendor(title)

    return {
        "title": title,
        "vendor": vendor,
        "link": link,
        "published": published,
        "severity": severity,
        "cvss_score": cvss_score,
        "cves": cves,
        "cve_count": len(cves),
        "sectors": sectors,
        "summary_snippet": summary[:300] + "..." if len(summary) > 300 else summary,
    }

def fetch_advisories(limit=50):
    """
    Main entry point. Fetches both CISA feeds, parses all entries,
    sorts by date descending (newest first — standard SOC practice),
    and returns a clean list.

    Returns an empty list on failure rather than crashing —
    in a SOC tool, graceful degradation matters.
    """
    all_advisories = []

    for feed_url in [CISA_ICS_FEED, CISA_ICS_MEDICAL_FEED]:
        try:
            feed = feedparser.parse(feed_url)

            if feed.bozo:
                # bozo=True means feedparser hit a parsing issue but still got data
                # This is common with slightly malformed XML — we continue anyway
                print(f"[fetcher] Warning: feed parsing issue for {feed_url}")

            for entry in feed.entries:
                parsed = parse_advisory(entry)
                all_advisories.append(parsed)

        except Exception as e:
            print(f"[fetcher] Error fetching {feed_url}: {e}")
            continue

    # Sort newest first — same as how a SIEM surfaces alerts
    all_advisories.sort(key=lambda x: x["published"], reverse=True)

    return all_advisories[:limit]


def get_summary_stats(advisories):
    """
    Aggregate stats for the dashboard header cards.
    Counting by severity is the first thing a SOC analyst does
    when they start a shift — how many criticals am I walking into?
    """
    stats = {
        "total": len(advisories),
        "Critical": 0,
        "High": 0,
        "Medium": 0,
        "Low": 0,
        "Unknown": 0,
        "sectors": {},
        "vendors": {},
    }

    for adv in advisories:
        severity = adv.get("severity", "Unknown")
        stats[severity] = stats.get(severity, 0) + 1

        for sector in adv.get("sectors", []):
            stats["sectors"][sector] = stats["sectors"].get(sector, 0) + 1

        vendor = adv.get("vendor", "Unknown")
        stats["vendors"][vendor] = stats["vendors"].get(vendor, 0) + 1

    # Sort sectors and vendors by count descending
    stats["sectors"] = dict(
        sorted(stats["sectors"].items(), key=lambda x: x[1], reverse=True)
    )
    stats["top_vendors"] = dict(
        sorted(stats["vendors"].items(), key=lambda x: x[1], reverse=True)[:8]
    )

    return stats


# Quick test — run this file directly to see live CISA data in your terminal
# Command: python fetcher.py
if __name__ == "__main__":
    print("[*] Fetching CISA ICS advisories...")
    advisories = fetch_advisories(limit=10)

    print(f"\n[+] Got {len(advisories)} advisories\n")
    for adv in advisories:
        severity_marker = {
            "Critical": "🔴",
            "High":     "🟠",
            "Medium":   "🟡",
            "Low":      "🟢",
            "Unknown":  "⚪",
        }.get(adv["severity"], "⚪")

        print(f"{severity_marker} [{adv['published']}] {adv['vendor']} — {adv['title'][:60]}")
        if adv["cves"]:
            print(f"   CVEs: {', '.join(adv['cves'][:3])}")
        if adv["cvss_score"]:
            print(f"   CVSS: {adv['cvss_score']} ({adv['severity']})")
        print(f"   Sectors: {', '.join(adv['sectors'])}")
        print()

    stats = get_summary_stats(advisories)
    print(f"[STATS] Critical: {stats['Critical']} | High: {stats['High']} | Medium: {stats['Medium']}")
    print(f"[TOP SECTORS] {list(stats['sectors'].keys())[:4]}")