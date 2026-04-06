# OT/ICS Threat Dashboard

A live SOC-style web dashboard that monitors CISA ICS-CERT advisories and surfaces
OT/ICS threats by severity, sector, and vendor — built for Blue Team analysts
who need a fast way to stay current on industrial cybersecurity threats.

**Live demo:** [ot-threat-dashboard.onrender.com](https://ot-threat-dashboard.onrender.com)

---

## The problem

OT environments — power grids, water systems, factories — run on industrial control
systems never designed with cybersecurity in mind. CISA publishes advisories for
these systems regularly, but reading them from a raw feed is slow. SOC analysts
need a triage view, not raw XML.

## What this does

- Fetches CISA ICS-CERT advisory feed every 30 minutes automatically
- Enriches each advisory with live CVSS scores from the NVD API
- Displays severity donut chart and top sector breakdown
- Filterable table by severity and sector with column sorting
- Click any row to open a detail panel with full CVE list and NVD links
- One-click CVE copy for fast incident ticket writing
- Vendor risk tracker showing most-active vendors this week
- Keyboard shortcuts: / to search, Esc to close panel

## Tech stack

Python · Flask · feedparser · APScheduler · Chart.js · Render (deployment)

## Run locally
```bash
git clone https://github.com/HarshAsolkar/ot-threat-dashboard
cd ot-threat-dashboard
py -3.11 -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
python app.py
# Open http://localhost:5000
```

## What I learned

- How CVSS scoring works in practice and how NVD structures vulnerability data
- Which vendors dominate OT advisories — Siemens, Schneider Electric, Hitachi Energy
- The difference between IT and OT threat intelligence — OT focuses on
  availability and physical safety, not just data confidentiality
- How scheduled background pipelines handle graceful API failure
- How to build a REST API that separates data layer from presentation layer

## API endpoints

`GET /api/advisories` — returns JSON of all parsed advisories and summary stats
`GET /api/health` — health check for uptime monitoring

---

Built by [Harsh Asolkar](https://github.com/HarshAsolkar) — SOC Analyst · Shieldworkz
