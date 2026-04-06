from flask import Flask, jsonify, render_template
from apscheduler.schedulers.background import BackgroundScheduler
from fetcher import fetch_advisories, get_summary_stats
from datetime import datetime
import atexit

app = Flask(__name__)

# In-memory cache — simple and sufficient for a portfolio project
# In a real SOC tool this would be Redis or a database
_cache = {
    "advisories": [],
    "stats": {},
    "last_updated": None,
    "is_loading": True,
}


def refresh_cache():
    """
    Pull fresh advisories from CISA and update the cache.
    Called once on startup and then every 30 minutes automatically.
    This is the pattern used in real threat intel pipelines —
    scheduled pulls rather than on-demand to avoid hammering external APIs.
    """
    print(f"[scheduler] Refreshing advisory cache at {datetime.utcnow().isoformat()}Z")
    try:
        advisories = fetch_advisories(limit=60)
        stats = get_summary_stats(advisories)
        _cache["advisories"] = advisories
        _cache["stats"] = stats
        _cache["last_updated"] = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
        _cache["is_loading"] = False
        print(f"[scheduler] Cache updated — {len(advisories)} advisories loaded.")
    except Exception as e:
        print(f"[scheduler] Refresh failed: {e}")
        _cache["is_loading"] = False


# Load data immediately on startup (don't wait for the first scheduled run)
refresh_cache()

# Schedule automatic refresh every 30 minutes
scheduler = BackgroundScheduler()
scheduler.add_job(func=refresh_cache, trigger="interval", minutes=30)
scheduler.start()

# Shut down the scheduler cleanly when the app exits
atexit.register(lambda: scheduler.shutdown())


@app.route("/")
def index():
    """Serve the main dashboard page."""
    return render_template("index.html")


@app.route("/api/advisories")
def api_advisories():
    """
    JSON API endpoint — returns all cached advisories + summary stats.
    The frontend fetches this on load and on manual refresh.
    Having a clean REST API (even for a solo project) is good practice —
    it separates your data layer from your presentation layer.
    """
    return jsonify({
        "advisories": _cache["advisories"],
        "stats": _cache["stats"],
        "last_updated": _cache["last_updated"],
        "is_loading": _cache["is_loading"],
        "count": len(_cache["advisories"]),
    })


@app.route("/api/health")
def health():
    """
    Health check endpoint — standard practice for any deployed service.
    Railway and other platforms ping this to verify the app is alive.
    """
    return jsonify({
        "status": "ok",
        "advisories_loaded": len(_cache["advisories"]),
        "last_updated": _cache["last_updated"],
    })


if __name__ == "__main__":
    # debug=False in production — never expose debug mode on a live server
    app.run(debug=False, host="0.0.0.0", port=5000)