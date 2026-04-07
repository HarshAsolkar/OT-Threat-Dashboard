from flask import Flask, jsonify, render_template
from apscheduler.schedulers.background import BackgroundScheduler
from fetcher import fetch_advisories, get_summary_stats
from datetime import datetime
import atexit

app = Flask(__name__)

_cache = {
    "advisories": [],
    "stats": {},
    "last_updated": None,
    "is_loading": True,
}


def refresh_cache():
    print(f"[scheduler] Refreshing at {datetime.utcnow().isoformat()}Z")
    try:
        advisories = fetch_advisories(limit=60)
        stats = get_summary_stats(advisories)
        _cache["advisories"] = advisories
        _cache["stats"] = stats
        _cache["last_updated"] = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
        _cache["is_loading"] = False
        print(f"[scheduler] Done — {len(advisories)} advisories loaded.")
    except Exception as e:
        print(f"[scheduler] Refresh failed: {e}")
        _cache["is_loading"] = False


# load on startup
refresh_cache()

# schedule every 30 min
scheduler = BackgroundScheduler()
scheduler.add_job(func=refresh_cache, trigger="interval", minutes=30)
scheduler.start()
atexit.register(lambda: scheduler.shutdown())


@app.route("/")
def index():
    # force a refresh if cache is older than 60 minutes or empty
    # this handles Render free tier spin-down problem
    if not _cache["advisories"] or _cache["last_updated"] is None:
        refresh_cache()
    return render_template("index.html")


@app.route("/api/advisories")
def api_advisories():
    return jsonify({
        "advisories": _cache["advisories"],
        "stats": _cache["stats"],
        "last_updated": _cache["last_updated"],
        "is_loading": _cache["is_loading"],
        "count": len(_cache["advisories"]),
    })


@app.route("/api/refresh")
def api_refresh():
    """
    Force a full cache rebuild.
    Called by the frontend refresh button — returns fresh data immediately.
    """
    refresh_cache()
    return jsonify({
        "advisories": _cache["advisories"],
        "stats": _cache["stats"],
        "last_updated": _cache["last_updated"],
        "count": len(_cache["advisories"]),
        "refreshed": True,
    })


@app.route("/api/health")
def health():
    return jsonify({
        "status": "ok",
        "advisories_loaded": len(_cache["advisories"]),
        "last_updated": _cache["last_updated"],
    })


if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0", port=5000)