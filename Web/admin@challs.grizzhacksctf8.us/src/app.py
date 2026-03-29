from __future__ import annotations

import json
import os
import re
import secrets
import sqlite3
import time
from pathlib import Path

from flask import Flask, Response, make_response, redirect, render_template, request, url_for


APP_DIR = Path(__file__).resolve().parent
DB_PATH = Path(os.environ.get("DB_PATH", str(APP_DIR / "state.db")))

FLAG_PATH = Path(os.environ.get("FLAG_PATH", "/flag.txt"))
FALLBACK_FLAG_PATH = APP_DIR / "flag.txt"

TTL_SECONDS = int(os.environ.get("SUBMISSION_TTL_SECONDS", "1800"))
FLAG_RE = re.compile(r"GRIZZ\{[^}]+\}")

DB_TIMEOUT = float(os.environ.get("DB_TIMEOUT", "10.0"))           # seconds
DB_BUSY_TIMEOUT_MS = int(os.environ.get("DB_BUSY_TIMEOUT_MS", "5000"))  # ms

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-secret-that-bears-can-smell")


def db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, timeout=DB_TIMEOUT)
    conn.row_factory = sqlite3.Row
    # These pragmas are per-connection
    conn.execute(f"PRAGMA busy_timeout={DB_BUSY_TIMEOUT_MS};")
    conn.execute("PRAGMA foreign_keys=ON;")
    return conn


def init_db() -> None:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with db() as conn:
        # WAL makes concurrent read/write much more robust
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS submissions (
              ticket TEXT PRIMARY KEY,
              path TEXT NOT NULL,
              created_at INTEGER NOT NULL,
              status TEXT NOT NULL,          -- queued|visiting|visited|error
              visited_at INTEGER,
              report TEXT,
              consumed_at INTEGER
            )
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_sub_status ON submissions(status, created_at)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_sub_created ON submissions(created_at)")
        conn.commit()


def cleanup_old(conn: sqlite3.Connection) -> None:
    cutoff = int(time.time()) - TTL_SECONDS
    conn.execute(
        "DELETE FROM submissions WHERE created_at < ? OR (consumed_at IS NOT NULL AND consumed_at < ?)",
        (cutoff, cutoff),
    )


def db_write(fn, tries: int = 7) -> None:
    """
    Retry writes if the DB is busy/locked.
    This handles bot+web collisions in a single-container setup.
    """
    delay = 0.05
    for attempt in range(tries):
        try:
            with db() as conn:
                # Acquire write intent early
                conn.execute("BEGIN IMMEDIATE;")
                fn(conn)
                conn.commit()
                return
        except sqlite3.OperationalError as e:
            msg = str(e).lower()
            if "locked" in msg or "busy" in msg:
                time.sleep(delay)
                delay = min(delay * 2, 0.8)
                continue
            raise
    raise sqlite3.OperationalError("database is locked (exhausted retries)")


init_db()


def _read_flag() -> str:
    try:
        return FLAG_PATH.read_text(encoding="utf-8").strip()
    except OSError:
        return FALLBACK_FLAG_PATH.read_text(encoding="utf-8").strip()


def _set_security_headers(resp: Response) -> Response:
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    csp = (
        "default-src 'self'; "
        "base-uri 'none'; "
        "object-src 'none'; "
        "frame-ancestors 'none'; "
        "form-action 'self'; "
        "script-src 'self'; "
        "style-src 'self'; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "font-src 'self' data:; "
    )
    resp.headers["Content-Security-Policy"] = csp
    resp.headers["X-XSS-Protection"] = "0"
    return resp


@app.after_request
def after(resp):
    return _set_security_headers(resp)


@app.get("/favicon.ico")
def favicon():
    return ("", 204)


@app.get("/")
def index():
    moods = [
        ("cedar", "Cedar Calm"),
        ("moss", "Moss Mode"),
        ("ember", "Ember Glow"),
        ("river", "River Reflection"),
    ]
    return render_template("index.html", moods=moods)


@app.get("/submit")
def submit_get():
    return render_template("submit.html", ticket=None, path_value="", message=None)


@app.post("/submit")
def submit_post():
    path = (request.form.get("path") or "").strip()
    if not path:
        return render_template("submit.html", ticket=None, path_value="", message="Path is required."), 400

    if not path.startswith("/"):
        return render_template("submit.html", ticket=None, path_value=path, message="Path must start with '/'."), 400
    if "://" in path or path.startswith("//"):
        return render_template("submit.html", ticket=None, path_value=path, message="Only same-origin paths allowed."), 400
    if len(path) > 1800:
        return render_template("submit.html", ticket=None, path_value=path, message="Path too long."), 400

    ticket = secrets.token_urlsafe(16)
    now = int(time.time())

    def _write(conn: sqlite3.Connection):
        cleanup_old(conn)
        conn.execute(
            "INSERT INTO submissions(ticket, path, created_at, status) VALUES(?, ?, ?, 'queued')",
            (ticket, path, now),
        )

    db_write(_write)

    return render_template(
        "submit.html",
        ticket=ticket,
        path_value=path,
        message="Queued. The ranger-bot will visit shortly. Don’t blink.",
    )


@app.get("/reports")
def reports():
    ticket = (request.args.get("ticket") or "").strip()
    if not ticket:
        return render_template("reports.html", ticket=None, status=None, report=None, consumed=False)

    with db() as conn:
        cleanup_old(conn)
        row = conn.execute("SELECT * FROM submissions WHERE ticket = ?", (ticket,)).fetchone()
        if not row:
            return render_template("error.html", title="No such ticket 🧾", message="That ticket does not exist.", status=404), 404

        consumed = row["consumed_at"] is not None
        report = row["report"]
        status = row["status"]

    # One-time retrieval: clear report after first view (write w/ retry)
    if report and not consumed:
        def _consume(conn: sqlite3.Connection):
            conn.execute(
                "UPDATE submissions SET report = NULL, consumed_at = ? WHERE ticket = ?",
                (int(time.time()), ticket),
            )
        db_write(_consume)
        return render_template("reports.html", ticket=ticket, status=status, report=report, consumed=False)

    return render_template("reports.html", ticket=ticket, status=status, report=None, consumed=consumed)


@app.get("/report")
def report():
    ticket = (request.args.get("ticket") or "").strip()
    d = request.args.get("d", "")
    if not ticket or not d:
        return ("", 400)

    d = d[:5000]

    def _store(conn: sqlite3.Connection):
        cleanup_old(conn)
        row = conn.execute("SELECT * FROM submissions WHERE ticket = ?", (ticket,)).fetchone()
        if not row:
            raise FileNotFoundError("ticket not found")
        if row["consumed_at"] is not None:
            raise PermissionError("consumed")

        conn.execute(
            "UPDATE submissions SET report = ?, status = CASE WHEN status IN ('queued','visiting') THEN 'visited' ELSE status END WHERE ticket = ?",
            (d, ticket),
        )

    try:
        db_write(_store)
    except FileNotFoundError:
        return ("", 404)
    except PermissionError:
        return ("", 410)

    return ("", 204)


@app.get("/bear-den")
def bear_den():
    if request.cookies.get("ranger") != "1":
        return render_template(
            "error.html",
            title="Access denied 🐻",
            message="The Grizzly Ranger says you don't have the right badge. Shocking.",
            status=403,
        ), 403

    try:
        flag = _read_flag()
    except OSError as e:
        return render_template(
            "error.html",
            title="Den malfunction 🧯",
            message=(
                "Flag file missing.\n\n"
                f"Expected flag at {FLAG_PATH} or {FALLBACK_FLAG_PATH}.\n"
                f"Error: {type(e).__name__}: {e}\n"
            ),
            status=500,
        ), 500

    return render_template("den.html", flag=flag)


@app.get("/api/pollen")
def api_pollen():
    cb = request.args.get("wind", "console.log")
    if "\n" in cb or "\r" in cb:
        return Response("/* wind too spicy */", mimetype="application/javascript")

    payload = {"forecast": "100% chance of bear", "advice": "Do not run. Bears love cardio."}
    js = f"({cb})({json.dumps(payload)});"
    return Response(js, mimetype="application/javascript")


@app.get("/themes/<path:name>")
def theme_js(name: str):
    if not re.fullmatch(r"[a-z0-9_-]{1,24}\.js", name):
        return Response("/* no */", mimetype="application/javascript")

    themes = {
        "cedar.js": {"--accent": "#36d399", "--accent2": "#a7f3d0", "--glow": "rgba(54, 211, 153, .35)", "label": "CEDAR CALM"},
        "moss.js":  {"--accent": "#22c55e", "--accent2": "#bbf7d0", "--glow": "rgba(34, 197, 94, .35)", "label": "MOSS MODE"},
        "ember.js": {"--accent": "#fb7185", "--accent2": "#fecdd3", "--glow": "rgba(251, 113, 133, .35)", "label": "EMBER GLOW"},
        "river.js": {"--accent": "#60a5fa", "--accent2": "#bfdbfe", "--glow": "rgba(96, 165, 250, .30)", "label": "RIVER REFLECTION"},
    }

    t = themes.get(name)
    if not t:
        return Response("/* unknown theme */", mimetype="application/javascript")

    js = f"""
(() => {{
  const root = document.documentElement;
  root.style.setProperty('--accent', '{t["--accent"]}');
  root.style.setProperty('--accent2', '{t["--accent2"]}');
  root.style.setProperty('--glow', '{t["--glow"]}');
  const el = document.querySelector('[data-mood-label]');
  if (el) el.textContent = '{t["label"]}';
}})();
"""
    return Response(js, mimetype="application/javascript")


@app.get("/__debug/ranger-login")
def debug_ranger_login():
    if os.environ.get("ENABLE_DEBUG_LOGIN") != "1":
        return ("nope", 404)
    resp = make_response(redirect(url_for("index")))
    resp.set_cookie("ranger", "1", httponly=True, samesite="Lax")
    return resp


@app.get("/health")
def health():
    return {"ok": True}
