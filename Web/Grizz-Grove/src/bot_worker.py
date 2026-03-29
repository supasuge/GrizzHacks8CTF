#!/usr/bin/env python3
from __future__ import annotations

import os
import sqlite3
import time
from urllib.parse import urljoin, urlparse, parse_qsl, urlencode, urlunparse

from playwright.sync_api import sync_playwright


APP_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get("DB_PATH", os.path.join(APP_DIR, "state.db"))

BASE_URL = os.environ.get("BOT_BASE_URL", "http://127.0.0.1:8080")
VISIT_TIMEOUT_MS = int(os.environ.get("BOT_VISIT_TIMEOUT_MS", "6000"))
SETTLE_TIMEOUT_MS = int(os.environ.get("BOT_SETTLE_TIMEOUT_MS", "2500"))
POLL_INTERVAL = float(os.environ.get("BOT_POLL_INTERVAL", "0.75"))
MAX_PER_LOOP = int(os.environ.get("BOT_MAX_PER_LOOP", "2"))
TTL_SECONDS = int(os.environ.get("SUBMISSION_TTL_SECONDS", "1800"))

DB_TIMEOUT = float(os.environ.get("DB_TIMEOUT", "10.0"))
DB_BUSY_TIMEOUT_MS = int(os.environ.get("DB_BUSY_TIMEOUT_MS", "5000"))

def db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, timeout=DB_TIMEOUT)
    conn.row_factory = sqlite3.Row
    conn.execute(f"PRAGMA busy_timeout={DB_BUSY_TIMEOUT_MS};")
    conn.execute("PRAGMA foreign_keys=ON;")
    return conn


def cleanup_old(conn: sqlite3.Connection) -> None:
    cutoff = int(time.time()) - TTL_SECONDS
    conn.execute(
        "DELETE FROM submissions WHERE created_at < ? OR (consumed_at IS NOT NULL AND consumed_at < ?)",
        (cutoff, cutoff),
    )


def recover_stale_visits(conn: sqlite3.Connection) -> None:
    cutoff = int(time.time()) - TTL_SECONDS
    conn.execute(
        "UPDATE submissions SET status='queued' WHERE status='visiting' AND created_at >= ?",
        (cutoff,),
    )


def db_write(fn, tries: int = 7) -> None:
    delay = 0.05
    for _ in range(tries):
        try:
            with db() as conn:
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


def append_ticket(path: str, ticket: str) -> str:
    u = urlparse(path)
    q = dict(parse_qsl(u.query, keep_blank_values=True))
    q["ticket"] = ticket
    return urlunparse((u.scheme, u.netloc, u.path, u.params, urlencode(q, doseq=True), u.fragment))


def main() -> None:
    print(
        f"[bot] BASE_URL={BASE_URL} DB_PATH={DB_PATH} "
        f"VISIT_TIMEOUT_MS={VISIT_TIMEOUT_MS} SETTLE_TIMEOUT_MS={SETTLE_TIMEOUT_MS}"
    )

    with sync_playwright() as p:
        browser = p.chromium.launch(
            headless=True,
            args=["--no-sandbox", "--disable-dev-shm-usage", "--disable-gpu"],
        )
        ctx = browser.new_context()
        ctx.add_cookies([{
            "name": "ranger",
            "value": "1",
            "url": BASE_URL + "/",
            "httpOnly": True,
            "sameSite": "Lax",
        }])

        while True:
            with db() as conn:
                cleanup_old(conn)
                recover_stale_visits(conn)
                rows = conn.execute(
                    "SELECT ticket, path FROM submissions WHERE status='queued' ORDER BY created_at ASC LIMIT ?",
                    (MAX_PER_LOOP,),
                ).fetchall()

            if not rows:
                time.sleep(POLL_INTERVAL)
                continue

            for r in rows:
                ticket = r["ticket"]
                path = r["path"]

                def _mark_visiting(c: sqlite3.Connection):
                    c.execute(
                        "UPDATE submissions SET status='visiting' WHERE ticket=? AND status='queued'",
                        (ticket,),
                    )

                db_write(_mark_visiting)

                visited_path = append_ticket(path, ticket)
                url = urljoin(BASE_URL, visited_path.lstrip("/"))
                print(f"[bot] Visiting ticket={ticket} url={url}")

                page = None
                try:
                    page = ctx.new_page()
                    page.goto(url, wait_until="domcontentloaded", timeout=VISIT_TIMEOUT_MS)
                    try:
                        page.wait_for_load_state("networkidle", timeout=SETTLE_TIMEOUT_MS)
                    except Exception:
                        page.wait_for_timeout(SETTLE_TIMEOUT_MS)

                    def _mark_visited(c: sqlite3.Connection):
                        c.execute(
                            "UPDATE submissions SET status='visited', visited_at=? WHERE ticket=?",
                            (int(time.time()), ticket),
                        )

                    db_write(_mark_visited)
                except Exception as e:
                    def _mark_error(c: sqlite3.Connection):
                        c.execute(
                            "UPDATE submissions SET status='error', visited_at=? WHERE ticket=?",
                            (int(time.time()), ticket),
                        )
                    db_write(_mark_error)
                    print(f"[bot] Error ticket={ticket}: {type(e).__name__}: {e}")
                finally:
                    if page is not None:
                        try:
                            page.close()
                        except Exception:
                            pass


if __name__ == "__main__":
    main()
