#!/usr/bin/env python3
from __future__ import annotations

import os
import secrets
import time
from pathlib import Path

from flask import (
    Flask,
    abort,
    flash,
    redirect,
    render_template,
    request,
    send_file,
    send_from_directory,
    session,
    url_for,
)

APP_DIR = Path(__file__).resolve().parent
UPLOAD_DIR = APP_DIR / "uploads"

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", secrets.token_hex(16))

ALLOWED_EXTS = {"png", "jpg", "jpeg", "gif", "webp"}

AVATAR_TTL_SECONDS = int(os.environ.get("AVATAR_TTL_SECONDS", "900"))

AVATAR_REGISTRY: dict[str, dict[str, object]] = {}


def now() -> float:
    return time.time()


def allowed_ext(filename: str) -> bool:
    if "." not in filename:
        return False
    ext = filename.rsplit(".", 1)[1].lower()
    return ext in ALLOWED_EXTS


def ensure_session_identity() -> None:
    if "sid" not in session:
        session["sid"] = secrets.token_hex(16)


def cleanup_expired_avatars() -> None:
    t = now()
    expired_sids = [sid for sid, meta in AVATAR_REGISTRY.items() if float(meta["expires_at"]) <= t]
    for sid in expired_sids:
        meta = AVATAR_REGISTRY.pop(sid, None)
        if not meta:
            continue
        filename = str(meta.get("filename", ""))
        if filename:
            try:
                (UPLOAD_DIR / filename).unlink(missing_ok=True)
            except Exception:
                pass


def delete_session_avatar(sid: str) -> None:
    meta = AVATAR_REGISTRY.pop(sid, None)
    if not meta:
        return
    filename = str(meta.get("filename", ""))
    if filename:
        try:
            (UPLOAD_DIR / filename).unlink(missing_ok=True)
        except Exception:
            pass


@app.before_request
def _pre_request_housekeeping():
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    cleanup_expired_avatars()
    ensure_session_identity()


@app.get("/")
def index():
    return render_template("index.html")


@app.post("/register")
def register():
    username = (request.form.get("username") or "").strip()
    if not username or len(username) > 32:
        flash("Pick a callsign (1-32 chars).", "error")
        return redirect(url_for("index"))

    sid = session.get("sid")
    if sid:
        delete_session_avatar(str(sid))

    session["username"] = username
    session["has_avatar"] = False
    session["avatar_exp"] = None

    flash("Callsign accepted. Upload your badge avatar to proceed.", "ok")
    return redirect(url_for("profile"))


@app.get("/profile")
def profile():
    username = session.get("username")
    if not username:
        return redirect(url_for("index"))

    remaining = None
    if session.get("has_avatar") and session.get("avatar_exp"):
        remaining = max(0, int(float(session["avatar_exp"]) - now()))

    return render_template(
        "profile.html",
        username=username,
        has_avatar=bool(session.get("has_avatar")),
        avatar_remaining=remaining,
    )


@app.post("/upload")
def upload():
    username = session.get("username")
    if not username:
        return redirect(url_for("index"))

    if "avatar" not in request.files:
        flash("No file part found.", "error")
        return redirect(url_for("profile"))

    f = request.files["avatar"]
    if not f or not f.filename:
        flash("Choose an image to upload.", "error")
        return redirect(url_for("profile"))

    if not allowed_ext(f.filename):
        flash("That file type is not accepted. Use png/jpg/gif/webp.", "error")
        return redirect(url_for("profile"))

    sid = str(session["sid"])

    delete_session_avatar(sid)

    safe_ext = f.filename.rsplit(".", 1)[1].lower()
    stored_name = f"{sid}_{secrets.token_hex(8)}.avatar.{safe_ext}"
    dst = UPLOAD_DIR / stored_name
    f.save(dst)

    expires_at = now() + AVATAR_TTL_SECONDS
    AVATAR_REGISTRY[sid] = {"filename": stored_name, "expires_at": expires_at}

    session["has_avatar"] = True
    session["avatar_exp"] = expires_at

    flash("Avatar uploaded. Your Nebula ID badge is ready.", "ok")
    return redirect(url_for("profile"))


@app.get("/me/avatar")
def my_avatar():
    username = session.get("username")
    if not username:
        abort(403)

    sid = str(session.get("sid", ""))
    meta = AVATAR_REGISTRY.get(sid)
    if not meta:
        abort(404)

    if float(meta["expires_at"]) <= now():
        delete_session_avatar(sid)
        abort(404)

    filename = str(meta["filename"])
    return send_from_directory(UPLOAD_DIR, filename, as_attachment=False)


@app.get("/vault/<path:filename>")
def vault(filename: str):
    target = UPLOAD_DIR / filename
    if not target.exists():
        abort(404)
    return send_file(target)


@app.get("/health")
def health():
    return {"ok": True}


if __name__ == "__main__":
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    app.run(host="0.0.0.0", port=6969, debug=False)