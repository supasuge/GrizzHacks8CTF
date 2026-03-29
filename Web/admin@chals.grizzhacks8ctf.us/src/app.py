from __future__ import annotations
import html
import os
from pathlib import Path
from flask import Flask, redirect, render_template, request, url_for
APP_DIR = Path(__file__).resolve().parent
SCROLLS_DIR = (APP_DIR / "scrolls").resolve()
app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", os.urandom(32))

def render_safe_md(md: str) -> str:
    """
    Safe-ish minimal markdown renderer:
    """
    src = html.escape(md, quote=True)
    lines = src.splitlines()
    out = []
    in_ul = False
    def close_ul():
        nonlocal in_ul
        if in_ul:
            out.append("</ul>")
            in_ul = False
    for raw in lines:
        line = raw.rstrip()
        if line.startswith("# "):
            close_ul()
            out.append(f"<h1>{line[2:].strip()}</h1>")
            continue
        if line.startswith("## "):
            close_ul()
            out.append(f"<h2>{line[3:].strip()}</h2>")
            continue
        if line.startswith("- "):
            if not in_ul:
                out.append("<ul>")
                in_ul = True
            out.append(f"<li>{line[2:].strip()}</li>")
            continue
        # blank line
        if line.strip() == "":
            close_ul()
            out.append("<div class='spacer'></div>")
            continue
        close_ul()
        out.append(f"<p>{line}</p>")
    close_ul()
    return "\n".join(out)



def resolve_archive_ref(user_ref: str) -> Path:
    """
    Resolves a user-provided archive reference to a local file path
    """
    if not user_ref:
        raise ValueError("ref is required")
    ref = user_ref.strip()
    if "." not in Path(ref).name:
        ref += ".md"
    if len(ref) > 180:
        raise ValueError("ref is too long")
    candidate = (SCROLLS_DIR / ref).resolve()
    base_str = str(SCROLLS_DIR)
    cand_str = str(candidate)
    if not cand_str.startswith(base_str):
        raise ValueError("ref is out of pantry bounds")
    return candidate

@app.after_request
def add_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    csp = (
        "default-src 'self'; "
        "base-uri 'none'; "
        "object-src 'none'; "
        "frame-ancestors 'none'; "
        "form-action 'self'; "
        "script-src 'none'; "
        "style-src 'self' https://cdn.jsdelivr.net; "
        "img-src 'self' data:; "
        "font-src 'self' https://cdn.jsdelivr.net data:; "
        "connect-src 'self'; "
    )
    resp.headers["Content-Security-Policy"] = csp
    resp.headers["X-XSS-Protection"] = "0"
    return resp

@app.get("/")
def index():
    featured = [
        "classic/soup_001",
        "classic/soup_002",
        "classic/soup_003",
        "chef/notes",
    ]
    return render_template("index.html", featured=featured)

@app.get("/slurp")
def slurp():
    ref = request.args.get("ladle", "").strip()
    if not ref:
        return (
            render_template(
                "error.html",
                title="Missing ladle reference",
                message="Provide a recipe reference in the ladle query parameter before fetching.",
                status=400,
            ),
            400,
        )
    elif ref.startswith(".."):
        return (
            render_template(
                "error.html",
                title="Hacking detected 🐻",
                message="You are not allowed to access this resource.",
                status=403,
            ),
            403,
        )
    try:
        path = resolve_archive_ref(ref)
        data = path.read_text(encoding="utf-8", errors="strict")
    except UnicodeDecodeError:
        return (
            render_template(
                "error.html",
                title="That ladle scooped bytes, not soup ☠️",
                message="This archive item isn't edible text. Try another recipe scroll. Or maybe you should just go back to the index and start over.",
                status=415,
            ),
            415,
        )
    except (OSError, ValueError):
        return (
            render_template(
                "error.html",
                title="Pantry access denied 🐻",
                message="The Grizzly Librarian refuses to fetch that archive item, unfortunate my friend. What shall you do now?",
                status=404,
            ),
            404,
        )
    rendered = render_safe_md(data)
    return render_template("slurp.html", ref=ref, rendered=rendered)


@app.get("/health")
def health():
    return render_template("health.html", status="OK", status_class="success")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "1337")), debug=False) 
