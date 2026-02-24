# Solution — Nebula Vault (`solve.py`)

This solver is basically “do what a human would do in the browser”, but automated:

1) hit the homepage to get a session  
2) register a callsign  
3) upload an avatar (forced step)  
4) optionally verify the secure avatar endpoint works  
5) abuse the Vault route to path-traverse into `/app/flag.txt`

---

## Run it

If you’re running the challenge locally on the updated port:

```bash
python3 solve.py --base http://127.0.0.1:6969
````

If you changed ports / host, just swap `--base`.

Optional: skip the `/me/avatar` check:

```bash
python3 solve.py --base http://127.0.0.1:6969 --no-avatar-check
```

---

## What the script is doing (step-by-step, no fluff)

### 0) Establish a session

```py
r = s.get(f"{base}/", ...)
```

This matters because the app creates a per-session `sid` (server-side identity) using cookies.
No cookie = no consistent “you”.

So the script hits `/` first so the session cookie exists for the rest of the flow.

---

### 1) Register callsign

```py
s.post(f"{base}/register", data={"username": args.callsign}, allow_redirects=True)
```

This mirrors the UI: you submit a callsign, server stores it in session, and sends you to `/profile`.

---

### 2) Upload avatar (forced step)

```py
fake_png = b"\x89PNG\r\n\x1a\n" + b"CTFCTFCTF"
files = {"avatar": ("avatar.png", fake_png, "image/png")}
s.post(f"{base}/upload", files=files, allow_redirects=True)
```

The app forces the upload, so we do it too.

Important detail: we don’t need a real image.
We just need:

* a filename ending in `.png`
* some bytes (we throw in the PNG magic header so it looks legit-ish)

Upload is *session-bound* and *ephemeral* on the server, but that doesn’t stop the exploit — it’s just nice app hygiene.

---

### 3) (Optional) Verify secure avatar endpoint works

```py
r = s.get(f"{base}/me/avatar")
```

This is not required to get the flag. It’s just sanity:

* `/me/avatar` is the secure endpoint (no filename in the URL)
* it proves the session cookie is working
* and that the app stored our avatar for this session

You can skip this with `--no-avatar-check`.

---

### 4) Exploit the vulnerable Vault endpoint

- `%2e%2e` == `urlencode('..')`

```python
exploit_url = f"{base}/vault/%2e%2e/flag.txt"
r = s.get(exploit_url)
```

This is the actual exploit.

The Vault route does something like:

* takes `filename` from the URL
* does `UPLOAD_DIR / filename`
* then `send_file(...)`

So if we give it `../flag.txt`, we escape `/app/uploads` and land at `/app/flag.txt`.

**But** we don’t send raw `../` because clients/proxies love “helpfully” normalizing paths.
That’s why we use:

* `%2e%2e` → URL-decoded to `..` on the server
* resulting path → `../flag.txt`

So the server reads the flag and returns it.

---

## Output / UX stuff

The ANSI codes are just there so it prints like:

* `[*]` info lines
* `[+]` success lines
* `[-]` failure lines

Also: `must_ok()` hard-fails on any HTTP 4xx/5xx so you don’t get silent garbage output.

---

## TL;DR

The solve is:

* “be a normal user” (register + upload)
* then “be a menace” (vault traversal)

And the working payload is:

```
/vault/%2e%2e/flag.txt
```

