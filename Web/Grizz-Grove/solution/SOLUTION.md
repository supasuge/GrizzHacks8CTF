```md
# SOLUTION.md — GRIZZ GROVE: “CSP solved XSS” (it didn’t)

> **TL;DR**: CSP isn’t a magic spell. It’s a policy.  
> If you ship a **script-loading gadget** and a **same-origin JSONP endpoint**, you effectively hand attackers a pre-approved “run my code” button—*with compliance-grade paperwork*.

---

## 0) What the challenge is *actually* testing

This challenge is not “classic reflected XSS” where you inject `<script>alert(1)</script>` into a template.

Instead it’s testing a more modern reality:

- You can have:
  - strict CSP (`script-src 'self'`)
  - HTML auto-escaping
  - no inline scripts/events
- …and still lose, if:
  1) the app dynamically loads scripts from attacker-controlled input (**CSP gadget**),
  2) there’s an endpoint that returns attacker-controllable JavaScript (**JSONP**),
  3) an admin bot visits your link with privileged cookies (**realistic CTF infra**).

So the “bypass” isn’t “defeat CSP”, it’s:  
**use CSP exactly as intended against the site**.

---

## 1) The moving parts

### A) CSP policy (the “security theater”)
The app sets something close to:

- `script-src 'self'`
- no inline scripts
- no external CDNs

Meaning:
- You cannot execute inline JS.
- You can execute *external JS served from the same origin*.

This is the key. CSP is not “no JavaScript ever.” It’s “JavaScript must be loaded from places I allow.”

### B) The “mood loader” gadget (`static/js/app.js`)
The client has code like:

- reads `?mood=...`
- sanitizes it (but not in a cryptographically meaningful way)
- **creates** `<script src="...">` dynamically
- appends it into `<head>`

In other words: it’s a *script loader*. A very helpful one. Thanks.

Two important behaviors:
1) If `mood` starts with `/`, it loads that exact path.
2) If not, it loads `/themes/<mood>.js`.

So if you can pass:

```

?mood=/api/pollen?wind=...

````

…the page will execute `/api/pollen?...` as a script.

### C) JSONP endpoint (`/api/pollen`)
JSONP is legacy-but-still-seen-in-the-wild behavior:

- server returns JavaScript
- it “calls” a callback provided by the client (`wind` param)

The app returns something like:

```js
( callback_expression )( { ...payload... } );
````

So if **you control** `wind=...`, you control a JS expression that gets executed.

### D) Admin/bot simulation

This is how most HTB/real CTFs work:

* The flag is only visible to an “admin” (ranger) in `/bear-den`
* Admin has a cookie like `ranger=1`
* You can submit a link/path
* A headless bot visits it with privileged cookie

Your job isn’t “be admin.”
Your job is “make the admin’s browser do something stupid.”

Welcome to web security.

---

## 2) Why this works under strict CSP

Because CSP allows:

* scripts from `'self'`

And **both** the gadget and JSONP are `'self'`.

So CSP isn’t being bypassed. CSP is being **obeyed**.

The vulnerability is:

* a trusted, attacker-controlled **script source** on the same origin.

This is why people call these “CSP gadgets”:

* the policy is correct
* your code creates a policy-approved code-execution path anyway

---

## 3) The actual exploit strategy

We want the admin bot to:

1. load our crafted URL
2. which causes the mood loader to inject a `<script src="/api/pollen?...">`
3. which executes JSONP code
4. which fetches `/bear-den` (cookie makes it succeed)
5. extracts `GRIZZ{...}`
6. exfiltrates it to `/report?ticket=...`

The key is the callback in JSONP: it needs to run JavaScript.

So our callback does:

* read ticket from `location.search`
* fetch `/bear-den`
* regex match `GRIZZ{...}`
* send to `/report?ticket=...&d=...`

### The callback (human readable)

```js
function(p){
  var q = new URLSearchParams(location.search);
  var ticket = q.get('ticket') || '';

  fetch('/bear-den')
    .then(r => r.text())
    .then(t => {
      var m = t.match(/GRIZZ\{[^}]+\}/);
      if (m) {
        fetch('/report?ticket=' + encodeURIComponent(ticket) +
              '&d=' + encodeURIComponent(m[0]));
      }
    });
}
```

### The payload path we submit

We need something like:

```
/?mood=/api/pollen?wind=<CALLBACK>
```

But there is one more twist…

---

## 4) The “why is my payload breaking?” twist (double-encoding)

The mood loader’s sanitization keeps only:

* `[\w\-\/\.\?\=&%]`

It does **not** allow characters like:

* `(` `)` `{` `}` `'` `:` `;` `,`

Those are kind of important in JavaScript...

Also: `URLSearchParams.get()` returns a **decoded** string.
So `%28` becomes `(` before the sanitizer runs — and then the sanitizer strips it.

So the trick is:

* keep the JavaScript syntax **encoded** when `app.js` sees it
* let it survive the sanitizer as `%xx` sequences
* then the browser/script request decodes and the server uses it normally

That requires **double-URL-encoding** the callback.

Example:

* we want literal `%28` to remain visible after the initial decode
* so we encode `%` as `%25`
* `%28` becomes `%2528` in the final URL

This is why the solver uses `double_urlencode()`.

It’s not “magic.”
It’s just understanding the decode pipeline.

---

## 5) The “bot flow” + one-time reports

### A) Ticket system

Each submission creates a `ticket`.

The bot:

* appends `ticket=<ticket>` to the path it visits
* so your JS can grab it and exfil to the correct record

### B) One-time retrieval

To stop “bro just refresh /reports and steal flags”:

* `/reports?ticket=...` shows report once
* immediately clears the stored report (`report = NULL`, sets `consumed_at`)
* subsequent views show “already redeemed”

So the *correct player flow* is:

1. Submit payload
2. Get ticket
3. Poll `/reports?ticket=...` until the report appears
4. Copy flag immediately
5. Anyone else who gets your ticket later is sad

---

## 6) Walkthrough: how you solve it manually (without the script)

### Step 1 — Queue a visit

Go to `/submit` and submit the path:

```
/?mood=/api/pollen?wind=<YOUR_DOUBLE_ENCODED_CALLBACK>
```

You get a ticket like:

```
abcDEF123...
```

### Step 2 — Wait for bot

Bot visits your path (with `ranger=1` cookie) and appends `?ticket=...`.

### Step 3 — Redeem the report

Open:

```
/reports?ticket=abcDEF123...
```

If it worked, you see:

```
GRIZZ{...}
```

And the report clears immediately.

---

## 7) Solver logic (what `solution/solve.py` does)

1. Build callback JS
2. Double-encode it so `app.js` doesn’t shred it
3. POST to `/submit` with the payload path
4. Extract ticket from HTML
5. Poll `/reports?ticket=...` until `GRIZZ{...}` appears
6. Print flag and exit

This is deliberately deterministic:

* no headless browser required on the attacker side
* the bot is the only JS executor (which mirrors real CTF infra)

---

## 8) Defensive takeaways (aka: how not to build this in real life)

If you want to prevent this class:

### A) Don’t dynamically load scripts from user-controlled data

Yes, even if it’s “same-origin only.”

### B) Remove JSONP endpoints

Use CORS and proper JSON responses.

### C) If you *must* support dynamic behavior:

* Use strict allowlists
* hardcode script paths
* don’t let user input influence `<script src=...>`

### D) CSP is not “XSS solved”

CSP is a *mitigation*, not a correctness proof.
If your app logic creates a code-execution gadget, CSP won’t save you.

---

## 9) Common failure modes (aka: “why doesn’t it work??”)

* **Bot isn’t running** → `/reports` never gets populated
* **Callback isn’t callable** → JSONP returns syntax error
* **Over-escaped regex** → doesn’t match `GRIZZ{...}` so no exfil
* **Not double-encoding** → sanitizer strips JS syntax and payload breaks
* **Reports already consumed** → one-time retrieval clears it

---

## 10) Summary

You didn’t defeat CSP.

You exploited:

* a CSP-approved script execution path (`script-src 'self'`)
* created by a “harmless” theme loader
* amplified by JSONP callback injection
* executed by an admin bot
* recorded via a one-time ticket report

In other words:
**You used the site’s own security posture as an exploitation scaffold.**

Which is… incredibly realistic.

🐻

