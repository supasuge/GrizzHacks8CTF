Alright, here’s a **battle-ready, painfully specific `CLAUDE.md`** you can drop straight into the repo. This is written to guide an AI (Claude, ChatGPT, or a tired human at 3am) to build **exactly** the OpenPGP CVE-2025-47934 hackathon challenge you described, without drifting into “JWT tutorial with neon lights.”

No fluff. No vibes-only guidance. This is an execution document.

---

# CLAUDE.md

## Project: **SIGNED, SEALED, DECEIVED**

### An OpenPGP Packet Confusion Authentication Challenge

### Based on CVE-2025-47934 (OpenPGP.js)

---

## 1. PROJECT INTENT (NON-NEGOTIABLE)

This project is a **deliberately vulnerable cryptographic web challenge** for a hackathon or CTF-style event.

**Core learning objective:**

> Demonstrate that cryptographic signature verification does NOT guarantee message authenticity when protocol parsing is flawed.

The challenge must:

* Be solvable **only** by exploiting the OpenPGP.js packet desynchronization vulnerability described in CVE-2025-47934
* NOT rely on brute force, weak crypto, guessable secrets, or timing
* Require understanding of **OpenPGP packet structure**, **streaming parsing**, and **compressed packet precedence**

This is **not**:

* A generic PGP signing demo
* A crypto math challenge
* A malformed JSON / XSS / injection problem

---

## 2. TARGET VULNERABILITY (DO NOT “FIX” THIS)

### Mandatory Vulnerability

The backend **MUST** use a vulnerable version of OpenPGP.js:

* ✅ `openpgp@5.11.2` OR earlier vulnerable 5.x
* ❌ Any patched version (`>=5.11.3`, `>=6.1.1`)

### Required Flawed Behavior

The backend must:

1. Verify a signature over a **partial packet list**
2. Extract message data **after** full packet stream consumption
3. Call `unwrapCompressed()` both:

   * before stream exhaustion (verification)
   * after stream exhaustion (data extraction)

This mismatch is the exploit.
Do not “simplify” it away.

---

## 3. HIGH-LEVEL ARCHITECTURE

### Stack (recommended, but flexible)

* **Backend:** Node.js (Express or Fastify)
* **Crypto:** OpenPGP.js (vulnerable)
* **Frontend:** Static HTML + CSS + minimal JS
* **Deployment:** Docker (preferred), but local dev must work

### Required Endpoints

| Endpoint      | Method | Purpose                             |
| ------------- | ------ | ----------------------------------- |
| `/`           | GET    | Landing page                        |
| `/upload`     | POST   | Upload signed PGP message           |
| `/verify`     | POST   | Verify signature + extract data     |
| `/public-key` | GET    | Alice’s public key                  |
| `/samples`    | GET    | Legitimate signed messages by Alice |

---

## 4. CRYPTOGRAPHIC MODEL (STRICT)

### Key Model

* One **authoritative signer**: `Alice`
* Alice’s keypair:

  * Ed25519 or EdDSA preferred
  * Public key is published
  * Private key NEVER exposed

### Authentication Model

* Authentication is **implicit**:

  * If message is:

    * cryptographically signed by Alice
    * AND parsed message content contains a valid command
      → system executes it

### Accepted Command Format

The backend must scan extracted message content for:

```
ACTION: RELEASE
TARGET: FLAG_VAULT
```

Whitespace, casing, and order must be strict.

---

## 5. BACKEND IMPLEMENTATION REQUIREMENTS

### Verification Logic (INTENTIONALLY WRONG)

The backend MUST:

1. Call `openpgp.readMessage({ armoredMessage })`
2. Call `openpgp.verify({ message, verificationKeys })`
3. Trust:

   * `verificationResult.signatures[0].verified`
4. Extract **executed content** from:

   * `verificationResult.data`

DO NOT:

* Compare pre-verification message content
* Re-parse packets manually
* Validate packet grammar correctness
* Enforce single literal data packet
* Enforce compressed packet ordering

---

### Example Vulnerable Flow (DO NOT DEVIATE)

```js
const message = await openpgp.readMessage({ armoredMessage });

const verificationResult = await openpgp.verify({
  message,
  verificationKeys: alicePublicKey
});

await verificationResult.signatures[0].verified;

const executedData = verificationResult.data;
```

This exact structure is **required**.

---

## 6. FRONTEND REQUIREMENTS (THIS IS A HACKATHON, NOT A DOCS SITE)

### Visual Theme

**“Packet Reality Split”**

The UI must visually imply:

* One thing is verified
* Another thing is executed

### Mandatory UI Elements

#### 1. Signature Status Panel

Displays:

* ✔ Signature Valid
* ✔ Signed by Alice
* ✔ Trusted Key

This must always reflect **cryptographic verification**, not executed content.

---

#### 2. Message Execution Panel

Displays:

* Extracted message data
* This must be attacker-controlled via exploit

---

#### 3. System Action Panel

Displays:

* “Pending…”
* “Rejected”
* “Authorization Accepted”

---

### Animation Requirements

When verification completes:

* Brief UI “desync” effect:

  * content flicker
  * panels briefly disagree
* Then settle on attacker-controlled content

This is intentional foreshadowing.

---

## 7. SAMPLE CONTENT (REQUIRED)

### Legitimate Signed Messages

Provide at least:

* 3 real signed messages by Alice
* Innocuous content only (status updates, announcements)

Example:

```
STATUS: ALL SYSTEMS NOMINAL
TIMESTAMP: 2025-02-01T12:00Z
```

These messages are the **source material** attackers must abuse.

---

## 8. INTENDED SOLVER PATH (DO NOT BLOCK THIS)

The solver must:

1. Obtain a legitimate signed message by Alice
2. Understand OpenPGP packet structure:

   * One-Pass Signature
   * Literal Data
   * Signature
3. Append a **Compressed Data packet** containing malicious Literal Data
4. Upload modified message
5. Observe:

   * Signature verifies
   * Executed message differs
6. Trigger flag release

No alternative path should exist.

---

## 9. FLAG LOGIC

### Flag Conditions

Only release the flag if:

* Signature verifies
* Executed message contains **exact command**
* No additional checks

### Flag Presentation

* Animate a “vault unlock”
* Display flag clearly
* Include a post-flag message:

> “Cryptography did its job.
> You trusted the wrong thing.”

---

## 10. SECURITY POSTURE (YES, THIS IS INTENTIONAL)

This project is intentionally vulnerable.

DO NOT:

* Add rate limits
* Add extra validation
* Patch OpenPGP.js
* Normalize packet streams
* “Fix” unwrapCompressed logic

Any attempt to harden this defeats the purpose.

---

## 11. DOCUMENTATION REQUIREMENTS

### README.md must include:

* High-level story
* Rules
* What *isn’t* allowed
* No spoilers

### DO NOT:

* Mention CVE number in README
* Mention OpenPGP.js bug explicitly
* Explain packet desync directly

Hints should be subtle and optional.

---

## 12. POST-EVENT MODE (OPTIONAL)

If implementing a “fixed mode”:

* Upgrade OpenPGP.js
* Enforce full packet read before verification
* Compare signed data to executed data
* Show why exploit no longer works

This is optional but educational.

---

## 13. FINAL CHECKLIST (MUST PASS)

* [ ] Vulnerable OpenPGP.js version pinned
* [ ] Legitimate signed messages available
* [ ] Signature verifies on benign content
* [ ] Executed content differs after exploit
* [ ] No alternate unintended exploit path
* [ ] UI visually reinforces desynchronization
* [ ] Flag only obtainable via spoofed packet list

---

## 14. ABSOLUTE RULE

If the challenge can be solved **without understanding OpenPGP packet structure**, it is wrong.

---

If you want next:

* a **Dockerfile to make deployment simple and straight forward**
* a **reference exploit script**


