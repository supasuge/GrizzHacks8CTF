# Solution

## From a high-level

The intended solution path is as follows:

1. Extract leaf cert
2. Parse AIA extension
3. Download intermediate via HTTP
4. Parse intermediate certificate
5. Extract custom OID extension
6. Base64 decode the payload
7. Recover the flag


## Solution Guide (Deep Dive)

This document explains **what you’re looking at**, **why it behaves that way**, and **how to solve it** using both tooling and the provided `solve.py`.

---

## What this challenge is testing

This challenge simulates a realistic TLS/PKI scenario:

- A website is reachable over **HTTPS (TLS)**.
- The server presents a **leaf (server) certificate**, but it is **misconfigured** and does **not** provide the intermediate CA certificate needed to build a full chain.
- The leaf certificate includes an **AIA** (Authority Information Access) pointer that tells clients where to download the missing intermediate.
- The **flag is embedded in the intermediate CA certificate** as a **custom X.509 extension** identified by a custom **OID**.

To solve it, you must:
1. Retrieve the leaf certificate from the TLS handshake.
2. Extract the AIA “CA Issuers” URL.
3. Download the intermediate certificate (DER file).
4. Parse the intermediate certificate and extract the custom extension by OID.
5. Decode the payload to recover the flag.

---

## 1) PKI / Certificates 101 (the stuff you must understand)

### 1.1 Certificate Authorities (CAs): levels and roles

In PKI, a **Certificate Authority (CA)** is an entity that signs certificates. Signing creates a **chain of trust**.

There are typically three “levels” relevant to TLS:

#### A) Root CA (Trust Anchor)
- **Self-signed**: the Root signs its own certificate.
- Installed in OS/browser trust stores (Windows/macOS/Linux, Firefox, etc.).
- Purpose: serves as the **ultimate trusted starting point**.

Key properties:
- `BasicConstraints: CA:TRUE`
- `KeyUsage: keyCertSign, cRLSign` (it can sign certificates and CRLs)

Why it matters:
- If you trust the root, and the signatures down the chain verify, you trust the leaf.

#### B) Intermediate CA (Issuing CA)
- Not self-signed.
- Signed by the root (or another intermediate).
- Purpose: issues certificates to leaf servers/users while keeping the root offline.

Why intermediates exist:
- **Risk reduction**: keep the root key highly protected/offline.
- **Operational flexibility**: intermediates can be rotated without replacing the root in every client trust store.
- **Policy separation**: different intermediates for different purposes.

Key properties:
- `BasicConstraints: CA:TRUE`
- Often `pathLenConstraint` to restrict how many CA layers can follow.

#### C) Leaf / End-Entity Certificate (Server certificate)
- Presented by the HTTPS server during the TLS handshake.
- Signed by an intermediate CA (usually).
- Purpose: binds a public key to a domain name (identity).

Key properties:
- `BasicConstraints: CA:FALSE`
- `Subject Alternative Name (SAN)` includes domain(s).
- `KeyUsage` includes things needed for TLS (commonly `digitalSignature` and/or `keyEncipherment`).

**In this challenge**
- Root CA exists (not sent to clients; not needed if you trust it).
- Intermediate CA exists (contains the flag).
- Leaf certificate exists (presented by the server).
- The server is misconfigured: it sends only the leaf, not the intermediate.

---

## 2) Common abbreviations and what they mean

### TLS
Transport Layer Security. The protocol used by HTTPS.

### X.509
The certificate format standard used in TLS.

### CA
Certificate Authority.

### CN
Common Name. Historically used for domain validation, but modern TLS uses SAN.

### SAN
Subject Alternative Name. The correct place for DNS names in modern certs.

### AIA
Authority Information Access. An X.509 extension that can include:
- **CA Issuers** URL: where to download the issuer cert (intermediate)
- OCSP responder URL: where to check revocation status

### OID
Object Identifier. A globally unique identifier for an extension type.
- Example: `2.5.29.19` corresponds to `BasicConstraints`.
- Custom extensions use enterprise ranges, often under `1.3.6.1.4.1`.

### DER / PEM
Two common encodings for the same X.509 certificate data.

---

## 3) Encoding & parsing: DER vs PEM (and why it matters)

### 3.1 DER
- **Binary** encoding.
- Strict subset of ASN.1 BER rules.
- Common for machine distribution (e.g., `*.der`, `*.cer`).
- The intermediate in this challenge is served as a `.der` file.

When you see a download endpoint like:
`/.well-known/pki/intermediate.der`
…you should assume it’s **DER**.

### 3.2 PEM
- **Text** encoding (Base64 of DER wrapped with header/footer).
- Looks like:

```
-----BEGIN CERTIFICATE-----
MIID...
-----END CERTIFICATE-----
```

PEM is just DER wrapped for readability/transport.

### 3.3 ASN.1 (Abstract Syntax Notation One)
- A schema language used to define certificate structures.
- X.509 certs are ASN.1 structures; DER is a binary encoding of ASN.1.

“Parsing a cert” means:
- decode DER/PEM into a structured object (fields, extensions, etc.).

---

## 4) Why clients fail when the server doesn’t send the intermediate

A “correct” TLS server typically sends:
- Leaf certificate
- Intermediate certificate(s)

The root is often not sent because:
- It’s assumed the client already has it in its trust store.

If the server sends only the leaf, a client must still find the intermediate somehow:
- OS/browser cache
- AIA fetch (“CA Issuers” URL)
- manual installation

If none exists, verification errors occur, commonly:
- `unable to get local issuer certificate`
- `unable to verify the first certificate`

This is exactly what this challenge intends.

---

## 5) Where the flag is hidden (conceptually)

The flag is stored in the intermediate CA certificate inside a **custom X.509 extension**.

- Custom extension identifier: `1.3.6.1.4.1.1337.42.1`
- The value is bytes that look like:
- `BH-CTF:<base64(flag)>`

Why custom extensions are “realistic”:
- Enterprises/vendors add extensions for internal metadata.
- Certificate tooling will display them, but they are not part of the standard “common fields” people check.

---

## 6) Manual solve (tooling path)

Assume target host is `TARGET`.

### Step 1 — Pull the server’s leaf certificate

```bash
openssl s_client -connect TARGET:443 -showcerts </dev/null
```

This will show the leaf certificate. It may also show verification errors because the chain is incomplete.

To extract the cert cleanly, you can copy the PEM block into a file like `leaf.pem`
(Everything between `BEGIN CERTIFICATE` and `END CERTIFICATE`).

### Step 2 — Inspect leaf certificate extensions and find AIA

```bash
openssl x509 -in leaf.pem -text -noout | less
```

Search for **Authority Information Access** and look for `CA Issuers - URI: ...`

You should see something like:

* `http://TARGET/.well-known/pki/intermediate.der`

### Step 3 — Download the intermediate certificate

```bash
curl -sS http://TARGET/.well-known/pki/intermediate.der -o intermediate.der
```

### Step 4 — Parse intermediate DER and locate the custom OID

```bash
openssl x509 -inform DER -in intermediate.der -text -noout | less
```

Look for extension OID:

* `1.3.6.1.4.1.1337.42.1`

You should see the value containing:

* `BH-CTF:<base64...>`

### Step 5 — Decode base64 payload to recover flag

If the extension value contains a base64 blob:

```bash
echo 'ZmxhZ3t...}' | base64 -d
```

(You may need to copy only the base64 portion after `BH-CTF:`.)

---

## 7) Automated solve (`solve.py`) explained in depth

The script automates the manual flow with correct parsing logic.

### 7.1 Grab leaf certificate from TLS handshake

* Establish TCP connection to `host:443`
* Wrap with TLS context
* Disable validation (`CERT_NONE`) because chain is intentionally broken
* Use `getpeercert(binary_form=True)` to get certificate bytes in DER

Why DER from TLS is important:

* TLS gives you the leaf cert as binary DER.
* You avoid copy/paste and formatting issues.

### 7.2 Parse leaf cert and extract AIA “CA Issuers”

* X.509 extension: `Authority Information Access`
* Find the entry where `access_method == CA_ISSUERS`
* Extract URL string

This is the critical breadcrumb.

### 7.3 Download intermediate DER from AIA URL

* Use HTTP GET to retrieve `intermediate.der`
* Parse it as DER into an X.509 object

### 7.4 Locate the custom extension by OID

* OID: `1.3.6.1.4.1.1337.42.1`
* The library exposes it as an unrecognized extension with raw bytes.

### 7.5 Decode the extension payload format

* Expect a prefix `BH-CTF:`
* Everything after the colon is base64
* Decode to get the flag string

---

## 8) “Why this is realistic” (CTF relevance)

In real environments:

* Intermediate cert delivery is frequently mishandled.
* Chain issues cause outages, failed API calls, broken mobile clients, etc.
* Debugging often involves:

  * openssl s_client
  * certificate chain inspection
  * AIA fetching
  * CA trust store reasoning

This challenge teaches those operational skills in a controlled lab setting.

---

## 9) Troubleshooting

### “It just hangs”

If you run the container without `-d`, nginx runs in the foreground (normal). Use:

```bash
docker run -d ...
docker logs -f pki-ctf
```

### “I can’t bind 80/443”

Ports are already in use. Run on alternate ports:

```bash
docker run -d --name pki-ctf -p 8080:80 -p 8443:443 -e HOSTNAME=localhost pki-ctf
```

Then use:

* `http://localhost:8080/.well-known/pki/intermediate.der`
* TLS connect to `localhost:8443`

### “AIA URL points to hostname that isn’t reachable”

If `HOSTNAME` inside container doesn’t match how players reach it, AIA becomes wrong.
Fix by running with:

```bash
-e HOSTNAME=challenge.example.com
```

where that name resolves publicly to the server.

---

## 10) Key takeaways

* **Root CA**: trust anchor (usually preinstalled).
* **Intermediate CA**: issuer (operational, often downloadable).
* **Leaf cert**: what the server presents.
* **AIA**: where the issuer cert can be fetched.
* **DER/PEM**: binary vs text encoding of the same X.509 structure.
* **OID**: identifier for extensions; custom ones are common in enterprise PKI.

Flag recovery requires using PKI metadata the way real clients and PKI engineers do.

---
