# EZ-pcap — Solution Overview

## Challenge Summary

This challenge provides a packet capture file:

    handout/capture_victim.pcap

The PCAP contains HTTP traffic between an attacker and a vulnerable internal web service. The service exposes a `/diagnostic` endpoint that improperly executes user-controlled input in a shell context, leading to command injection.

The attacker performs:

1. Normal diagnostic traffic
2. A command injection using an encoded payload
3. A follow-up request retrieving sensitive data

The sensitive data returned by the server contains the flag, base64-encoded.

The goal is to identify the injection sequence and recover the flag.

---

## What You Should See in the PCAP

When analyzing the capture in Wireshark:

- Filter on `http`
- Follow the TCP stream for suspicious requests
- Locate a `GET /diagnostic?target=...` request containing an encoded command
- Identify a follow-up `GET /secret`
- Observe the HTTP response body containing a base64 blob
- Decode the blob to obtain the flag

The final flag format is:

    GRIZZ{...}

---

## Automated Solver Script

The file:

    solution/solve.py

automates flag extraction directly from the PCAP.

### How It Works

The script:

1. Reads the PCAP using Scapy.
2. Iterates over TCP packets containing raw payload data.
3. Searches for:
   - Direct occurrences of `GRIZZ{...}`
   - Base64-encoded strings within HTTP responses.
4. Attempts to decode detected base64 strings.
5. Checks decoded output for a valid `GRIZZ{...}` pattern.
6. Prints the first valid flag found.

It does not require Wireshark or tshark.

---

## Usage

```bash
python solve.py ../handout/capture.pcap                                   
GRIZZ{pcap_cmd_injection_chain_via_namespaces}
```

---

## Educational Purpose

This challenge demonstrates:

- Network traffic analysis
- HTTP request inspection
- Command injection identification
- Base64 decoding
- Practical forensic workflow

The solver script illustrates how automated extraction tools can assist incident responders in parsing captures programmatically rather than manually inspecting streams.

---

## Intended Learning Outcome

Participants should be able to:

- Recognize injection patterns in query parameters
- Identify encoded payloads within traffic
- Reconstruct attacker activity from network captures
- Decode obfuscated data to retrieve sensitive information

This mirrors real-world blue-team forensic analysis workflows.

---