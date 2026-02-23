# EZ-pcap — Command Injection PCAP Challenge

<p align="center"><img src="image.png" alt="Certainly logo" width="180" /></p>

## Summary

This challenge is a packet-capture (PCAP) forensics task. You are given a network capture that contains normal HTTP traffic plus a real exploitation sequence. Your job is to inspect the PCAP, identify the injected payload, and recover the flag.

## Handout

- `handout/capture.pcap`

## Scenario

An internal “Diagnostic Portal” exposes an HTTP endpoint that accepts a `target` parameter for network checks (e.g., `ping`). An attacker discovers the service and performs a command injection using an encoded payload. Spot the payload, and retrieve the flag!

## Player Goal
Recover the flag by analyzing the PCAP:
1. Locate suspicious HTTP requests.
2. Identify the injected command embedded in a query parameter.
3. Decode the attacker’s encoded payload.
4. Extract the base64 response containing the final flag.

## Flag Format
Flags are always in the format:

`GRIZZ{...}`

## How this PCAP was created

The PCAP was generated in a fully isolated lab environment that simulates two hosts:
- **Victim**: runs a small vulnerable web app (diagnostic endpoint) on TCP/5000
- **Attacker**: sends benign requests and then an encoded command-injection payload

Traffic is captured with `tcpdump` during:
- normal browsing
- the injection request
- a follow-up data retrieval request/response that contains the flag (base64-encoded)

The result is a PCAP containing a complete, realistic attack chain suitable for Wireshark “Follow TCP Stream” analysis.

## Hints (optional)
- Filter for HTTP traffic.
- “Follow TCP Stream” is your friend.
- Look for base64 blobs in either the injected payload or the HTTP response body.