# GrizzHacks8 CTF Platform — Architecture Design Spec
**Date:** 2026-03-26
**Event:** GrizzHacks8 CTF, March 28–29 2025
**Categories:** Crypto, Web, Misc, Pwn, OSINT

---

## 1. System Overview

Two-service architecture on a single host, sharing PostgreSQL and Redis.

```
┌─────────────────────────────────────────────────────────────┐
│                      Cloudflare (DNS + TLS)                  │
│   grizzhacks8ctf.us        *.chal.grizzhacks8ctf.us          │
└──────────────┬───────────────────────────┬──────────────────┘
               │                           │
        ┌──────▼──────┐            ┌───────▼───────┐
        │    Nginx     │            │     Nginx      │
        │  (main app)  │            │ (chal proxy)   │
        └──────┬──────┘            └───────┬───────┘
               │                           │  subdomain→upstream
        ┌──────▼──────┐            ┌───────▼───────┐
        │  CTF Core   │  REST API  │   Dispatch    │
        │  Flask App  │◄──────────►│   Service     │
        │  :5000      │            │   :5001       │
        └──────┬──────┘            └───────┬───────┘
               │                           │ Docker TCP
        ┌──────▼──────────────────┐ ┌─────▼──────┐
        │   PostgreSQL + Redis    │ │  Docker    │
        │   (shared, one host)    │ │  Engine    │
        └─────────────────────────┘ └────────────┘
```

**Services:**
- **CTF Core** — auth, challenges, scoreboard, admin, anti-cheat (`ctfapp/`, port 5000)
- **Dispatch Service** — Docker TCP, instance lifecycle, subdomain routing (`dispatch_service/`, port 5001, internal only)

**Shared infrastructure:**
- PostgreSQL — all persistent models
- Redis — sessions, rate limits, instance map, team_flags hashmap

---

## 2. Data Models

### Users & Teams
```
users
  id, public_id (uuid), username, email
  password_hash, is_admin, state
  email_verified_at, totp_secret (2FA scaffold)
  created_at

teams
  id, team_uid (uuid), name
  join_token, captain_user_id
  max_size=4, state, created_at

team_members
  team_id, user_id
  role (captain|member)
  joined_at, active
```

### Scoring Identity
```
principals
  id, kind (team|solo)
  public_id (uuid)
  team_id (nullable), user_id (nullable)
  team_secret (32 bytes) — HMAC flag derivation key
  score_total, last_solve_at
```

Solo players have `team_id=null`; `team_secret` lives directly on Principal.
Team players share a Principal owned by their team.

### Challenges & Files
```
challenges
  id, slug, title, category_slug
  description_md, points
  flag_type (derived|dynamic)
    derived = HMAC-derived per-principal (all MVP challenges)
    dynamic = flag comes from instance.flag_override (future)
  is_dynamic (bool)
  container_image (nullable)
  container_port (nullable)
  status (hidden|visible)
  NOTE: no `flag` column — flags are never stored on challenges.
        All flags derived from ADMIN_KEY + principal.team_secret + challenge.id

challenge_files
  challenge_id, filename
  storage_path, size, checksum

team_flags  (durable mirror of Redis team_flags hash)
  principal_id, challenge_id
  flag_value               ← derived flag, stored for durability
  UNIQUE (principal_id, challenge_id)
```

### Dispatch Scaffold
```
instances
  id, challenge_id, principal_id
  subdomain, container_id
  flag_override (nullable — used when flag_mode=dynamic)
  spawned_at, expires_at
  status (running|stopped)
```

### Submissions & Solves
```
submissions
  id, principal_id, challenge_id
  flag_submitted_hash (sha256 of raw input — never store plaintext)
  result (correct|wrong)
  ip, user_agent, created_at

solves
  principal_id, challenge_id   ← UNIQUE constraint
  points_awarded, solved_at

score_events  (append-only ledger)
  principal_id, challenge_id
  delta, reason, created_at
```

### Audit Trail
```
event_log
  id, type, severity (INFO|WARNING|CRITICAL)
  actor_user_id, principal_id, challenge_id
  payload_json
  prev_sig, sig   ← chained HMAC (tamper-evident)
  created_at
```

---

## 3. Core Flask App Structure

```
ctfapp/
├── __init__.py              # app factory
├── config.py                # Config / DevelopmentConfig / ProductionConfig
├── extensions.py            # db, limiter, cache, csrf, redis client
├── security.py              # security headers after_request
├── errors.py                # HTTP + generic exception handlers
├── secure_log.py            # chained HMAC event_log writer
│
├── models/
│   ├── user.py              # User, TeamMember
│   ├── team.py              # Team
│   ├── principal.py         # Principal
│   ├── challenge.py         # Challenge, ChallengeFile
│   ├── instance.py          # Instance (dispatch scaffold)
│   ├── submission.py        # Submission, Solve, ScoreEvent
│   └── event_log.py         # EventLog
│
├── blueprints/
│   ├── auth/                # register (team/solo choice), login, logout, email verify
│   ├── challenges/          # list by category, detail, flag submit
│   ├── scoreboard/          # leaderboard (team + solo, filterable)
│   ├── team/                # create team, join via token, member list
│   ├── dispatch/            # spawn/destroy/reset instance (proxies to dispatch svc)
│   └── admin/               # challenge CRUD, user/team mgmt, event log, analytics
│
├── services/
│   ├── auth_service.py      # registration, login, session logic
│   ├── flag_engine.py       # derive_flag, verify_flag, pre-generate for team
│   ├── mail_service.py      # Mailtrap — verification + 2FA emails
│   ├── event_service.py     # write EventLog with chained HMAC
│   └── anticheat.py         # submission checks, flag-share detection
│
└── templates/
    ├── base.html            # dark CTF theme, nav
    ├── auth/                # login.html, register.html
    ├── challenges/          # list.html, detail.html
    ├── scoreboard/          # index.html
    ├── team/                # create.html, manage.html
    ├── dispatch/            # instance.html (spawn UI)
    └── admin/               # dashboard, challenges, users, event_log, analytics
```

---

## 4. Dispatch Service

```
dispatch_service/
├── app.py                   # Flask app, :5001
├── config.py                # DOCKER_TCP_HOST, TTL, image whitelist
├── docker_client.py         # docker-py over TCP
├── instance_registry.py     # Redis-backed instance map
├── nginx_writer.py          # writes upstream conf fragments, reloads nginx
├── reaper.py                # APScheduler — destroys expired instances every 60s
└── routes.py                # REST API (internal + admin endpoints)
```

### Internal REST API (called by CTF Core)
```
POST   /instances/spawn
       body: { challenge_id, principal_id, image, port, ttl_seconds }
       → run container on ctf-isolated network
       → generate subdomain: team-<principal_uid>-<chal_slug>
       → write nginx upstream conf, reload nginx
       → store in Redis + instances table
       → return: { subdomain, expires_at }

DELETE /instances/<principal_id>/<challenge_id>
       → stop + rm container, remove nginx conf, clear Redis

GET    /instances/<principal_id>
       → all active instances for a principal

POST   /instances/<principal_id>/<challenge_id>/reset
       → destroy + respawn (enforces cooldown via Redis TTL key)
```

### Admin-Only API (`@require_admin_token`)
```
GET    /admin/instances                       # all active instances
DELETE /admin/instances/<id>                  # force-kill any container
POST   /admin/instances/reap                  # trigger reaper manually
GET    /admin/containers/stats                # CPU/mem per container
POST   /admin/challenges/<id>/reset-all       # destroy all instances for a challenge
```

### Container Isolation
Each container launched with:
- Network: `ctf-isolated` (no inter-container routing)
- Random host port mapped to container port
- `CHALLENGE_FLAG` env var injected
- Memory: 256MB, CPU: 0.5 (configurable)
- No `--privileged`, no `--network host`

### Nginx Dynamic Upstream
Dispatch writes per-subdomain conf fragments to `/etc/nginx/conf.d/upstreams/` and calls `nginx -s reload`.
Reaper removes fragments for expired instances.

---

## 5. Anti-Cheat — HMAC Flag Scheme

### Flag Derivation
Every team (and solo principal) has a `team_secret` (32 random bytes generated at creation).
Flags are derived per `(principal, challenge)` pair:

```python
import hmac, hashlib

def derive_flag(admin_key: bytes, team_secret: bytes, challenge_id: int) -> str:
    msg = team_secret + challenge_id.to_bytes(4, "big")
    digest = hmac.new(admin_key, msg, hashlib.sha3_256).hexdigest()
    return f"GRIZZ{{{digest[:32]}}}"

def verify_flag(submitted: str, admin_key: bytes,
                team_secret: bytes, challenge_id: int) -> bool:
    expected = derive_flag(admin_key, team_secret, challenge_id)
    return hmac.compare_digest(submitted.strip(), expected)
```

`ADMIN_KEY` is loaded from env only — never stored in DB. Flags can always be re-derived.

### Pre-Generation
On team/solo principal creation:
1. Generate `team_secret = os.urandom(32)`
2. For every currently visible challenge: derive and store flag
3. Storage: `HSET team_flags:<principal_id> <challenge_id> <flag>` in Redis
4. Mirrored to a `team_flags` DB table for durability (survives Redis restart)

When admin adds a new challenge:
- Derive and store flags for all existing principals

### Submission Verification
```
1. Lookup principal_id from session
2. HGET team_flags:<principal_id> <challenge_id>  → expected flag
3. hmac.compare_digest(submitted, expected)
   CORRECT → record solve, update score
   WRONG   →
     a. Scan all other principals' flags for this challenge
        Match found → AnticheatEvent(CRITICAL, FLAG_SHARE_DETECTED)
     b. Increment wrong-attempt counter (Redis)
        3 wrong in window → 30s lockout (429 + retry_after header)
```

### Dynamic Flag Scaffold
When `flag_type=dynamic` (future): `flag_override` on the `Instance` row replaces the derived flag. Verification checks `instance.flag_override` instead of `HGET team_flags`. Flag sharing detection still works — submitted value is checked against all other instances' `flag_override` values.

### AnticheatEvent Severities
| Type | Severity | Trigger |
|---|---|---|
| `FLAG_SHARE_DETECTED` | CRITICAL | Submitted flag matches another principal's derived flag |
| `BRUTE_FORCE_LOCKOUT` | WARNING | 3+ wrong submissions in window |
| `SUSPICIOUS_SOLVE` | INFO | Correct flag on attempt #1, high-point challenge (scaffold) |

All events written to `event_log` with chained HMAC signatures.

---

## 6. Infrastructure

### TLS Strategy
Wildcard cert (`*.chal.grizzhacks8ctf.us`) requires **DNS-01 challenge** — HTTP challenge cannot issue wildcards.
Certbot + `certbot-dns-cloudflare` plugin handles this automatically using a Cloudflare API token.

Two certs issued:
1. `grizzhacks8ctf.us` + `www.grizzhacks8ctf.us` — main app
2. `*.chal.grizzhacks8ctf.us` — challenge subdomains

Both auto-renewed via a certbot container with a cron entrypoint.

### Docker Compose
```yaml
# docker-compose.yml
services:

  certbot:
    image: certbot/dns-cloudflare
    volumes:
      - certs:/etc/letsencrypt
      - ./infra/cloudflare.ini:/cloudflare.ini:ro
    entrypoint: >
      /bin/sh -c "
        certbot certonly --dns-cloudflare
          --dns-cloudflare-credentials /cloudflare.ini
          --email admin@grizzhacks8ctf.us --agree-tos --non-interactive
          -d grizzhacks8ctf.us -d www.grizzhacks8ctf.us &&
        certbot certonly --dns-cloudflare
          --dns-cloudflare-credentials /cloudflare.ini
          --email admin@grizzhacks8ctf.us --agree-tos --non-interactive
          -d '*.chal.grizzhacks8ctf.us' &&
        trap exit TERM; while :; do
          certbot renew --quiet; sleep 12h & wait;
        done"

  nginx-main:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./infra/nginx/main.conf:/etc/nginx/nginx.conf:ro
      - certs:/etc/letsencrypt:ro
    depends_on: [ctf-core, certbot]
    networks: [ctf-internal]

  nginx-chal:
    image: nginx:alpine
    ports:
      - "8443:443"   # Cloudflare proxies *.chal.* here
    volumes:
      - ./infra/nginx/chal.conf:/etc/nginx/nginx.conf:ro
      - ./infra/nginx/upstreams:/etc/nginx/conf.d/upstreams:ro
      - certs:/etc/letsencrypt:ro
    networks: [ctf-internal, ctf-isolated]

  ctf-core:
    build: .
    env_file: .env
    expose: ["5000"]
    depends_on: [postgres, redis]
    networks: [ctf-internal]

  dispatch:
    build: ./dispatch_service
    env_file: .env
    expose: ["5001"]
    volumes:
      - ./infra/nginx/upstreams:/upstreams  # writes conf fragments here
      - /var/run/docker.sock:/var/run/docker.sock  # or TCP via DOCKER_TCP_HOST
    depends_on: [postgres, redis]
    networks: [ctf-internal, ctf-isolated]

  postgres:
    image: postgres:16-alpine
    env_file: .env
    volumes:
      - pgdata:/var/lib/postgresql/data
    networks: [ctf-internal]

  redis:
    image: redis:7-alpine
    command: redis-server --appendonly yes
    volumes:
      - redisdata:/data
    networks: [ctf-internal]

networks:
  ctf-internal:
    driver: bridge
  ctf-isolated:
    driver: bridge
    internal: true   # no outbound internet from challenge containers

volumes:
  certs:
  pgdata:
  redisdata:
```

### Nginx Main Config (`infra/nginx/main.conf`)
```nginx
# HTTP → HTTPS redirect
server {
    listen 80;
    server_name grizzhacks8ctf.us www.grizzhacks8ctf.us;
    location /.well-known/acme-challenge/ { root /var/www/certbot; }
    location / { return 301 https://$host$request_uri; }
}

server {
    listen 443 ssl http2;
    server_name grizzhacks8ctf.us www.grizzhacks8ctf.us;

    ssl_certificate     /etc/letsencrypt/live/grizzhacks8ctf.us/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/grizzhacks8ctf.us/privkey.pem;
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_ciphers         HIGH:!aNULL:!MD5;

    location / {
        proxy_pass         http://ctf-core:5000;
        proxy_set_header   Host              $host;
        proxy_set_header   X-Real-IP         $remote_addr;
        proxy_set_header   X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header   X-Forwarded-Proto $scheme;
    }
}
```

### Nginx Chal Config (`infra/nginx/chal.conf`)
```nginx
# Wildcard SSL for all challenge subdomains
# Per-subdomain upstreams are included dynamically from /conf.d/upstreams/
server {
    listen 443 ssl http2;
    server_name ~^(?<subdomain>.+)\.chal\.grizzhacks8ctf\.us$;

    ssl_certificate     /etc/letsencrypt/live/chal.grizzhacks8ctf.us/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/chal.grizzhacks8ctf.us/privkey.pem;
    ssl_protocols       TLSv1.2 TLSv1.3;

    # Dispatch writes upstream blocks here; nginx-chal reloaded after each write
    include /etc/nginx/conf.d/upstreams/$subdomain.conf;

    location / {
        proxy_pass http://$subdomain;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

### Cloudflare Credentials (`infra/cloudflare.ini`)
```ini
# Cloudflare API token with DNS:Edit permission for grizzhacks8ctf.us
dns_cloudflare_api_token = <CF_API_TOKEN>
```
This file must be `chmod 600` — never committed to git (add to `.gitignore`).

### Environment Variables
```
# Core
SECRET_KEY                     # Flask secret key
ADMIN_KEY                      # HMAC flag derivation key (never in DB)
DATABASE_URL                   # postgresql://ctf:pass@postgres:5432/ctfdb
REDIS_URL                      # redis://redis:6379/0
DISPATCH_INTERNAL_URL          # http://dispatch:5001
DISPATCH_ADMIN_TOKEN           # shared secret for admin dispatch API
MAILTRAP_API_KEY               # email delivery
APP_ENV                        # development | production

# Dispatch
DOCKER_TCP_HOST                # tcp://docker-host:2376 (or leave unset to use socket)
INSTANCE_TTL_SECONDS=7200      # 2-hour default
CONTAINER_MEMORY_LIMIT=256m
CONTAINER_CPU_LIMIT=0.5
NGINX_UPSTREAM_DIR=/upstreams  # path to shared volume
CHALLENGE_IMAGE_WHITELIST      # comma-separated allowed image names

# Postgres
POSTGRES_DB=ctfdb
POSTGRES_USER=ctf
POSTGRES_PASSWORD=             # set a strong password
```

### Nginx Chal Dynamic Upstream Fragment
```nginx
# Written by dispatch to: /etc/nginx/conf.d/upstreams/<subdomain>.conf
upstream team-abc-webchall {
    server 127.0.0.1:32841;
}
server {
    listen 443 ssl;
    server_name team-abc-webchall.chal.grizzhacks8ctf.us;
    ssl_certificate     /certs/fullchain.pem;
    ssl_certificate_key /certs/privkey.pem;
    location / {
        proxy_pass http://team-abc-webchall;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

---

## 7. Implementation Order (MVP)

1. Fix `extensions.py`, `__init__.py` — wire db, redis, limiter, csrf, cache
2. Models — all tables, migrations
3. `flag_engine.py` — derive_flag, verify_flag, pre-generation
4. Auth blueprint — register (team/solo), login, logout
5. Team blueprint — create, join, manage
6. Challenges blueprint — list, detail, submit (with anti-cheat + rate limiting)
7. Scoreboard blueprint
8. Admin blueprint — challenge CRUD + user/team mgmt + event log
9. Dispatch service — Docker client, instance registry, nginx writer, reaper
10. Dispatch blueprint in Core — spawn/destroy/reset UI
11. Templates — dark theme, all pages
12. Docker Compose + Nginx configs
13. `.env.example`, `Dockerfile`s, `start.sh`
