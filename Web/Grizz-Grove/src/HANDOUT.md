# GRIZZ GROVE handout

## Story

Grizz Grove rolled out strict CSP and declared victory over XSS.
Then someone added “themes” that load scripts dynamically because… vibes.

> You can submit a path for the ranger-bot to “review”.
>> Need I say more?

## Goal

Steal the flag from the ranger-only Bear Den.

## Endpoints (player-facing)

- queue a path for the bot to visit
- redeem your one-time report

## Hints

- CSP blocks inline scripts, but the page still loads scripts... Surely XSS won't work here. nah, no way.
- Moods are just a vibe eh
