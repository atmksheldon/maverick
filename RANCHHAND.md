# MAVERICK

Global open-source discovery service for internet-connected robots — vacuums, humanoids, lawn bots, telepresence, delivery bots, industrial arms. Shodan/Censys-style index scoped to robots, with a live world map, Shodan-style query DSL, and (eventually) live telemetry.

**Tagline (from the design doc):** "Round up the mavericks — every robot the internet forgot to fence in."

The name's metaphor: a maverick is an unbranded calf strayed from the herd; every device this system finds is a robot loose on the internet nobody has claimed or counted.

## Source of truth

Full design context — problem, audiences, premises, approaches considered, recommended approach, architecture sketch, success criteria, build order, observations — lives in **`docs/DESIGN.md`** (copied from `~/.gstack/projects/johnwick/johnwick-main-design-20260524-111301.md`). **Read that first** before doing anything substantive on this project.

## Status

- **Phase:** pre-code. Repo initialized, design doc locked, no source written yet.
- **Created:** 2026-05-24 via `/office-hours` skill.
- **Branch:** `main`.

## Locked decisions (do not relitigate without explicit user OK)

1. **Mode:** open source / research. Apache 2.0 license intended.
2. **Wedge:** vacuums + humanoids, globally, as two distinct dashboard panes (Population view + Humanoid Atlas). Other robot classes are "coming soon" until launch.
3. **Audiences:** security/OSINT researchers, ROS community, robot OEMs. Not "general public / journalists" as primary.
4. **Approach C — cost-aware hybrid:**
   - Narrow active scanning with **Masscan** (~1000 pps, slow/polite) from **3x Hetzner Cloud CAX11 ARM** VPS in Falkenstein + Hillsboro + Helsinki for ASN/geo diversity (~$13/mo total).
   - Free-tier passive enrichment only: Censys academic, Shodan's free `internetdb.shodan.io`, GitHub code search, public MQTT broker lists. **No paid Shodan/Censys tiers.**
   - **shadenode** is the collector + index + dashboard host. **Never** scan from shadenode (keeps home IP off blocklists).
5. **Ethical line — load-bearing:** existence + fingerprint, never contents. No floorplans, video, PII, credentials, or exploitation. Locations reverse-geocoded to **city level only**, never street.
6. **Two-tier data release:** aggregate stats + fingerprint definitions + public index are open; raw scan data + per-device records are researcher-only with vetting.
7. **Timeline:** soft beta week 8, public launch week 16 (~120 days).
8. **Stack:** Go backend, Next.js + Mapbox GL JS frontend, Postgres + PostGIS storage, Cloudflare Tunnel for public exposure.

## Architecture sketch

```
[Hetzner CAX11 #1 — Falkenstein] ──┐
[Hetzner CAX11 #2 — Hillsboro]   ──┼── Masscan + UDP probes (rate-limited, /about charter served)
[Hetzner CAX11 #3 — Helsinki]    ──┘        │
                                            ▼
                                   (raw observations → JSONL)
                                            │
                                            ▼
                                ┌────────────────────────┐
                                │ shadenode              │
                                │ ───────────────────────│
                                │ ingest (Go service)    │
                                │ fingerprint engine     │
                                │ Postgres + PostGIS     │
                                │ Next.js dashboard      │
                                │ DSL query API          │
                                └────────────────────────┘
                                            │
                                            ▼
                                  Cloudflare Tunnel → public.maverick.tld
```

## Current assignment (do this before writing code)

1. **Buy the domain.** Preference order: `maverick.io` → `maverick.dev` → `findmaverick.com` → `maverick-index.org`. Namecheap.
2. **Create the public GitHub repo** at `github.com/{user}/maverick`. Apache 2.0. README opens with the cowboy metaphor + states the ethical line in plain English + links to the (eventual) research charter.
3. **Push this initial commit** with `RANCHHAND.md` + `docs/DESIGN.md` so the design context is in the repo history.

## Open questions to resolve (from DESIGN.md)

- Final domain choice (after availability check).
- Whether to pursue informal university research-group affiliation for credibility + Censys academic tier eligibility.
- Validate at week 1 that ≥10 publicly reachable humanoid endpoints exist (otherwise Humanoid Atlas pane is too sparse for launch).
- GDPR posture for EU vacuum entries (probably handled by city-level reverse-geocoding + clear opt-out, but document it before month 3).

## How to "activate" me in a new session

- `cd ~/maverick` and open in your AI coding agent — this file (`RANCHHAND.md`) is loaded automatically.
- Say "read the design doc" if you want me to ingest the full `docs/DESIGN.md` before answering.
- Useful skills for this project: `/plan-eng-review` (lock the Postgres + Go service architecture before coding), `/plan-design-review` (UX pass on Population view + Humanoid Atlas before building), `/autoplan` (run all reviews in sequence with auto-decisions).

## Code-style preferences (from user's portfolio)

- **Backend:** Go. Matches Coinrunner, Tapestry Agent, Nighthawk-6 patterns.
- **Frontend:** Next.js + Mapbox GL JS. Mapbox key already provisioned.
- **Storage:** Postgres + PostGIS. Familiar from RanchGuard / ApexCitadel.
- **Hosting pattern:** shadenode (Fedora 43, Tailscale `100.80.4.15`) behind Cloudflare Tunnel. SSH alias `shadenode`. Self-hosted git available via `ssh shadenode 'git-new-repo NAME'`.
