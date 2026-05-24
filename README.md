# MAVERICK

> Round up the mavericks — every robot the internet forgot to fence in.

**MAVERICK** is an open-source, research-flavored discovery service for internet-connected robots — vacuums, humanoids, lawn bots, telepresence, delivery bots, industrial arms. Think Shodan or Censys, but scoped to robots, with a live world map, a Shodan-style query DSL, and (eventually) a live telemetry stream.

A *maverick* is an unbranded calf strayed from the herd. Every device we index is a robot loose on the internet that nobody has claimed or counted.

## Status

Pre-code. Design doc locked, infrastructure not yet provisioned. See [`docs/DESIGN.md`](docs/DESIGN.md) for the full plan — problem framing, audiences, premises, architecture, build order, and open questions.

Soft beta target: ~8 weeks. Public launch target: ~16 weeks.

## Ethical line — load-bearing

This project indexes **existence + fingerprint, never contents.** That means:

- **What we index:** that a device exists, an approximate location, the device model, and the firmware version where we can fingerprint it.
- **What we never log, never store, never publish:** floorplans, camera frames, audio, telemetry payloads, credentials, PII, or anything that could be used to exploit a device.
- **Locations are reverse-geocoded to city level only.** Never street-level. Never coordinates accurate enough to identify a household.
- **Two-tier data release:** aggregate statistics, fingerprint definitions, and the public index are open. Raw scan data and per-device records are researcher-only, with vetting.
- **No exploitation.** Active scans are slow, polite (~1000 pps), and limited to fingerprintable surface. Source IPs serve a research-charter page at `/about` so anyone receiving a probe can see who we are and how to opt out.

If a contribution would push MAVERICK toward becoming a doxxing tool or an exploit catalog, it doesn't get merged. The brand survives only if every artifact reinforces the research framing.

## Audiences

- **Security / OSINT researchers** — exposure statistics, fleet-wide CVE impact estimates, fingerprint definitions.
- **ROS and robotics researchers** — neutral observatory data for population studies and fleet observability research.
- **Robot OEMs** — ground truth on their own deployed populations and unauthorized exposures.

## Architecture (sketch)

```
[Hetzner CAX11 #1 — Falkenstein]  ─┐
[Hetzner CAX11 #2 — Hillsboro]    ─┼─ Masscan + UDP probes (~1000 pps, polite)
[Hetzner CAX11 #3 — Helsinki]     ─┘             │
                                                 ▼
                                       (raw observations → JSONL)
                                                 │
                                                 ▼
                                  ┌──────────────────────────┐
                                  │ shadenode (collector)    │
                                  │ ─────────────────────────│
                                  │ Go ingest service        │
                                  │ Fingerprint engine       │
                                  │ Postgres + PostGIS       │
                                  │ Next.js + Mapbox GL JS   │
                                  │ DSL query API            │
                                  └──────────────────────────┘
                                                 │
                                                 ▼
                                       Cloudflare Tunnel → public dashboard
```

**Stack:** Go (backend) · Next.js + Mapbox GL JS (frontend) · Postgres + PostGIS (storage) · Masscan (scanners) · Cloudflare Tunnel (public exposure).

Full architecture rationale lives in [`docs/DESIGN.md`](docs/DESIGN.md).

## Roadmap

- **Weeks 1-2** — Foundations. Schema, charter page, Cloudflare Tunnel.
- **Weeks 3-4** — First scanner. Masscan from one Hetzner box; miIO + Tuya MQTT sweeps; ingest pipeline.
- **Weeks 5-6** — Map + DSL. Mapbox dashboard, query parser, internal humanoid catalog.
- **Weeks 7-8** — Soft beta. Three scanners live, Humanoid Atlas pane, research charter, HN launch.
- **Weeks 9-16** — Coverage + community. More fingerprints, open the fingerprint repo to contributions, submit research note.

## License

Apache License 2.0 — see [`LICENSE`](LICENSE).

## Contributing

Not open for contributions yet — the architecture is still being laid down. Once the fingerprint repo is split out (~ week 12), community-contributed fingerprints will be the primary way to help. Until then, the most useful thing you can do is read [`docs/DESIGN.md`](docs/DESIGN.md) and open an issue if something looks wrong, missing, or ethically off.
