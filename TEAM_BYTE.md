# TEAM BYTE — Project Guide

*A simple explanation of what we built. Anyone can read this.*

---

## What problem are we solving?

Important networks (like the power grid) need to be watched for hackers. But you
can't let the watching system touch the real network — if it gets hacked, the
hacker could jump into the grid.

So there's a special one-way device (a **diode**) that copies network traffic into
our system. Our system can **only watch**. It can never send anything back.

**Our job:** watch that copied traffic, spot 6 kinds of attacks, and show alerts on
a screen — all in real time, without ever touching the real network.

---

## The 6 attacks we catch

| # | Attack | In plain words | How we spot it |
|---|--------|----------------|----------------|
| 1 | **Flood (DDoS)** | Attacker floods a server with junk traffic to crash it | Sudden spike in traffic from many different sources |
| 2 | **C2 Beaconing** | Infected computer secretly "calls home" to the hacker at fixed times | Messages sent at suspiciously regular clockwork intervals |
| 3 | **DGA / DNS Tunneling** | Malware uses random gibberish website names, or hides stolen data inside DNS lookups | Website names look random; or too many odd lookups |
| 4 | **Encrypted Malware** | Malware hides inside encrypted (HTTPS) traffic | We read the "envelope" info (not the message) — fingerprints + robotic patterns |
| 5 | **Port Scanning** | Attacker knocks on many doors to find a way in | One source touching lots of ports/computers quickly |
| 6 | **Data Exfiltration** | Attacker steals data by sending it out | A computer suddenly sending out way more data than normal |

**We never decrypt anything.** We only look at patterns, sizes, timing, and metadata.

---

## How it works (the flow)

```
Copied traffic  ─►  Turn packets into "flow records"  ─►  Message queue (Kafka)
                                                                  │
                                                                  ▼
                            Detectors check each flow for the 6 attacks
                            (using short-term memory in Redis)
                                                                  │
                                                                  ▼
                        Alerts saved (Postgres) + shown LIVE on the dashboard
```

Think of it like an assembly line: traffic comes in, gets inspected, and any threat
lights up on the screen within seconds.

---

## What each part does

| Part | Folder | Its job |
|------|--------|---------|
| **Ingest** | `ingest/` | Reads traffic and turns it into simple records |
| **Detectors** | `workers/detectors/` | 6 mini-programs, one per attack, that raise alerts |
| **Memory** | `workers/state.py` | Remembers recent activity (needed to spot patterns) |
| **Alerts** | `workers/alerting.py` | Saves alerts and sends them to the dashboard |
| **Brain (ML)** | `models/` | Trained AI models for the trickier attacks (DGA, encrypted) |
| **API** | `api/` | Feeds alerts to the dashboard (live + history) |
| **Dashboard** | `dashboard/` | The screen that shows alerts to a human |
| **Lab traffic** | `labgen/` | Fake attack traffic we made to test everything |

---

## How good is it? (our test results)

- **Every attack type is caught** — 6 out of 6.
- **Zero false alarms** on normal traffic (100% precision).
- **~630 flows checked per second** on a single laptop — and we can add more workers
  to go faster.

Every alert tells you: **when**, **what attack**, **how confident** we are, **who**
(source → target), and **why** (the exact evidence).

---

## How to run it

You need Docker and the `uv` tool installed.

```bash
uv sync                    # install everything
cp .env.example .env       # basic settings
./scripts/demo.sh          # starts the whole system
```

Then open **http://127.0.0.1:5173** in a browser to watch alerts appear live.

To check our results yourself:

```bash
uv run python -m evaluation.evaluate    # shows accuracy per attack
uv run python -m bench.throughput       # shows speed (flows/sec)
```

---

## The golden rules we always follow

1. **One-way only** — we watch, we never touch the real network.
2. **No decryption** — we respect privacy; only metadata and patterns.
3. **Real-time** — alerts within seconds, not end-of-day reports.
4. **Every alert is explainable** — it always says *why* it fired.

---

## Want more detail?

- `README.md` — full setup and commands
- `docs/architecture.md` — how the pieces connect
- `docs/models.md` — how each detector and AI model works
- `docs/threat-model.md` — the attacks and our assumptions
- `docs/performance.md` — accuracy and speed numbers
