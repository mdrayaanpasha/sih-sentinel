# Threat model & operating assumptions

## Deployment
The system sits behind a **hardware data diode / passive tap** that copies production traffic
one-way into the monitoring segment. It is a pure sensor:
- **No return path.** It cannot send packets to the production network — no probing, scanning,
  active response, or blocking. Even if this monitoring system were fully compromised, the diode
  physically prevents pivoting back into production.
- **No decryption.** It has no keys and performs no MITM. Encrypted traffic is assessed from
  handshake metadata (JA3/JA3S, SNI) and observable size/timing only.

These are enforced in code: only the ingest component reads packets, and nothing in the pipeline
opens an outbound network connection to a monitored host.

## The six threat classes
1. **Flood / DDoS** — volumetric traffic (often half-open SYNs) from many sources overwhelming a
   target. Observable: rate spike + high source-IP cardinality toward one destination.
2. **Botnet C2 beaconing** — infected hosts phone home on a fixed cadence. Observable: metronomic
   inter-arrival times to a small destination set.
3. **DGA / DNS tunneling** — malware resolves algorithmically-generated domains, or smuggles data
   inside DNS query names. Observable: domain randomness/entropy; long names + high query volume.
4. **Malware in encrypted sessions** — C2 over TLS. Observable without decryption: JA3/JA3S
   fingerprint, and robotic packet size/timing patterns.
5. **Port scanning** — reconnaissance probing many ports/hosts. Observable: one source touching
   many distinct targets in a short window with probe-like flows.
6. **Data exfiltration** — bulk data leaving a host. Observable: outbound:inbound byte ratio and
   volume far above that host's learned baseline.

## Limitations (honest scope)
- Trained models use **synthetic** data for this prototype; production use should retrain on real
  feeds (Tranco/DGArchive for DGA; labeled pcaps for encrypted-flow). Feature pipelines are ready.
- Thresholds are tuned for the lab corpus and should be recalibrated to a site's baseline.
- JA3 blocklist ships with sample entries; wire it to a live threat-intel feed.
- Detectors are per-flow/windowed heuristics + ML; a determined adversary can pace activity below
  thresholds. Layering (multiple weak signals) and baseline learning mitigate but don't eliminate this.
