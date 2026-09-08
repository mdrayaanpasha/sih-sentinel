"""Generate a labeled lab pcap covering benign traffic + all 6 threat classes.

Each scenario uses distinct hosts and its own time window so flows don't cross-
contaminate. Ground truth is written to data/labels.csv as (threat_class, match_field,
match_ip): an alert is a true positive if its threat_class matches and the named IP
(src or dst) matches. This stands in for "which tool was running when" labeling used
with real generators (hping3/Slowloris/dnscat2/DGArchive/custom bot-C2).

    uv run python -m labgen.generate            # -> data/lab.pcap + data/labels.csv
"""

from __future__ import annotations

import csv
import os
import random

from labgen.pcap_lib import SYN, PcapWriter, dns_query, ipv4, tcp, udp

T0 = 1_700_000_000.0
RNG = random.Random(7)

BENIGN_DOMAINS = [
    "google.com", "cloudflare.com", "microsoft.com", "github.com", "wikipedia.org",
    "amazon.com", "apple.com", "netflix.com", "office365.com", "ubuntu.com",
]
DGA_TLDS = ["com", "net", "biz", "info"]


def _dga_domain() -> str:
    n = RNG.randint(12, 22)
    label = "".join(RNG.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(n))
    return f"{label}.{RNG.choice(DGA_TLDS)}"


def build(pw: PcapWriter, labels: list[dict]) -> None:
    # ---- benign: web sessions + good DNS (window @ +0..30s) ----
    t = T0
    server = "10.0.0.10"
    for i in range(30):
        src = f"10.1.0.{10 + (i % 15)}"
        pw.tcp_flow(t + i * 0.5, src, server, 40000 + i, 443,
                    n_out=RNG.randint(3, 8), out_size=RNG.randint(200, 1200),
                    n_in=RNG.randint(4, 12), in_size=RNG.randint(400, 1400))
        pw.add_ip(t + i * 0.5, ipv4(src, server, 17, udp(50000 + i, 53,
                  dns_query(RNG.choice(BENIGN_DOMAINS)))))

    # ---- portscan: 10.2.0.5 -> 10.0.0.20, many ports (window @ +40s) ----
    t = T0 + 40
    for i in range(60):
        pw.add_ip(t + i * 0.01, ipv4("10.2.0.5", "10.0.0.20", 6, tcp(41000 + i, 20 + i, 7, 0, SYN)))
    labels.append({"threat_class": "portscan", "match_field": "src", "match_ip": "10.2.0.5",
                   "description": "vertical port scan, 60 ports"})

    # ---- flood: many spoofed srcs -> 10.0.0.30:80 bare SYN (window @ +60s) ----
    t = T0 + 60
    for i in range(60):
        src = f"198.51.100.{1 + i}"
        pw.add_ip(t + i * 0.02, ipv4(src, "10.0.0.30", 6, tcp(30000 + i, 80, 1, 0, SYN)))
    labels.append({"threat_class": "flood", "match_field": "dst", "match_ip": "10.0.0.30",
                   "description": "SYN flood from 60 sources"})

    # ---- beaconing: bot 10.2.0.6 -> C2 203.0.113.5:443, regular cadence (window @ +80s) ----
    t = T0 + 80
    for i in range(12):
        pw.tcp_flow(t + i * 2.0, "10.2.0.6", "203.0.113.5", 45000 + i, 443,
                    n_out=3, out_size=350, n_in=2, in_size=300)
    labels.append({"threat_class": "beaconing", "match_field": "src", "match_ip": "10.2.0.6",
                   "description": "C2 beacon every 2s, 12 beacons"})

    # ---- dga_dns: infected 10.2.0.7 -> DNS, DGA lookups + tunneling (window @ +120s) ----
    t = T0 + 120
    for i in range(60):
        pw.add_ip(t + i * 0.05, ipv4("10.2.0.7", "10.0.0.10", 17,
                  udp(51000 + i, 53, dns_query(_dga_domain()))))
    for i in range(50):  # tunneling: long random subdomains under one parent
        sub = "".join(RNG.choice("abcdef0123456789") for _ in range(40))
        pw.add_ip(t + 3 + i * 0.05, ipv4("10.2.0.7", "10.0.0.10", 17,
                  udp(52000 + i, 53, dns_query(f"{sub}.tunnel.evil.com", qtype=16))))
    labels.append({"threat_class": "dga_dns", "match_field": "src", "match_ip": "10.2.0.7",
                   "description": "DGA lookups + DNS tunneling"})

    # ---- tls_malware: 10.2.0.8 -> 203.0.113.9:443, small uniform payloads (window @ +160s) ----
    t = T0 + 160
    for i in range(6):
        pw.tcp_flow(t + i * 1.0, "10.2.0.8", "203.0.113.9", 46000 + i, 443,
                    n_out=8, out_size=90, n_in=6, in_size=90, gap=0.5)
    labels.append({"threat_class": "tls_malware", "match_field": "src", "match_ip": "10.2.0.8",
                   "description": "robotic TLS: small uniform payloads"})

    # ---- exfil: 10.2.0.9 -> 203.0.113.20:443, large outbound transfer (window @ +200s) ----
    t = T0 + 200
    pw.tcp_flow(t, "10.2.0.9", "203.0.113.20", 47000, 443,
                n_out=4200, out_size=1400, n_in=6, in_size=80, gap=0.0005)
    labels.append({"threat_class": "exfil", "match_field": "src", "match_ip": "10.2.0.9",
                   "description": "5.9 MB outbound bulk transfer"})


def main() -> None:
    os.makedirs("data", exist_ok=True)
    pw = PcapWriter()
    labels: list[dict] = []
    build(pw, labels)
    n = pw.write("data/lab.pcap")
    with open("data/labels.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["threat_class", "match_field", "match_ip", "description"])
        w.writeheader()
        w.writerows(labels)
    size_mb = os.path.getsize("data/lab.pcap") / 1e6
    print(f"wrote data/lab.pcap ({n} packets, {size_mb:.1f} MB)")
    print(f"wrote data/labels.csv ({len(labels)} labeled scenarios)")


if __name__ == "__main__":
    main()
