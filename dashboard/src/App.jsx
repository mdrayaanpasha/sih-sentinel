import React, { useEffect, useMemo, useRef, useState } from "react";

const THREATS = {
  flood: "Flood / DDoS",
  beaconing: "C2 Beaconing",
  dga_dns: "DGA / DNS Tunnel",
  tls_malware: "Encrypted Malware",
  portscan: "Port Scan",
  exfil: "Data Exfil",
};
const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3 };
const MAX_ROWS = 500;

function fmtTime(ts) {
  return new Date(ts * 1000).toLocaleTimeString();
}

export default function App() {
  const [alerts, setAlerts] = useState([]);
  const [stats, setStats] = useState({ total: 0, by_threat: {}, by_severity: {} });
  const [connected, setConnected] = useState(false);
  const [threatFilter, setThreatFilter] = useState("all");
  const [sevFilter, setSevFilter] = useState("all");
  const [expanded, setExpanded] = useState(null);
  const wsRef = useRef(null);

  // initial history + periodic stats
  useEffect(() => {
    fetch("/api/alerts?limit=200").then((r) => r.json()).then(setAlerts).catch(() => {});
    const refresh = () => fetch("/api/stats").then((r) => r.json()).then(setStats).catch(() => {});
    refresh();
    const t = setInterval(refresh, 3000);
    return () => clearInterval(t);
  }, []);

  // live websocket
  useEffect(() => {
    let stop = false;
    function connect() {
      const proto = location.protocol === "https:" ? "wss" : "ws";
      const ws = new WebSocket(`${proto}://${location.host}/ws/alerts`);
      wsRef.current = ws;
      ws.onopen = () => setConnected(true);
      ws.onclose = () => {
        setConnected(false);
        if (!stop) setTimeout(connect, 1500);
      };
      ws.onmessage = (e) => {
        const a = JSON.parse(e.data);
        setAlerts((prev) => [a, ...prev].slice(0, MAX_ROWS));
      };
    }
    connect();
    return () => {
      stop = true;
      wsRef.current?.close();
    };
  }, []);

  const filtered = useMemo(() => {
    return alerts
      .filter((a) => threatFilter === "all" || a.threat_class === threatFilter)
      .filter((a) => sevFilter === "all" || a.severity === sevFilter);
  }, [alerts, threatFilter, sevFilter]);

  return (
    <div className="app">
      <header>
        <div className="brand">
          <span className="dot" /> SENTINEL
          <small>passive threat monitor · read-only diode feed</small>
        </div>
        <div className={`conn ${connected ? "on" : "off"}`}>
          {connected ? "live" : "reconnecting…"}
        </div>
      </header>

      <section className="cards">
        <div className="card total">
          <div className="num">{stats.total}</div>
          <div className="lbl">total alerts</div>
        </div>
        {Object.keys(THREATS).map((k) => (
          <div
            key={k}
            className={`card ${threatFilter === k ? "sel" : ""}`}
            onClick={() => setThreatFilter(threatFilter === k ? "all" : k)}
          >
            <div className="num">{stats.by_threat?.[k] || 0}</div>
            <div className="lbl">{THREATS[k]}</div>
          </div>
        ))}
      </section>

      <section className="controls">
        <label>
          Threat:
          <select value={threatFilter} onChange={(e) => setThreatFilter(e.target.value)}>
            <option value="all">all</option>
            {Object.entries(THREATS).map(([k, v]) => (
              <option key={k} value={k}>{v}</option>
            ))}
          </select>
        </label>
        <label>
          Severity:
          <select value={sevFilter} onChange={(e) => setSevFilter(e.target.value)}>
            <option value="all">all</option>
            {["critical", "high", "medium", "low"].map((s) => (
              <option key={s} value={s}>{s}</option>
            ))}
          </select>
        </label>
        <span className="count">{filtered.length} shown</span>
      </section>

      <section className="table">
        <div className="row head">
          <div>time</div><div>threat</div><div>severity</div><div>confidence</div>
          <div>source</div><div>destination</div><div>evidence</div>
        </div>
        {filtered.map((a, i) => (
          <div
            key={`${a.flow_id}-${a.ts}-${i}`}
            className={`row sev-${a.severity}`}
            onClick={() => setExpanded(expanded === i ? null : i)}
          >
            <div>{fmtTime(a.ts)}</div>
            <div><span className={`tag t-${a.threat_class}`}>{THREATS[a.threat_class] || a.threat_class}</span></div>
            <div><span className={`sev sev-${a.severity}`}>{a.severity}</span></div>
            <div>
              <div className="bar"><span style={{ width: `${a.confidence * 100}%` }} /></div>
              {(a.confidence * 100).toFixed(0)}%
            </div>
            <div className="mono">{a.src_ip}{a.src_port ? `:${a.src_port}` : ""}</div>
            <div className="mono">{a.dst_ip}{a.dst_port ? `:${a.dst_port}` : ""}</div>
            <div className="ev">
              {expanded === i
                ? <pre>{JSON.stringify(a.evidence, null, 2)}</pre>
                : Object.entries(a.evidence || {}).slice(0, 2).map(([k, v]) => `${k}=${v}`).join("  ")}
            </div>
          </div>
        ))}
        {filtered.length === 0 && <div className="empty">no alerts yet — replay a pcap to see live detections</div>}
      </section>
    </div>
  );
}
