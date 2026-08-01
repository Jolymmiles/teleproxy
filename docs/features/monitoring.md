---
description: "Built-in HTTP stats endpoint and Prometheus metrics for Teleproxy. Track connections, traffic, per-secret usage, and DC health."
---

# Monitoring

## HTTP Stats Endpoint

```bash
curl http://localhost:8888/stats
```

Requires `--http-stats` flag. Accessible from private networks only (loopback, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`).

Use the stats port, not the client proxy port. A 404 from a public source
address is intentional: `/stats`, `/metrics`, and `/link` share the same access
control. Access them locally, through an SSH tunnel, or add your management
network with `--stats-allow-net`.

```bash
ssh -L 8888:127.0.0.1:8888 user@proxy.example.com
# Then open http://127.0.0.1:8888/link locally.
```

### Custom Network Access

To allow access from overlay/VPN networks (Tailscale, WireGuard, Netbird), use `--stats-allow-net`:

```bash
./teleproxy ... --stats-allow-net 100.64.0.0/10 --stats-allow-net fd00::/8
```

Repeatable — specify multiple times for multiple ranges. Both IPv4 and IPv6 CIDR notation supported.

## Prometheus Metrics

```bash
curl http://localhost:8888/metrics
```

Returns Prometheus exposition format on the same stats port. Includes per-secret metrics when labels are configured.

Available metrics include connection counts, per-secret connections, rejection counts, and IP ACL rejections.

### ClientHello JA4 Fingerprint Distribution

Every well-formed TLS ClientHello reaching the proxy is fingerprinted with [JA4](https://github.com/FoxIO-LLC/ja4) and accumulated into a top-32 counter — including ClientHellos that subsequently fail HMAC validation. That second part is the point: when TSPU pushes a new detection signature, the only operationally interesting traffic is the probe that *doesn't* validate. Always on, zero configuration.

```
# HELP teleproxy_ja4_seen ClientHello JA4 fingerprints observed (top 32 by count, aggregated across workers).
# TYPE teleproxy_ja4_seen counter
teleproxy_ja4_seen{hash="t13d1615h2_46e7e9700bed_45f260be83e2"} 8
```

ClientHellos whose HMAC matches a configured secret also feed a bounded top-four distribution for that secret:

```
# HELP teleproxy_secret_ja4_seen ClientHello JA4 fingerprints observed per secret (top 4 by count, aggregated across workers).
# TYPE teleproxy_secret_ja4_seen counter
teleproxy_secret_ja4_seen{secret="family",hash="t13d1615h2_46e7e9700bed_45f260be83e2"} 6
```

The `/stats` endpoint emits the same data as tab-separated `ja4_seen\t<hash>\t<count>` and `secret_<label>_ja4_seen\t<hash>\t<count>` lines. Unmatched ClientHellos appear only in the global counter. Diff the global distribution against the per-secret view or upstream session log to separate unrecognized probes from fingerprints using a distributed secret.

Optional: `--ja4-log` (or `[stats] ja4_log = true` in TOML, `JA4_LOG=true` in Docker) prints one `ja4=... sni=...` line per connection at verbose level 2. Useful for one-off investigations, noisy for steady-state logging.

### DC Latency Probes

When enabled, teleproxy periodically probes all 5 Telegram DCs with a TCP handshake and exposes the results as a Prometheus histogram:

```bash
# Enable with 30-second probe interval
./teleproxy ... --dc-probe-interval 30
```

Metrics exposed:

| Metric | Type | Description |
|--------|------|-------------|
| `teleproxy_dc_latency_seconds` | histogram | TCP handshake RTT per DC (labels: `dc="1"`..`dc="5"`) |
| `teleproxy_dc_probe_failures_total` | counter | Failed probe attempts per DC |
| `teleproxy_dc_latency_last_seconds` | gauge | Most recent probe latency per DC |

The text `/stats` endpoint includes matching fields: `dc_probe_interval`, `dcN_probe_latency_last`, `dcN_probe_latency_avg`, `dcN_probe_count`, `dcN_probe_failures`.

Disabled by default. Set `dc_probe_interval` in the TOML config or use the `DC_PROBE_INTERVAL` environment variable in Docker.

## Grafana Dashboard

Import the [bundled dashboard](https://github.com/teleproxy/teleproxy/blob/main/dashboards/teleproxy.json) into Grafana:

1. Download `dashboards/teleproxy.json` from the repository
2. In Grafana → Dashboards → Import → Upload JSON file
3. Select your Prometheus datasource

The dashboard covers connections, per-secret usage, rejection rates, DC connectivity, and resource utilization.

## Health Checks

Docker containers include built-in health monitoring via the stats endpoint. Check with:

```bash
docker ps  # STATUS column shows health
```
