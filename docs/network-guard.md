# Network Guard

Network Guard extends hushwarren beyond the local device: it listens on one or
more LAN IP addresses so that every device on your network can use the same
DNS sinkhole — phones, TVs, game consoles, etc. — without installing anything on
them.

## Architecture

```
Phone / TV / smart device
        │ DNS port 53 (UDP or TCP)
        ▼
  [Network Guard listener]   ← bound to 192.168.x.y:53  (your LAN IP)
        │
        ▼
  SinkholeHandler (same pipeline as Local Guard)
        │
        ├─ forward   → upstream resolver
        └─ block     → NXDOMAIN / loopback (per block_action)
```

The Network Guard listeners share the **same decision engine** as the Local Guard
(loopback) listeners.  There is no second set of rules or blocklists; all
traffic flows through a single `SinkholeHandler`.

The control API (`hushd` HTTP server) **always** binds only to `127.0.0.1`.
Enabling Network Guard does not change this — see §8 of `docs/architecture.md`.

## Configuration

Add a `[network_guard]` section to `~/.config/hushwarren/config.toml`:

```toml
[network_guard]
enabled      = true
bind         = ["192.168.1.10"]   # your Mac's LAN IP
log_clients  = true               # record per-device client IPs
```

| Key           | Type         | Default | Description |
|---------------|--------------|---------|-------------|
| `enabled`     | bool         | `false` | Start guard listeners on each `bind` address |
| `bind`        | `[string]`   | `[]`    | LAN IP addresses to listen on (no wildcards, no loopback) |
| `log_clients` | bool         | `false` | Tag each query in the SQLite log with the source IP |

### Validation rules

hushwarren validates the config on startup (and `hush config check`).  These
combinations are rejected with an error:

- `bind` contains `0.0.0.0` or `::` (unspecified / wildcard)
- `bind` contains any loopback address (`127.*`, `::1`)
- `bind` contains a string that is not a valid IP address
- `enabled = true` with an empty `bind` list

Validation runs even when `enabled = false` so that a misconfigured address is
caught before it matters.

### Finding your LAN IP

```
# macOS
ipconfig getifaddr en0

# or
ifconfig | grep "inet " | grep -v 127
```

### Router DNS setting

Point your router's DNS server (DHCP option 6) to the same IP you put in `bind`.
All devices on the LAN will then use hushwarren automatically.

## Per-client statistics

When `log_clients = true`, each DNS query that arrives on a guard listener is
tagged with the client's IP address in the SQLite rollup database
(`~/.local/share/hushwarren/querylog.sqlite`, column `client`).

The schema was extended in version 2 (migrated automatically from v1 on first
start with Network Guard data):

```sql
ALTER TABLE queries ADD COLUMN client TEXT;   -- nullable; NULL for loopback
```

Retrieve totals via the API:

```
GET /v0/clients?hours=24
Authorization: Bearer <token>
```

Response:
```json
{
  "log_clients_enabled": true,
  "explanation": null,
  "clients": [
    { "client": "192.168.1.42", "total": 847, "blocked": 312 },
    { "client": "192.168.1.55", "total": 204, "blocked": 19  }
  ]
}
```

When `log_clients = false` the response is:
```json
{
  "log_clients_enabled": false,
  "explanation": "network_guard.log_clients is off; set it to true to enable per-client stats",
  "clients": []
}
```

### Privacy note

Per-client logging records **every device's browsing activity** visible to
whoever can read the SQLite file.  The `anonymous` query-log mode redacts domain
names but still records client IPs (that is the point of per-device counters).
Only enable `log_clients` if you are comfortable with this.

## Dashboard

When `log_clients = true`, a **Clients** tab appears in the dashboard
(`http://127.0.0.1:<port>/dashboard/`).  The tab is hidden when the feature is
off so the interface is not cluttered with disabled functionality.

## Bind failures

If hushd cannot bind on a configured LAN address (e.g., the interface is not
yet up), it logs a warning and continues running without the guard listener.
This is intentional: bind failures on LAN addresses are non-fatal.  The Local
Guard (loopback) always starts regardless.

## Security invariant

The control API HTTP server **never** binds to a non-loopback address.  This is
a hard invariant enforced in code (`crates/daemon/src/api/mod.rs`).  The
`network_guard.bind` list is only used for the DNS listeners; it has no effect
on API binding.
