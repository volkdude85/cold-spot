# Drivers

A driver is data, not code. The daemon ships built-ins for Mullvad, IVPN, Proton,
Windscribe, NordVPN, ExpressVPN, Surfshark, Tailscale, the official WireGuard app and a
`generic` fallback. Drop a `*.json` file here (or in the directory you pass with `-vpns`) to
add a provider or override a built-in.

```json
{
  "name": "myvpn",
  "title": "My VPN",
  "packages": ["com.example.myvpn"],
  "dns": "10.64.0.1",
  "expect_egress": [],
  "notes": "What this provider actually does, for the next person."
}
```

| field | meaning |
| --- | --- |
| `name` | lowercase, stable; what the API and panel call it |
| `title` | what a human sees in the dropdown |
| `packages` | how the phone recognises the provider — the only field auto-detection needs |
| `dns` | adopted when the driver is activated; leave empty to keep the current resolver |
| `expect_egress` | optional CIDRs the exit must be inside; empty means "learn it and fail closed if it moves" |
| `notes` | free text |

Find your provider's package name with:

```bash
adb shell pm list packages | grep -i vpn
# then confirm it really implements VpnService:
adb shell dumpsys package <pkg> | grep -n 'android.net.VpnService'
```

Some non-VPN apps ship a `VpnService` (Brave browser does, for its firewall). That is why
detection intersects installed implementers against this table instead of counting them.
