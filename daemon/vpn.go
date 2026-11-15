package main

// VPN drivers.
//
// The gate never talks to a provider's API - it rides whatever VpnService is up,
// because its sockets are ordinary app sockets. What differs per provider is
// only what you expect to *see* on the wire: the ranges it exits from, the DNS it
// wants used, and how a client of that provider recognises it. That is a driver:
// data, not code.
//
// A driver is a JSON file in the drivers directory:
//
//	{
//	  "name": "mullvad",
//	  "title": "Mullvad",
//	  "packages": ["net.mullvad.mullvadvpn"],
//	  "dns": "10.64.0.1",
//	  "expect_egress": [],
//	  "notes": "WireGuard; the app's tunnel carries anything the phone sends."
//	}
//
// `packages` is how the phone recognises it, `dns` is adopted when the driver is
// activated, and `expect_egress` is optional: with no ranges the guard learns the
// baseline instead of asserting one, which is what makes an unknown provider work
// without shipping a table of every exit network on earth.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type vpnDriver struct {
	Name         string   `json:"name"`
	Title        string   `json:"title"`
	Packages     []string `json:"packages"`
	DNS          string   `json:"dns,omitempty"`
	ExpectEgress []string `json:"expect_egress,omitempty"`
	Notes        string   `json:"notes,omitempty"`
	Builtin      bool     `json:"builtin,omitempty"`
}

// builtinDrivers ship with the daemon so a fresh install recognises the common
// providers without the user writing JSON first. They carry no exit ranges on
// purpose - those change, and a stale range is a false "leak".
func builtinDrivers() []vpnDriver {
	return []vpnDriver{
		{Name: "mullvad", Title: "Mullvad", Packages: []string{"net.mullvad.mullvadvpn"},
			Notes: "WireGuard/OpenVPN; uses its own DNS inside the tunnel.", Builtin: true},
		{Name: "ivpn", Title: "IVPN", Packages: []string{"net.ivpn.client"},
			Notes: "WireGuard/OpenVPN.", Builtin: true},
		{Name: "proton", Title: "Proton VPN", Packages: []string{"ch.protonvpn.android"},
			Notes: "WireGuard/OpenVPN; supports split tunneling per app.", Builtin: true},
		{Name: "windscribe", Title: "Windscribe", Packages: []string{"com.windscribe.vpn"}, Builtin: true},
		{Name: "nord", Title: "NordVPN", Packages: []string{"com.nordvpn.android"}, Builtin: true},
		{Name: "express", Title: "ExpressVPN", Packages: []string{"com.expressvpn.vpn"}, Builtin: true},
		{Name: "surfshark", Title: "Surfshark", Packages: []string{"com.surfshark.vpnclient.android"}, Builtin: true},
		{Name: "tailscale", Title: "Tailscale", Packages: []string{"com.tailscale.ipn"},
			Notes: "Mesh, not a privacy tunnel: exit ranges are your own tailnet.", Builtin: true},
		{Name: "wireguard", Title: "WireGuard (official app)", Packages: []string{"com.wireguard.android"},
			Notes: "Any WireGuard config, including a self-hosted endpoint.", Builtin: true},
		{Name: "generic", Title: "Any other VpnService",
			Notes: "Fallback: rides whatever tun is up, guard learns the baseline.", Builtin: true},
	}
}

// loadDrivers merges the builtins with any JSON files on disk. A file with the
// same name as a builtin overrides it, which is how a user pins exit ranges for a
// provider without forking the daemon.
func loadDrivers(dir string) []vpnDriver {
	byName := map[string]vpnDriver{}
	for _, d := range builtinDrivers() {
		byName[d.Name] = d
	}
	if dir != "" {
		entries, err := os.ReadDir(dir)
		if err == nil {
			for _, e := range entries {
				if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
					continue
				}
				b, err := os.ReadFile(filepath.Join(dir, e.Name()))
				if err != nil {
					continue
				}
				var d vpnDriver
				if json.Unmarshal(b, &d) != nil || d.Name == "" {
					continue
				}
				byName[d.Name] = d
			}
		}
	}
	out := make([]vpnDriver, 0, len(byName))
	for _, d := range byName {
		out = append(out, d)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// driverForPackage answers "which provider is this?", used by the app when it
// reports the VPN that ConnectivityManager says is up.
func driverForPackage(drivers []vpnDriver, pkg string) *vpnDriver {
	for i := range drivers {
		for _, p := range drivers[i].Packages {
			if p == pkg {
				return &drivers[i]
			}
		}
	}
	return nil
}
