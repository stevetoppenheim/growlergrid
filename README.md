# GrowlerGrid

A free, self-maintaining reactive-defense recipe for OPNsense: it detects an attack, denies the source at the edge, logs it with evidence, and shares the indicator to a global blocklist. Named after the EA-18G Growler, which loiters, catches an emitter the moment it lights up, and denies it. Here the "weapon" is lawful denial and cost-imposition, never hacking back.

Built entirely from native OPNsense features plus one dependency-free Python daemon. No paid product, no custom GUI plugin to break on upgrades, and effectively no maintenance.

## What it does

Four stages, in a loop:

1. **Detect.** Suricata (native IDS/IPS) watches real WAN traffic; an isolated decoy host runs a tarpit on the ports bots love.
2. **Deny.** CrowdSec bans hostile IPs at the firewall and taps the community blocklist; the GrowlerGrid collector turns every decoy hit into a ban too.
3. **Attribute.** Packet capture, structured logs, flow records, and GeoIP give you time-stamped evidence, shipped off-box.
4. **Share.** CrowdSec reports to and consumes a global community blocklist.

The collector (`gg-collectord.py` + `growlergrid.py`) is the only custom piece: a stdlib-only daemon that reads logs, maintains a progressive ban table, and writes a plain blocklist file that OPNsense ingests as a native URL-table alias.

## Why it is safe and self-maintaining

- A whitelisted / RFC1918 / loopback IP can never be banned (fail-closed), even on malformed input.
- The decision log is a byte-capped ring that trims itself: no logrotate, no flush.
- The ban table decays on its own, is bounded by a hard horizon, and persists across reboots.
- The blocklist is written atomically, so OPNsense never reads a half-written list.
- The collector opens no outbound sockets; it only reads local logs and writes two local files.

## Quick start

```
# run the test suite and the stress simulation (no dependencies)
python3 -m unittest -v
python3 simulate.py
```

Then follow the full build in the DIY guide: it walks every OPNsense click with the expected result of each step. See `DESIGN.md` for the architecture, threat model, and the hardware acceptance checklist, and `TESTING.md` for how to validate on real hardware.

## Repository layout

- `growlergrid.py` - the engine (ban table, whitelist, ring log, blocklist emitter, parsers). Importable and unit-tested.
- `gg-collectord.py` - the daemon: tails log sources, runs the engine, writes the blocklist. Persists state across restarts.
- `test_growlergrid.py` - the automated test suite (`python3 -m unittest -v`).
- `simulate.py` - a 200,000-event stress simulation of the safety invariants.
- `config.example.json` - copy to `config.json` and edit.
- `deploy/gg-collectord` - FreeBSD / OPNsense rc.d service script.
- `deploy/gg-collectord.service` - systemd unit (for a separate Linux decoy host).
- `DESIGN.md` - full design, security posture, and acceptance checklist.
- `TESTING.md` - what is tested here vs. what you must test on your box.
- `docs/` - the article and the community write-up.

## A note on "origin" and the law

A source IP proves the proximate emitter, not the human behind it. Attackers routinely route through compromised hosts, VPNs, Tor, or botnets. This project deliberately does not "hack back": reaching out to another computer without authorization is barred for private parties under laws like the U.S. Computer Fraud and Abuse Act. Everything here acts only on traffic that comes to you, or on your own equipment.

## Status and testing

The engine ships with an 18-case unit-test suite and a 200,000-event simulation, both passing. The integration with Suricata, CrowdSec, netmap, and pf can only be validated on real OPNsense/FreeBSD hardware; `TESTING.md` has the acceptance checklist to run on your box.

## Contributing

This is a community recipe, not a product. Useful contributions: run the hardware acceptance checklist and report what broke, write parsers for more log sources, tighten the decoy isolation, and share Suricata suppress-list tuning. Open an issue or a pull request.

## License

MIT. See `LICENSE`.
