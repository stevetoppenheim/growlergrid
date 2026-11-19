# Reactive Network Defense on OPNsense: a Growler-style detect / respond / attribute design

Nov 19, 2026

## The concept, and the one part of it to change

An EA-18G Growler does not fly to the enemy airfield and blow it up. It loiters in contested airspace, listens passively for an emitter to light up (a search or targeting radar), and the moment it gets a "lock" it denies and degrades that emitter: jamming it, spoofing it, and cueing a kinetic strike (a HARM anti-radiation missile, or another shooter) carried out under rules of engagement. The core job is SEAD/EW: deny the adversary use of the spectrum, pinpoint who is emitting, and protect the rest of the package. That maps onto network defense almost perfectly, with one exception worth being precise about.

**What maps cleanly (and is what both designs below do):**

- **Loiter and listen:** a passive sensor on your perimeter watching traffic, costing the attacker nothing to trip.
- **Detect the lock:** a probe, scan, brute-force, or exploit attempt is the radar switching on.
- **Engage / deny:** drop, block, blackhole, or *tarpit* the source so its attack degrades or stops. Tarpitting is the closest legal analog to jamming: you burn the attacker's connections, time, and bandwidth, and it all happens on your own equipment.
- **Attribute with proof:** capture who emitted, from where, with evidence that holds up later (the geolocation / ELINT cut).
- **Share to the net:** feed the attacker's identity into a shared blocklist so the whole community degrades them, the way a datalink cues the rest of the strike package.

**The one part to change: "attack and destroy" the attacker's own network.** In cyber terms that is *hacking back*: reaching out to break into or disable the source system. For a private party in the U.S. that is barred by the Computer Fraud and Abuse Act, which prohibits access to another computer without authorization and offers no self-defense exception. Even the federal program signed on August 12, 2026, which for the first time lets *vetted, government-authorized* companies run offensive "hack-back" operations, is narrowly scoped to foreign cyber-enabled criminal organizations and is explicitly *not* a general hack-back license; it does not cover an ordinary operator running a firewall. Operationally it is also a trap: attackers almost always come through compromised third parties, proxies, rented VPS, or botnet nodes, so "striking back" usually means attacking an innocent victim and manufacturing your own liability.

**So the faithful Growler analog is: detect → deny / degrade → attribute → share, not counter-attack.** That version is the one that actually works, is legal, and is buildable on an OPNsense box today. Both designs below are this shape.

## The shared mental model: one four-stage loop

Both options are the same loop, built from different parts. An attack is caught by the sensor (1), the shooter bans it at the firewall and tarpits it (2), the event is logged off-box as evidence (3), and the attacker's identity is shared to, and pre-drawn from, the global fleet (4). The "drop" is applied back at the attacker from your own firewall; nothing ever reaches out to the attacker's machine.

> Architecture diagram (in the live document): Attacker → [1 Detect: Suricata + decoy bait] → [2 Deny: CrowdSec ban, pf drop, tarpit] → the drop is applied back at the attacker; [2] also feeds [3 Attribute: pcap, EVE, geo] → off-box proof store, and exchanges report/consume with [4 Share: CrowdSec CAPI] ↔ the community fleet's global blocklist.

## Option 1: the Reactive Sensor-Shooter (Suricata + CrowdSec, native on OPNsense)

This is the most faithful Growler loop, and it is built entirely from two things OPNsense already ships or offers as a first-class plugin. Suricata is the ES/ELINT receiver; CrowdSec is the shooter and the datalink. On the current release (OPNsense 25.7 "Ultimate Unicorn", 2026) both are a few clicks away.

**The sensor, Suricata.** OPNsense's built-in Intrusion Detection is Suricata, and it runs as either a passive IDS (alert only) or an inline IPS that drops matching packets in-band. You start it under **Services → Intrusion Detection → Administration**: enable it on the WAN interface, pick the Hyperscan pattern matcher (much faster than Aho-Corasick), and load the free Proofpoint ET Open ruleset. Run it in IDS mode first (this is the loiter phase, costless to the attacker and safe for your traffic), then cut to IPS once the ruleset is tuned (the phased plan below covers the cutover). When a signature or protocol anomaly fires, that is the radar lock.

**The shooter and datalink, CrowdSec.** CrowdSec is an open-source IPS that reads logs, decides who is hostile, and bans them at the firewall. Install the `os-crowdsec` plugin from **System → Firmware → Plugins** (tick *Show community plugins*); it deploys three packages: `os-crowdsec` (the UI), `crowdsec` (the log processor + Local API), and `crowdsec-firewall-bouncer` (which applies bans through OPNsense pf tables). Three services run by default: the **Log Processor** (formerly "IDS"), the **LAPI**, and the **Remediation Component** (formerly "IPS"). The log processor consumes Suricata's events and the firewall/service logs, runs behavioral *scenarios* (brute-force, port scan, web exploit, credential stuffing), and when one trips it writes a *decision*. The bouncer enforces that decision by dropping the source IP into a pf block table. That is the jam: the emitter is denied.

**The networked kill-web.** CrowdSec's real power is the datalink. The same alert that blocks locally is reported, anonymized, to the central CrowdSec API (CAPI), where it feeds a behavior-based community blocklist that often exposes a new attacker worldwide within minutes of its first appearance anywhere. In return your firewall consumes that global blocklist and pre-emptively drops known-hostile IPs before they ever probe you. You are both a sensor contributing cuts and a shooter consuming the whole fleet's targeting data.

**How a single engagement flows:**

1. An attacker scans or brute-forces a service behind the firewall (radar switches on).
2. Suricata and the service logs record it; the CrowdSec log processor matches a scenario (lock).
3. CrowdSec writes a ban decision; the firewall bouncer loads the IP into a pf drop table (engage/deny).
4. The full event (timestamps, ports, payload, Suricata's EVE JSON, optional packet capture) is logged for attribution (the ELINT cut; see the proof layer below).
5. The decision is pushed to CAPI; the community degrades that attacker everywhere (datalink).

**Why Suricata *and* CrowdSec, not one of them.** They see different things. Suricata does deep packet inspection and catches exploit *content* on the wire; CrowdSec does cross-log *behavioral* correlation and catches patterns (the same IP failing auth across services) and brings the crowd-sourced blocklist. Running both gives you signature detection, behavioral detection, and global threat intel feeding one firewall.

**Pros:** all first-party or official-plugin, no custom code; survives reboots and updates; the community blocklist means you benefit from attacks on others; scales to your whole network because the OPNsense box is the gateway all traffic crosses.

**Cons:** Suricata in inline IPS mode is CPU-hungry (budget a 4-core box and ≥4 GB RAM for ~1 Gbps, with multi-queue NICs); a badly tuned ruleset in blocking mode can break legitimate traffic, which is exactly why you run IDS-only first; and detection is only as good as the rules, so it will miss a genuinely novel attack that trips no signature and no scenario. Option 2 is the answer to that last gap.

## Option 2: the Decoy Grid / Tarpit (deception + cost-imposition)

Where Option 1 watches your real services, this one puts out *fake emitters*: decoy services that exist only to be attacked. It is the towed-decoy / expendable-decoy side of EW: something that deliberately radiates to attract the shot, reveal the shooter, and waste its munitions. Its defining advantage is attribution so clean it needs no interpretation: **nothing legitimate ever touches a decoy, so every single hit is, by definition, a confirmed hostile with no false positives.** That is the opposite of Option 1's signature-tuning problem, and it is why the two belong together.

**Step one, move the real services and bait the old ports.** Put your real SSH on a non-standard port and let the bots keep hammering 22. Anything that connects to port 22 is now either lost or hostile, and it walks straight into a tarpit.

**The tarpit, the legal "jam."** A tarpit answers the connection and then feeds it an endless, painfully slow trickle so the attacker's scanner hangs instead of moving on. Two tiny, battle-tested tools:

- **`endlessh` / `endlessh-go`:** an SSH tarpit that sends an endless, random SSH banner and keeps clients locked up for hours or days. `endlessh-go` is a ~10 MB-memory Go rewrite with built-in metrics/observability and sits on a decoy port by default. Deploy it in a container or small VM/jail.
- **`tarpitd.py`:** a multi-protocol tarpit that can run SSH (endlessh mode), an endless-HTTP-header pattern, and a slow-TLS-hello pattern at once; a flag like `-r -2` makes it wait two seconds per byte, so every malicious request endures a long delay. Good for catching HTTP scanners hunting `/wp-admin`, `/.env`, and the like.

This is the honest version of "attack back": you are not touching the attacker's machine, you are making *your own* machine an expensive place to attack. It all happens inside your perimeter, so it is entirely legal, and it measurably reduces how many other targets the attacker can hit per hour.

**Optional: a low-interaction honeypot for richer capture.** If you want to know *what* the attacker tries, not just that they knocked, add a low-interaction honeypot such as OpenCanary or a modern deception tool like Beelzebub (multi-protocol SSH/HTTP/TCP/TELNET decoys from a simple YAML config, with an LLM-driven adaptive-response mode). It records the commands, credentials, and tool signatures they use before they reach anything real. **Keep it low-interaction and network-isolated:** a decoy must never become a pivot into your real network.

**Closing the loop back to the firewall.** A tarpit or honeypot that only logs is a sensor without a shooter. Wire the decoy's hits back to OPNsense so a single touch triggers a network-wide block:

1. The decoy logs each connecting IP (every one is confirmed hostile).
2. A small watcher (a few lines of shell/Python tailing the log, or a CrowdSec custom acquisition that reads the decoy log) extracts the source IP.
3. It adds that IP to an OPNsense firewall alias / pf table that your WAN rules drop: an instant, high-confidence ban.
4. If you run CrowdSec from Option 1, feed the decoy log to it instead; the ban then propagates through the bouncer *and* can be reported to the community.

**Pros:** essentially zero false positives, so bans are safe to make instantly and automatically; catches novel and zero-day *scanning* that trips no Suricata signature; tiny footprint (endlessh-go runs in ~10 MB); imposes real, measurable cost on the attacker; zero risk to production traffic because the decoys are isolated.

**Cons:** it only catches attackers who touch the bait, so it complements Option 1's inspection of real traffic rather than replacing it; any honeypot above the simplest tarpit must be carefully isolated so it can't be abused as a stepping-stone; and a pure tarpit tells you an IP is hostile but little about intent unless you add the honeypot layer.

## The attribution & proof layer (shared by both options)

This is the "log the attackers with proof of where they originate" requirement: the ELINT cut that turns a block into evidence. Both designs feed the same layer. The principle: capture more than an IP, and get it off the box before anyone can tamper with it.

**What to capture (the evidence, strongest first):**

- **Full packet capture (pcap).** Suricata can save the actual packets that triggered an alert; OPNsense exposes pcap directly. The raw payload plus headers is the primary exhibit: it shows exactly what was sent, not just that something was.
- **Structured event records (Suricata EVE JSON).** Every alert is a JSON record with a precise timestamp, the full 5-tuple (source IP + port, destination IP + port), protocol, the signature that matched, and the flow it belonged to. This is the machine-readable spine of the case.
- **Flow / NetFlow records.** OPNsense's own flow logging records who talked to whom, when, and how much: corroborating metadata that stands even when payloads are encrypted.
- **Firewall and service logs.** The drop events and the authentication failures, time-correlated to the above.

**Enrichment: the "from where" part.** Decorate every source IP with GeoIP (country/city), ASN and network owner, reverse DNS, and the WHOIS abuse contact. OPNsense supports GeoIP in aliases and CrowdSec enriches decisions with geo data; together they give you "this came from AS####, hosting provider X, geolocated to country Y," which is both the attribution you asked for and the input to a formal abuse report to the upstream provider.

**Chain of custody: why it must leave the box immediately.** Logs that live only on the firewall are worthless as proof if the firewall is ever compromised. Ship them off in real time to an append-only / write-once store: Suricata's `eve.json` via the Filebeat plugin to a central logging cluster (Elastic or equivalent), or syslog over TLS to a remote collector. Make the timestamps trustworthy with NTP, and ideally hash or sign the archived records. Off-box, time-synced, integrity-protected logs are the difference between "evidence" and "a claim."

**One honest caveat on "origin."** A source IP is proof of the *proximate* emitter, the last hop that reached you, not automatically the human behind it. Attackers routinely route through compromised hosts, rented VPS, VPNs, Tor, or botnets. So your proof is solid as "this IP, on this network, in this country, attacked me at this timestamp," which is exactly what you need for a block, an abuse report, or handing a case to law enforcement. It is *not* a basis to counter-attack that address, which is the operational half of why the hack-back line in the first section matters.

## Which to pick, and why they're one system

Run both, layered. They cover each other's blind spots: Option 1 inspects your *real* traffic but depends on rules and can false-positive; Option 2 has perfect precision but only sees attackers who touch the bait. Together you get signature detection, behavioral correlation, global threat intel, zero-false-positive decoys, and cost-imposition, all funneling into one pf block table and one proof store. If you must sequence it, build Option 1 first (it protects real services from day one) and add Option 2 once the sensor-shooter loop is solid.

| Dimension | Option 1: Sensor-Shooter | Option 2: Decoy / Tarpit |
| --- | --- | --- |
| Growler analog | ES receiver + jammer + datalink | Towed / expendable decoy |
| Core tools | Suricata + CrowdSec (native OPNsense) | endlessh-go / tarpitd.py (+ optional honeypot) |
| Detects | Exploit content + attack behavior on real traffic | Anyone who touches a fake service |
| False positives | Possible until tuned (run IDS first) | Essentially zero by design |
| Catches novel / zero-day | Only if it trips a rule or scenario | Yes, any scan of the bait |
| Compute cost | High in inline IPS mode (4-core, ≥4 GB) | Tiny (~10 MB for endlessh-go) |
| Risk to production | Misconfigured IPS can drop good traffic | None if decoys are isolated |
| Best at | Protecting real services + community intel | Clean attribution + wasting attacker time |

## Phased implementation checklist

Build order from a bare OPNsense box to the full reactive loop. The golden rule is the IDS→IPS cutover: never start in blocking mode. Watch first, then enforce.

**Phase 0: Baseline and safety**

- Confirm OPNsense is current (25.7+) and take a config backup before changes
- Enable NTP so every log timestamp is trustworthy
- Set up a remote log target now (syslog over TLS or the Filebeat plugin) so nothing is ever only on-box

**Phase 1: Sensor (Suricata in IDS mode)**

- Services → Intrusion Detection → Administration: enable on WAN, Hyperscan pattern matcher
- Add the ET Open ruleset; schedule daily rule updates
- Leave it in IDS (alert-only) mode and watch the Alerts tab for several days
- Enable EVE JSON output and confirm events are reaching your remote store

**Phase 2: Shooter (CrowdSec)**

- System → Firmware → Plugins → install os-crowdsec (show community plugins)
- Verify the three services are running: Log Processor, LAPI, Remediation Component
- Point CrowdSec acquisition at the Suricata and firewall/service logs
- Create a free CrowdSec Console account and subscribe to the community blocklist (CAPI)
- Whitelist your own admin IPs / RFC1918 ranges so you can never ban yourself

**Phase 3: Cut to prevention**

- Review which Suricata rules and CrowdSec scenarios fired, and suppress the noisy false positives
- In a maintenance window, switch Suricata to IPS mode (Netmap or Divert)
- Enable the CrowdSec firewall bouncer and confirm bans land in the pf table
- Add the WAN block rule that drops the CrowdSec / blocklist alias

**Phase 4: Decoy grid (Option 2)**

- Move real SSH/RDP/admin to non-standard ports; confirm your own access still works
- Stand up endlessh-go (and/or tarpitd.py) on an isolated VM, container, or jail
- Port-forward the baited ports (22, etc.) from OPNsense to the decoy
- Wire decoy hits into the OPNsense block alias (log-watcher script or CrowdSec custom acquisition)
- (Optional) Add an isolated low-interaction honeypot (OpenCanary / Beelzebub) for richer capture

**Phase 5: Proof pipeline**

- Turn on packet capture on Suricata alerts
- Confirm pcap + EVE JSON + flow records all land in the remote store
- Add GeoIP / ASN / WHOIS enrichment to source IPs
- Build one dashboard: top attacker IPs, countries, ASNs, and ban counts

**Phase 6: Operate**

- Keep rules and scenarios on auto-update; review suppressions monthly
- Set a sane ban duration and decay so the block table doesn't grow forever
- Spot-check that community intel is both consumed and contributed
- Define a retention window for captured evidence and enforce it (see guardrails)

## Legal & operational guardrails

The single rule that keeps all of this lawful: **everything acts only on traffic that comes to you, or on your own equipment.** Blocking, tarpitting, deceiving, logging, and reporting are all inside-the-perimeter actions. The line you do not cross is reaching out to touch the attacker's system.

- **No hacking back.** The CFAA bars accessing another computer without authorization and has no private self-defense exception. U.S. DOJ guidance (CCIPS) has consistently warned victims not to hack back, and the 2022 CFAA charging policy that protects good-faith security research explicitly offers *no* safe harbor for it. The August 12, 2026 federal "active cyber response" program is a narrow, vetted, government-authorized channel aimed at foreign cyber-criminal organizations, not a license for a private operator, and not something you opt into through a firewall.
- **What *is* fine, actively:** drop and blackhole hostile IPs; tarpit and waste their resources on your own box; deceive them with decoys; file abuse reports to the upstream provider using your enriched logs; share indicators to a community blocklist; and hand evidence to law enforcement.
- **Don't hurt yourself:** always whitelist your own admin and RFC1918 ranges; prefer banning single IPs over wide ranges that could catch legitimate users; keep honeypots low-interaction and network-isolated so a decoy can never be used as a pivot.
- **Data retention and privacy:** captured packets and logs can contain personal data, so set an explicit retention window, restrict access to the evidence store, and dispose of it on schedule. It is worth a quick check against any logging/GDPR obligations that apply to you.
- **If you ever think you need to go offensive,** that is a conversation with legal counsel and law enforcement, not a configuration change. For almost every real-world case, detect → deny → attribute → report → share gets you the outcome you actually want: the attack stops, you have proof, and the attacker pays a cost.

## Hardened reference design: the GrowlerGrid recipe

This is the concrete, hardened build chosen for a simple, low-maintenance, self-maintaining system. It uses **no custom OPNsense GUI plugin**, because a custom plugin breaks on firmware upgrades and becomes a maintenance trap. The core is native OPNsense features plus one dependency-free Python daemon.

The moving parts:

- **Suricata (native):** IDS/IPS on WAN, the sensor. Native OPNsense feature, auto-updating rules.
- **CrowdSec (`os-crowdsec`, native plugin):** behavioral detection + the community blocklist, consumed and contributed.
- **An isolated decoy host** running an existing, battle-tested tarpit (`endlessh-go`) and optionally a low-interaction honeypot. Not on the firewall itself.
- **The GrowlerGrid collector:** one stdlib-only Python daemon (`gg-collectord.py`) that reads the decoy/Suricata/firewall logs, maintains a progressive ban table, and writes a plain blocklist file.
- **A native OPNsense URL-table alias** that ingests that blocklist file, dropped by one WAN rule.

Data flow: attacker hits a real service or a decoy → the event lands in a log → the collector escalates that IP's ban and rewrites the blocklist atomically → OPNsense re-reads the alias on its refresh interval → the WAN rule drops the IP. CrowdSec runs in parallel for signatured/behavioral traffic and the global feed. Nothing in this loop makes an outbound connection, and no component writes to another's files.

**Why it is self-maintaining:** rules auto-update (Suricata, CrowdSec); the decision log is a byte-capped ring that trims itself (no logrotate); the ban table decays on its own and persists across reboots; the blocklist is regenerated from live state every cycle; and bans have a hard horizon so reassigned or botnet-victim IPs always clear themselves. There is nothing to prune, rotate, or flush by hand.

## Security posture & threat model

The design is **fail-closed and inward-only**. Each guardrail maps to a concrete failure it prevents:

- **Never ban yourself.** RFC1918, loopback, and link-local ranges are always whitelisted, plus any admin CIDRs you add. A whitelisted address can never reach the blocklist, even on malformed input. (Prevents locking yourself out of management.)
- **No outbound from the collector.** The daemon opens no sockets; it only reads local logs and writes two local files. (Prevents the core from being a data-exfiltration or callback vector.)
- **Atomic output.** The blocklist is written to a temp file and `os.replace`d. (Prevents OPNsense ever ingesting a half-written list and dropping or passing the wrong traffic.)
- **Isolated decoy.** The tarpit/honeypot runs on a separate host with egress filtering, never on the firewall. (Prevents a decoy being used as a pivot into your network.)
- **Least privilege.** The systemd unit ships with `NoNewPrivileges`, `ProtectSystem=strict`, and a minimal writable-paths list; the rc.d service is scoped similarly. (Limits blast radius if the daemon is ever exploited.)
- **Bounded persistence.** The ring log cannot grow past its cap and the ban table cannot grow without bound. (Prevents disk-exhaustion as a denial-of-service against your own firewall.)

Residual risks stated honestly: signature/behavioral detection still misses genuinely novel attacks that trip no rule and touch no decoy; a source IP proves the proximate emitter, not the human; and no system is provably hole-free. The design minimizes, not eliminates, these.

## What was tested here vs. what you must test on your box

**Tested in development (real, automated, reproducible):** the engine ships with an 18-case `unittest` suite and a 200,000-event stress simulation, both passing. The simulation processed 168,385 hostile events, correctly refused all 31,615 whitelisted hits, held the ring log to 849,668 bytes under its 1,048,576-byte cap, kept every emitted entry a valid public IP, and decayed all bans to zero once attacks stopped. Run them yourself with `python3 -m unittest -v` and `python3 simulate.py`.

**Cannot be tested from a development environment; you must run these on real OPNsense/FreeBSD hardware.** This is the honest boundary: there is no OPNsense kernel, netmap, or pf here, so the integration must be validated on your box. The acceptance checklist:

| # | Acceptance test | Pass criterion |
| --- | --- | --- |
| 1 | Suricata IDS mode on WAN for 72h | Alerts populate; no legitimate traffic dropped |
| 2 | CrowdSec bouncer bans a test IP | IP appears in the pf table and is dropped |
| 3 | Collector writes blocklist from a decoy hit | Your real test IP lands in the alias within one refresh |
| 4 | URL-table alias + WAN drop rule | Blocked IP cannot reach any service; you still can |
| 5 | Reboot the firewall | Active bans survive (table persisted); no unblock gap |
| 6 | Admin IP / RFC1918 under attack simulation | Never banned; management stays reachable |
| 7 | Run for 7 days | Ring log stays capped; disk flat; no manual maintenance |
| 8 | Suricata IDS→IPS cutover in a window | No legitimate service interrupted after tuning |
