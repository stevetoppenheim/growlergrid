# Testing

## Tested here (reproducible, no dependencies)

```
python3 -m unittest -v     # 18 unit tests
python3 simulate.py        # 200,000-event stress simulation
```

The simulation processed 168,385 hostile events, refused all 31,615 whitelisted hits, held the ring log under its byte cap, kept every emitted entry a valid public IP, and decayed all bans to zero once attacks stopped.

The unit tests cover: the RFC1918 / loopback / admin whitelist (fail-closed), progressive ban escalation, the hard ban horizon, decay and expiry, the self-trimming ring log never exceeding its cap, atomic blocklist writes, log parsing (decoy, Suricata EVE alert-only, firewall), ban-state serialization across restarts, and the end-to-end collector loop.

## Must be tested on real OPNsense / FreeBSD hardware

The engine is pure logic and testable anywhere, but the integration with Suricata, CrowdSec, netmap, and pf has no substitute for a real box. Run this acceptance checklist before you trust it in production:

| # | Acceptance test | Pass criterion |
| --- | --- | --- |
| 1 | Suricata IDS mode on WAN for 72h | Alerts populate; no legitimate traffic dropped |
| 2 | CrowdSec bouncer bans a test IP | IP appears in the pf table and is dropped |
| 3 | Collector writes blocklist from a decoy hit | Your real test IP lands in the alias within one refresh |
| 4 | URL-table alias + WAN drop rule | Blocked IP cannot reach any service; you still can |
| 5 | Reboot the firewall | Active bans survive (state persisted); no unblock gap |
| 6 | Admin IP / RFC1918 under attack simulation | Never banned; management stays reachable |
| 7 | Run for 7 days | Ring log stays capped; disk flat; no manual maintenance |
| 8 | Suricata IDS to IPS cutover in a window | No legitimate service interrupted after tuning |

If you run these, please open an issue with your results (OPNsense version, hardware, what passed, what broke).
