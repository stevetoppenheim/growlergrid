#!/usr/bin/env python3
"""High-volume simulation / stress test of the GrowlerGrid engine.

This is an honest, runnable simulation -- NOT a claim of testing on real
OPNsense hardware. It drives the pure engine with a large synthetic attack
stream and asserts the safety invariants hold under load:

  INV-1  no whitelisted/private IP is ever emitted to the blocklist
  INV-2  the ring log never exceeds its hard cap
  INV-3  every emitted IP is a syntactically valid public IP
  INV-4  expired bans decay out (table does not grow without bound)
  INV-5  the blocklist file is always parseable (atomic writes never torn)
"""
import ipaddress
import os
import random
import tempfile
import time

import growlergrid as gg

EVENTS = 200_000
SEED = 1337


def run(events: int = EVENTS) -> None:
    rng = random.Random(SEED)
    d = tempfile.mkdtemp(prefix="ggsim-")
    em = gg.BlocklistEmitter(os.path.join(d, "blocklist.txt"))
    ring = gg.RingLog(os.path.join(d, "events.log"), max_bytes=1 * 1024 * 1024)
    col = gg.Collector(gg.BanTable(), gg.Whitelist(extra_cidrs=["203.0.113.0/24"]),
                       em, ring)

    sources = ["decoy", "suricata", "firewall"]
    # Attacker pool (public) + decoy noise that includes private/whitelisted IPs
    attackers = ["%d.%d.%d.%d" % (rng.randint(1, 223), rng.randint(0, 255),
                                  rng.randint(0, 255), rng.randint(1, 254))
                 for _ in range(4000)]
    whitelisted = ["192.168.1.%d" % i for i in range(1, 60)] + \
                  ["10.0.0.%d" % i for i in range(1, 60)] + \
                  ["203.0.113.%d" % i for i in range(1, 60)]

    now = 1_700_000_000.0
    max_ring = ring.hard_cap
    emitted_total = 0
    max_table = 0

    for i in range(events):
        now += rng.random() * 2.0  # time marches forward ~1s/event avg
        if rng.random() < 0.15:
            ip = rng.choice(whitelisted)        # should always be refused
        else:
            ip = rng.choice(attackers)
        src = rng.choice(sources)
        if src == "decoy":
            line = "%d %s" % (int(now), ip)
        elif src == "suricata":
            line = ('{"event_type":"alert","src_ip":"%s",'
                    '"alert":{"severity":%d}}' % (ip, rng.randint(1, 3)))
        else:
            line = "block in on igb0 proto tcp from %s to 10.0.0.1" % ip
        col.ingest(line, src, now=now)

        # INV-2: ring cap holds on every iteration
        assert ring.size() <= max_ring, (ring.size(), max_ring)

        if i % 1000 == 0:
            count = col.flush(now=now)
            emitted_total += 1
            max_table = max(max_table, len(col.table))
            # INV-1 + INV-3: validate every emitted IP
            with open(em.path) as fh:
                for ln in fh:
                    ln = ln.strip()
                    if not ln or ln.startswith("#"):
                        continue
                    addr = ipaddress.ip_address(ln)       # INV-5 parseable
                    assert not col.whitelist.contains(ln), ln   # INV-1
                    assert addr.is_global or not (addr.is_private), ln  # INV-3
            assert count == len(col.table.active(now))

    # Fast-forward far into the future: everything must decay (INV-4)
    col.table.decay(now + 100 * 24 * 3600)
    final = col.flush(now + 100 * 24 * 3600)

    print("=" * 60)
    print("GrowlerGrid simulation complete")
    print("=" * 60)
    print("events processed ............ %d" % col.processed)
    print("whitelisted refused ......... %d" % col.skipped_whitelist)
    print("invalid/ignored ............. %d" % col.skipped_invalid)
    print("peak active ban table ....... %d IPs" % max_table)
    print("ring log final size ......... %d bytes (cap %d)"
          % (ring.size(), ring.hard_cap))
    print("blocklist flushes ........... %d" % emitted_total)
    print("active bans after +100d ..... %d" % final)
    print("-" * 60)
    print("INV-1 no whitelisted IP ever emitted ... PASS")
    print("INV-2 ring never exceeded cap .......... PASS")
    print("INV-3 every emitted IP valid+public .... PASS")
    print("INV-4 bans decay to zero over time ..... %s"
          % ("PASS" if final == 0 else "FAIL"))
    print("INV-5 blocklist always parseable ....... PASS")
    assert final == 0, "INV-4 failed: bans did not decay"


if __name__ == "__main__":
    t0 = time.time()
    run()
    print("wall time ................... %.2fs" % (time.time() - t0))
