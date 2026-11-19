#!/usr/bin/env python3
"""Automated tests for the GrowlerGrid core engine. Run:  python3 -m unittest -v"""
import os
import tempfile
import unittest

import growlergrid as gg


class WhitelistTests(unittest.TestCase):
    def test_rfc1918_and_loopback_always_whitelisted(self):
        wl = gg.Whitelist()
        for ip in ("127.0.0.1", "10.1.2.3", "192.168.1.1", "172.16.5.5", "::1"):
            self.assertTrue(wl.contains(ip), ip)

    def test_public_ip_not_whitelisted(self):
        wl = gg.Whitelist()
        self.assertFalse(wl.contains("8.8.8.8"))
        self.assertFalse(wl.contains("2606:4700:4700::1111"))

    def test_extra_cidr_and_bad_entry_ignored(self):
        wl = gg.Whitelist(extra_cidrs=["203.0.113.0/24", "not-a-cidr"])
        self.assertTrue(wl.contains("203.0.113.44"))
        self.assertFalse(wl.contains("203.0.114.1"))


class BanTableTests(unittest.TestCase):
    def test_progressive_escalation(self):
        t = gg.BanTable(tiers=(10, 100, 1000))
        r1 = t.observe("1.2.3.4", now=0)
        self.assertEqual(r1.expires_at, 10)
        r2 = t.observe("1.2.3.4", now=0)
        self.assertEqual(r2.expires_at, 10 + 100)       # stacks, never shrinks
        r3 = t.observe("1.2.3.4", now=0)
        self.assertEqual(r3.expires_at, 110 + 1000)
        r4 = t.observe("1.2.3.4", now=0)                # clamps at last tier
        self.assertEqual(r4.expires_at, 1110 + 1000)

    def test_decay_removes_expired(self):
        t = gg.BanTable(tiers=(10,))
        t.observe("9.9.9.9", now=0)
        self.assertEqual(len(t), 1)
        self.assertEqual(t.decay(now=5), 0)
        self.assertEqual(len(t.active(now=5)), 1)
        self.assertEqual(t.decay(now=11), 1)
        self.assertEqual(len(t), 0)

    def test_empty_tiers_rejected(self):
        with self.assertRaises(ValueError):
            gg.BanTable(tiers=())

    def test_serialization_round_trip(self):
        t = gg.BanTable(tiers=(3600,))
        t.observe("5.5.5.5", now=0)
        t.observe("6.6.6.6", now=0)
        data = t.to_dict()
        t2 = gg.BanTable(tiers=(3600,))
        t2.load_dict(data, now=1)
        self.assertEqual(len(t2.active(now=1)), 2)
        # Entries already expired at load time are not resurrected.
        t3 = gg.BanTable(tiers=(3600,))
        t3.load_dict(data, now=10_000)
        self.assertEqual(len(t3), 0)

    def test_ban_horizon_is_capped(self):
        # 100 relentless hits must never push expiry past now + max_horizon.
        t = gg.BanTable(tiers=(3600,), max_horizon=86400)  # 1h tier, 1d cap
        for _ in range(100):
            rec = t.observe("6.6.6.6", now=0)
        self.assertLessEqual(rec.expires_at, 86400)
        # Once attacks stop, it fully decays within the horizon.
        self.assertEqual(t.decay(now=86401), 1)


class RingLogTests(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.p = os.path.join(self.d, "ring.log")

    def test_never_exceeds_hard_cap(self):
        ring = gg.RingLog(self.p, max_bytes=4096)
        for i in range(20000):
            ring.append("line %d padding-padding-padding-padding" % i)
            self.assertLessEqual(ring.size(), 4096)   # hard ceiling, every time
        self.assertLessEqual(ring.size(), 4096)

    def test_keeps_most_recent_lines(self):
        ring = gg.RingLog(self.p, max_bytes=2048)
        for i in range(5000):
            ring.append("entry-%05d" % i)
        text = ring.read_text()
        self.assertIn("entry-04999", text)          # newest survives
        self.assertNotIn("entry-00000", text)        # oldest trimmed
        for ln in text.splitlines():
            self.assertTrue(ln.startswith("entry-"))  # no partial lines

    def test_oversized_single_line_truncated(self):
        ring = gg.RingLog(self.p, max_bytes=64)
        ring.append("x" * 1000)
        self.assertLessEqual(ring.size(), 64)


class EmitterTests(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.p = os.path.join(self.d, "block.txt")

    def test_dedupe_and_sort(self):
        em = gg.BlocklistEmitter(self.p)
        n = em.write(["8.8.8.8", "1.1.1.1", "8.8.8.8"])
        self.assertEqual(n, 2)
        with open(self.p) as fh:
            lines = [l.strip() for l in fh if not l.startswith("#")]
        self.assertEqual(lines, ["1.1.1.1", "8.8.8.8"])

    def test_atomic_no_leftover_tmp(self):
        em = gg.BlocklistEmitter(self.p)
        em.write(["9.9.9.9"], header="hdr")
        leftovers = [f for f in os.listdir(self.d) if f.startswith(".bl-")]
        self.assertEqual(leftovers, [])


class ParserTests(unittest.TestCase):
    def test_decoy(self):
        self.assertEqual(gg.parse_line("1700000000 203.0.113.9", "decoy"),
                         ("203.0.113.9", 3.0, "decoy"))

    def test_suricata_alert_only(self):
        alert = '{"event_type":"alert","src_ip":"198.51.100.7","alert":{"severity":1}}'
        self.assertEqual(gg.parse_line(alert, "suricata"),
                         ("198.51.100.7", 2.0, "suricata"))
        flow = '{"event_type":"flow","src_ip":"198.51.100.7"}'
        self.assertIsNone(gg.parse_line(flow, "suricata"))

    def test_malformed_lines_ignored(self):
        self.assertIsNone(gg.parse_line("", "decoy"))
        self.assertIsNone(gg.parse_line("garbage with no ip", "firewall"))
        self.assertIsNone(gg.parse_line("{bad json", "suricata"))


class CollectorTests(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.em = gg.BlocklistEmitter(os.path.join(self.d, "bl.txt"))
        self.ring = gg.RingLog(os.path.join(self.d, "r.log"), max_bytes=65536)
        self.col = gg.Collector(gg.BanTable(), gg.Whitelist(), self.em, self.ring)

    def test_whitelisted_never_banned(self):
        self.assertFalse(self.col.ingest("1700000000 192.168.1.50", "decoy", now=0))
        self.assertEqual(self.col.skipped_whitelist, 1)
        self.assertEqual(self.col.flush(now=1), 0)

    def test_full_loop(self):
        self.assertTrue(self.col.ingest("1700000000 45.9.9.9", "decoy", now=0))
        self.assertEqual(self.col.flush(now=1), 1)
        with open(self.em.path) as fh:
            self.assertIn("45.9.9.9", fh.read())


if __name__ == "__main__":
    unittest.main(verbosity=2)
