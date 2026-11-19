#!/usr/bin/env python3
"""
gg-collectord -- the GrowlerGrid collector daemon.

Reads a small JSON config, tails one or more log sources (decoy/tarpit,
Suricata EVE, firewall), runs the GrowlerGrid engine, and writes:
  * an atomic blocklist file that OPNsense ingests as a URL-table alias
  * a self-trimming ring log of decisions

Stdlib only. No outbound sockets. Handles log rotation by inode. Persists
tail offsets to a state file so it survives restarts without re-banning the
whole history. Runs as a long-lived daemon, or with --once for cron/testing.

Usage:
  gg-collectord.py --config /usr/local/etc/growlergrid/config.json
  gg-collectord.py --config CONFIG --once      # single pass, for testing/cron
"""
from __future__ import annotations

import argparse
import json
import os
import signal
import sys
import time
from typing import Dict

import growlergrid as gg

DEFAULT_CONFIG = {
    "blocklist_path": "/usr/local/etc/growlergrid/blocklist.txt",
    "ring_path": "/var/log/growlergrid/decisions.log",
    "ring_max_bytes": 5 * 1024 * 1024,
    "state_path": "/var/db/growlergrid/offsets.json",
    "table_path": "/var/db/growlergrid/bantable.json",
    "whitelist": [],
    "tiers": list(gg.DEFAULT_TIERS),
    "max_horizon": 30 * 24 * 60 * 60,
    "flush_interval": 10,
    "poll_interval": 2,
    "sources": [
        # {"path": "/var/log/growlergrid/decoy.log", "source": "decoy"},
    ],
}


def load_config(path: str) -> Dict:
    cfg = dict(DEFAULT_CONFIG)
    if path:
        with open(path, "r", encoding="utf-8") as fh:
            cfg.update(json.load(fh))
    return cfg


class Tailer:
    """Follows a file by (inode, offset), surviving rotation and restarts."""

    def __init__(self, path: str, source: str, inode: int = 0, offset: int = 0):
        self.path = path
        self.source = source
        self.inode = inode
        self.offset = offset

    def read_new(self):
        try:
            st = os.stat(self.path)
        except OSError:
            return
        if st.st_ino != self.inode:
            # New/rotated file: start from the beginning of the new inode.
            self.inode = st.st_ino
            self.offset = 0
        if st.st_size < self.offset:
            # Truncated in place: restart from 0.
            self.offset = 0
        if st.st_size == self.offset:
            return
        with open(self.path, "r", encoding="utf-8", errors="replace") as fh:
            fh.seek(self.offset)
            for line in fh:
                if not line.endswith("\n"):
                    # Partial trailing line: stop; we'll get it next poll.
                    break
                yield line.rstrip("\n")
            self.offset = fh.tell()


def build_collector(cfg: Dict) -> gg.Collector:
    table = gg.BanTable(tiers=cfg["tiers"], max_horizon=cfg["max_horizon"])
    wl = gg.Whitelist(extra_cidrs=cfg["whitelist"])
    em = gg.BlocklistEmitter(cfg["blocklist_path"])
    ring = gg.RingLog(cfg["ring_path"], max_bytes=cfg["ring_max_bytes"])
    return gg.Collector(table, wl, em, ring)


def ensure_dirs(cfg: Dict) -> None:
    for key in ("blocklist_path", "ring_path", "state_path", "table_path"):
        d = os.path.dirname(cfg[key]) or "."
        os.makedirs(d, exist_ok=True)


def _atomic_json_dump(path: str, obj) -> None:
    d = os.path.dirname(path) or "."
    tmp = os.path.join(d, "." + os.path.basename(path) + ".tmp")
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(obj, fh)
    os.replace(tmp, path)


def save_table(path: str, col: "gg.Collector") -> None:
    _atomic_json_dump(path, col.table.to_dict())


def load_table(path: str, col: "gg.Collector", now: float) -> None:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            col.table.load_dict(json.load(fh), now=now)
    except (OSError, ValueError):
        pass


def load_offsets(path: str) -> Dict:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return {}


def save_offsets(path: str, tailers) -> None:
    data = {t.path: {"inode": t.inode, "offset": t.offset} for t in tailers}
    _atomic_json_dump(path, data)


def make_tailers(cfg: Dict):
    saved = load_offsets(cfg["state_path"])
    tailers = []
    for s in cfg["sources"]:
        prev = saved.get(s["path"], {})
        tailers.append(Tailer(s["path"], s["source"],
                              inode=prev.get("inode", 0),
                              offset=prev.get("offset", 0)))
    return tailers


def run(cfg: Dict, once: bool = False) -> None:
    ensure_dirs(cfg)
    col = build_collector(cfg)
    tailers = make_tailers(cfg)
    # Restore active bans from the last run so a restart/reboot/upgrade never
    # briefly unblocks everyone. Expired entries are dropped on load.
    load_table(cfg["table_path"], col, now=time.time())

    stop = {"flag": False}

    def _handler(signum, frame):
        stop["flag"] = True
    signal.signal(signal.SIGTERM, _handler)
    signal.signal(signal.SIGINT, _handler)

    def persist(now):
        col.flush(now=now)
        save_offsets(cfg["state_path"], tailers)
        save_table(cfg["table_path"], col)

    last_flush = 0.0
    while True:
        now = time.time()
        for t in tailers:
            for line in t.read_new():
                col.ingest(line, t.source, now=now)
        if once or now - last_flush >= cfg["flush_interval"]:
            persist(now)
            last_flush = now
        if once or stop["flag"]:
            if stop["flag"] and not once:
                persist(time.time())
            break
        time.sleep(cfg["poll_interval"])


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="GrowlerGrid collector daemon")
    ap.add_argument("--config", default="", help="path to config.json")
    ap.add_argument("--once", action="store_true",
                    help="single pass then exit (cron/testing)")
    args = ap.parse_args(argv)
    cfg = load_config(args.config)
    run(cfg, once=args.once)
    return 0


if __name__ == "__main__":
    sys.exit(main())
