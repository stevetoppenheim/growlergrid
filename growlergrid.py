#!/usr/bin/env python3
"""
GrowlerGrid collector -- the reactive core of the OPNsense "detect -> deny ->
attribute -> share" recipe.

Design goals (match the project's requirements):
  * stdlib only -> runs on OPNsense base Python3, nothing to maintain/update
  * fail-closed -> a whitelisted/private IP can NEVER be banned, even on bad input
  * self-maintaining logs -> a byte-capped ring log, no logrotate/cron/flush needed
  * atomic output -> the blocklist is swapped in with os.replace (never half-written)
  * no outbound network -> this module never opens a socket; it only reads logs
                           and writes two local files

It reads attack-event log lines (from a decoy/tarpit, the firewall, or Suricata),
escalates a per-IP ban progressively, lets old bans decay, and writes a plain
"one IP per line" blocklist that OPNsense ingests as a native URL-table alias.

This file is intentionally dependency-free and side-effect-free on import so it
can be unit-tested in isolation.
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
import tempfile
import time
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

__all__ = [
    "BanTier",
    "BanRecord",
    "BanTable",
    "RingLog",
    "Whitelist",
    "BlocklistEmitter",
    "parse_line",
    "DEFAULT_TIERS",
    "DEFAULT_PARSERS",
]

# --------------------------------------------------------------------------
# Ban policy
# --------------------------------------------------------------------------

# Progressive ("parabolic") ban durations in seconds, one per cumulative
# offense weight bracket. The Nth offense lands the attacker in tier N
# (clamped to the last tier). These are deliberately conservative defaults.
DEFAULT_TIERS: Tuple[int, ...] = (
    15 * 60,        # 1st strike: 15 minutes
    60 * 60,        # 2nd:         1 hour
    6 * 60 * 60,    # 3rd:         6 hours
    24 * 60 * 60,   # 4th:        24 hours
    72 * 60 * 60,   # 5th:        72 hours
    7 * 24 * 60 * 60,  # 6th+:     7 days
)


@dataclass
class BanTier:
    """A resolved ban decision for a single IP at a point in time."""

    ip: str
    offenses: int
    expires_at: float
    reason: str


@dataclass
class BanRecord:
    offenses: int = 0
    weight: float = 0.0
    first_seen: float = 0.0
    last_seen: float = 0.0
    expires_at: float = 0.0
    reason: str = ""


class BanTable:
    """Per-IP progressive ban state with time-based decay.

    All time is passed in explicitly (``now``) so the logic is deterministic
    and unit-testable -- no hidden clock.
    """

    def __init__(self, tiers: Sequence[int] = DEFAULT_TIERS,
                 max_horizon: int = 30 * 24 * 60 * 60) -> None:
        if not tiers:
            raise ValueError("tiers must be non-empty")
        if max_horizon <= 0:
            raise ValueError("max_horizon must be positive")
        self.tiers: Tuple[int, ...] = tuple(int(t) for t in tiers)
        # A single IP can never be banned past now + max_horizon. This keeps
        # the table self-clearing (a reassigned/botnet-victim IP always decays
        # once the attacks stop) and bounds persistence. A relentless attacker
        # simply keeps refreshing the horizon as long as it keeps attacking.
        self.max_horizon = int(max_horizon)
        self._rows: Dict[str, BanRecord] = {}

    def observe(self, ip: str, now: float, weight: float = 1.0,
                reason: str = "") -> BanRecord:
        """Record one hostile event for ``ip`` and (re)compute its ban."""
        rec = self._rows.get(ip)
        if rec is None:
            rec = BanRecord(first_seen=now)
            self._rows[ip] = rec
        rec.offenses += 1
        rec.weight += float(weight)
        rec.last_seen = now
        if reason:
            rec.reason = reason
        tier_index = min(rec.offenses - 1, len(self.tiers) - 1)
        duration = self.tiers[tier_index]
        # Extend from the later of "now" or the current expiry so stacking
        # offenses never shortens an existing ban...
        base = max(now, rec.expires_at)
        # ...but never past now + max_horizon, so a burst can't ban an IP for
        # months and a reassigned IP always clears once attacks stop.
        rec.expires_at = min(base + duration, now + self.max_horizon)
        return rec

    def decay(self, now: float) -> int:
        """Drop expired rows. Returns the number removed."""
        dead = [ip for ip, r in self._rows.items() if r.expires_at <= now]
        for ip in dead:
            del self._rows[ip]
        return len(dead)

    def active(self, now: float) -> List[BanTier]:
        """Currently-banned IPs, newest-expiry first."""
        out = [
            BanTier(ip=ip, offenses=r.offenses, expires_at=r.expires_at,
                    reason=r.reason)
            for ip, r in self._rows.items()
            if r.expires_at > now
        ]
        out.sort(key=lambda b: b.expires_at, reverse=True)
        return out

    def snapshot(self) -> Dict[str, BanRecord]:
        return dict(self._rows)

    def to_dict(self) -> Dict[str, Dict]:
        return {
            ip: {"offenses": r.offenses, "weight": r.weight,
                 "first_seen": r.first_seen, "last_seen": r.last_seen,
                 "expires_at": r.expires_at, "reason": r.reason}
            for ip, r in self._rows.items()
        }

    def load_dict(self, data: Dict[str, Dict], now: float = 0.0) -> None:
        """Replace state from a saved snapshot, dropping already-expired rows."""
        self._rows = {}
        for ip, d in (data or {}).items():
            try:
                exp = float(d.get("expires_at", 0.0))
            except (TypeError, ValueError):
                continue
            if exp <= now:
                continue  # expired while we were down -> don't resurrect it
            self._rows[ip] = BanRecord(
                offenses=int(d.get("offenses", 1)),
                weight=float(d.get("weight", 1.0)),
                first_seen=float(d.get("first_seen", 0.0)),
                last_seen=float(d.get("last_seen", 0.0)),
                expires_at=exp,
                reason=str(d.get("reason", "")),
            )

    def __len__(self) -> int:
        return len(self._rows)


# --------------------------------------------------------------------------
# Whitelist (fail-closed safety net)
# --------------------------------------------------------------------------

class Whitelist:
    """CIDR whitelist. Anything here is NEVER banned.

    Defaults always include the RFC1918 / loopback / link-local ranges so a
    misconfiguration can never lock out local administration.
    """

    _ALWAYS = (
        "127.0.0.0/8", "::1/128",
        "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
        "169.254.0.0/16", "fe80::/10", "fc00::/7",
    )

    def __init__(self, extra_cidrs: Iterable[str] = ()) -> None:
        nets = list(self._ALWAYS) + list(extra_cidrs)
        self._nets = []
        for c in nets:
            try:
                self._nets.append(ipaddress.ip_network(c, strict=False))
            except ValueError:
                # A bad whitelist entry must not crash the daemon; skip it.
                continue

    def contains(self, ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            # Not even a valid IP -> treat as NOT whitelisted, but callers
            # should have rejected it already. Returning False here keeps the
            # whitelist from silently swallowing junk.
            return False
        return any(addr in net for net in self._nets)


# --------------------------------------------------------------------------
# Self-trimming ring log (no logrotate, no flush cron)
# --------------------------------------------------------------------------

class RingLog:
    """A byte-capped append log that trims itself from the front.

    Hard guarantee: once appending has returned, the file is always
    <= ``max_bytes`` bytes. When a write pushes the file over the cap we trim
    it back down to ``trim_to`` * ``max_bytes`` (aligned to a line boundary),
    so trimming is amortized O(1) rather than on every write. No logrotate, no
    cron, no flush is ever required.
    """

    def __init__(self, path: str, max_bytes: int = 5 * 1024 * 1024,
                 trim_to: float = 0.8) -> None:
        if max_bytes <= 0:
            raise ValueError("max_bytes must be positive")
        if not 0.0 < trim_to < 1.0:
            raise ValueError("trim_to must be between 0 and 1")
        self.path = path
        self.hard_cap = int(max_bytes)
        self.target = max(1, int(max_bytes * trim_to))

    def append(self, line: str) -> None:
        data = (line.rstrip("\n") + "\n").encode("utf-8", "replace")
        # A single line larger than the cap is itself truncated to fit.
        if len(data) > self.hard_cap:
            data = data[: self.hard_cap - 1] + b"\n"
        with open(self.path, "ab") as fh:
            fh.write(data)
        if os.path.getsize(self.path) > self.hard_cap:
            self._trim()

    def _trim(self) -> None:
        with open(self.path, "rb") as fh:
            fh.seek(-self.target, os.SEEK_END)
            tail = fh.read()
        # Align to the next line boundary so we never keep a partial line.
        nl = tail.find(b"\n")
        if 0 <= nl < len(tail) - 1:
            tail = tail[nl + 1:]
        tmp = self.path + ".tmp"
        with open(tmp, "wb") as fh:
            fh.write(tail)
        os.replace(tmp, self.path)

    def size(self) -> int:
        try:
            return os.path.getsize(self.path)
        except OSError:
            return 0

    def read_text(self) -> str:
        try:
            with open(self.path, "r", encoding="utf-8", errors="replace") as fh:
                return fh.read()
        except OSError:
            return ""


# --------------------------------------------------------------------------
# Blocklist emitter (atomic)
# --------------------------------------------------------------------------

class BlocklistEmitter:
    """Writes the active blocklist as one-IP-per-line, atomically.

    OPNsense ingests this file as a URL-table (IP) alias. The write is atomic
    (temp file + os.replace) so OPNsense never reads a half-written list.
    """

    def __init__(self, path: str) -> None:
        self.path = path

    def write(self, ips: Iterable[str], header: Optional[str] = None) -> int:
        uniq = sorted(set(ips))
        d = os.path.dirname(self.path) or "."
        fd, tmp = tempfile.mkstemp(dir=d, prefix=".bl-", suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                if header:
                    for hline in header.splitlines():
                        fh.write("# " + hline + "\n")
                for ip in uniq:
                    fh.write(ip + "\n")
            os.replace(tmp, self.path)
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)
        return len(uniq)


# --------------------------------------------------------------------------
# Log parsing
# --------------------------------------------------------------------------

# Each parser maps a raw log line to (ip, weight, reason) or None.
# Weight lets a high-confidence source (a decoy touch) escalate faster than a
# low-confidence one (a single firewall drop).
_IP_RE = re.compile(
    r"(?P<ip>(?:\d{1,3}\.){3}\d{1,3}|[0-9a-fA-F:]{2,}:[0-9a-fA-F:]*)"
)


def _valid_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def _decoy_parser(line: str) -> Optional[Tuple[str, float, str]]:
    # Decoy/tarpit log: "<epoch> <ip>" -- every hit is confirmed hostile.
    parts = line.split()
    if len(parts) >= 2 and _valid_ip(parts[1]):
        return (parts[1], 3.0, "decoy")
    if len(parts) >= 1 and _valid_ip(parts[0]):
        return (parts[0], 3.0, "decoy")
    return None


def _suricata_eve_parser(line: str) -> Optional[Tuple[str, float, str]]:
    # Suricata EVE JSON: use src_ip of an alert event only.
    line = line.strip()
    if not line or line[0] != "{":
        return None
    try:
        ev = json.loads(line)
    except (ValueError, TypeError):
        return None
    if ev.get("event_type") != "alert":
        return None
    ip = ev.get("src_ip")
    if isinstance(ip, str) and _valid_ip(ip):
        sev = ((ev.get("alert") or {}).get("severity")) or 3
        weight = 2.0 if sev and sev <= 2 else 1.0
        return (ip, weight, "suricata")
    return None


def _firewall_parser(line: str) -> Optional[Tuple[str, float, str]]:
    # Generic firewall/filterlog block line: take the first IP that appears.
    m = _IP_RE.search(line)
    if m and _valid_ip(m.group("ip")):
        return (m.group("ip"), 1.0, "firewall")
    return None


DEFAULT_PARSERS = {
    "decoy": _decoy_parser,
    "suricata": _suricata_eve_parser,
    "firewall": _firewall_parser,
}


def parse_line(line: str, source: str) -> Optional[Tuple[str, float, str]]:
    """Parse one line from a named source into (ip, weight, reason)."""
    parser = DEFAULT_PARSERS.get(source)
    if parser is None:
        return None
    return parser(line)


# --------------------------------------------------------------------------
# Collector -- ties it together (used by the daemon; pure w.r.t. inputs)
# --------------------------------------------------------------------------

@dataclass
class Collector:
    table: BanTable
    whitelist: Whitelist
    emitter: BlocklistEmitter
    ring: Optional[RingLog] = None
    processed: int = field(default=0)
    skipped_whitelist: int = field(default=0)
    skipped_invalid: int = field(default=0)

    def ingest(self, line: str, source: str, now: float) -> bool:
        """Process one raw line. Returns True if it produced/updated a ban."""
        parsed = parse_line(line, source)
        if parsed is None:
            self.skipped_invalid += 1
            return False
        ip, weight, reason = parsed
        if not _valid_ip(ip):
            self.skipped_invalid += 1
            return False
        if self.whitelist.contains(ip):
            # FAIL-CLOSED: never, ever ban a whitelisted/private address.
            self.skipped_whitelist += 1
            return False
        rec = self.table.observe(ip, now=now, weight=weight, reason=reason)
        self.processed += 1
        if self.ring is not None:
            self.ring.append(
                "%d %s %s off=%d exp=%d"
                % (int(now), ip, reason, rec.offenses, int(rec.expires_at))
            )
        return True

    def flush(self, now: float) -> int:
        """Decay expired bans and (re)write the blocklist. Returns count."""
        self.table.decay(now)
        ips = [b.ip for b in self.table.active(now)]
        return self.emitter.write(
            ips,
            header="GrowlerGrid blocklist - generated %d - %d active"
            % (int(now), len(ips)),
        )
