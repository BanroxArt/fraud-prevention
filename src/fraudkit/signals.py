"""Stateless signals computed from a single event's fields."""

from __future__ import annotations

import ipaddress
import math
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass

# Providers that ignore dots in the local part. Extend if your traffic shows
# other providers doing the same; do not guess.
_DOTLESS_PROVIDERS = {"gmail.com", "googlemail.com"}

# Documentation ranges count as "private" in the ipaddress module. They are
# what tests and examples use, so do not treat them as a header bug.
_DOC_NETS = tuple(
    ipaddress.ip_network(n)
    for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32")
)


@dataclass(frozen=True, slots=True)
class Hit:
    code: str
    detail: str


def split_email(email: str) -> tuple[str, str] | None:
    email = email.strip().lower()
    if email.count("@") != 1:
        return None
    local, domain = email.split("@")
    if not local or "." not in domain:
        return None
    return local, domain


def normalize_email(email: str) -> str | None:
    """Canonical mailbox for linking: lowercase, drop ``+tag``, drop dots on Gmail.

    On Gmail, ``a.b+promo1`` and ``ab`` are the same inbox, so they should
    link to the same identity node.
    """
    parts = split_email(email)
    if parts is None:
        return None
    local, domain = parts
    local = local.split("+", 1)[0]
    if domain == "googlemail.com":
        domain = "gmail.com"
    if domain in _DOTLESS_PROVIDERS:
        local = local.replace(".", "")
    if not local:
        # "+promo@x" or ".@gmail.com" would all collapse to "@x" and link
        # every such signup into one cluster.
        return None
    return f"{local}@{domain}"


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    n = len(text)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def email_hits(
    email: str | None,
    disposable_domains: Iterable[str],
    *,
    digit_ratio: float = 0.5,
    entropy_bits: float = 3.6,
    min_random_len: int = 12,
) -> list[Hit]:
    if not email:
        return [Hit("EMAIL_MISSING", "no email on event")]
    parts = split_email(email)
    if parts is None:
        return [Hit("EMAIL_MALFORMED", "email does not parse")]
    local, domain = parts
    hits: list[Hit] = []
    disposable = {d.lower() for d in disposable_domains}
    # Match the registered domain and any subdomain of it.
    labels = domain.split(".")
    if any(".".join(labels[i:]) in disposable for i in range(len(labels) - 1)):
        hits.append(Hit("EMAIL_DISPOSABLE", domain))
    base = local.split("+", 1)[0]
    if "+" in local:
        hits.append(Hit("EMAIL_PLUS_TAG", "plus addressing"))
    digits = sum(ch.isdigit() for ch in base)
    if base and digits / len(base) >= digit_ratio and len(base) >= 6:
        hits.append(Hit("EMAIL_DIGIT_HEAVY", f"{digits}/{len(base)} digits"))
    stripped = base.replace(".", "").replace("_", "")
    if len(stripped) >= min_random_len and shannon_entropy(stripped) >= entropy_bits:
        hits.append(Hit("EMAIL_RANDOM_LOCALPART", f"entropy {shannon_entropy(stripped):.2f}"))
    return hits


class IpClassifier:
    """Classify client IPs against operator-supplied CIDR lists.

    fraudkit ships no hosting or proxy ranges. Those lists go stale quickly
    and their licensing varies, so you bring your own.
    """

    def __init__(
        self, hosting_cidrs: Iterable[str] = (), blocked_cidrs: Iterable[str] = ()
    ) -> None:
        self.hosting = [ipaddress.ip_network(c, strict=False) for c in hosting_cidrs]
        self.blocked = [ipaddress.ip_network(c, strict=False) for c in blocked_cidrs]

    def hits(self, ip: str | None) -> list[Hit]:
        if not ip:
            return []
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return [Hit("IP_MALFORMED", "unparseable ip")]
        out: list[Hit] = []
        is_doc = any(addr in net for net in _DOC_NETS if net.version == addr.version)
        if (addr.is_private or addr.is_loopback or addr.is_link_local) and not is_doc:
            # A client IP should never be private. This usually means the
            # proxy header is not being read, which breaks every IP rule.
            out.append(Hit("IP_NON_ROUTABLE", "private or loopback client ip"))
        if any(addr in net for net in self.blocked):
            out.append(Hit("IP_BLOCKLIST", "ip in blocked range"))
        elif any(addr in net for net in self.hosting):
            out.append(Hit("IP_HOSTING", "ip in hosting range"))
        return out


def ip_prefix(ip: str | None, v4_bits: int = 24, v6_bits: int = 64) -> str | None:
    """Collapse an IP to its network prefix for velocity keys.

    Per-address keys are easy to dodge with a /24 or a /64 of rotating
    addresses, so velocity rules usually want the prefix.
    """
    if not ip:
        return None
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    bits = v4_bits if addr.version == 4 else v6_bits
    return str(ipaddress.ip_network(f"{addr}/{bits}", strict=False))
