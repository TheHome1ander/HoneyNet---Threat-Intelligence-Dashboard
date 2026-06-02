"""
services/geoip.py — Async GeoIP lookup with in-memory cache.

CONCEPT — Why ip-api.com?
──────────────────────────
We're using the free tier of ip-api.com (no API key, 45 req/min).  The
alternative is a local MaxMind GeoLite2 database (~70 MB binary file), which
requires a free account and a weekly download cron.  ip-api.com is zero-setup
and perfect for a portfolio project.

In a real production honeypot you'd use a local GeoLite2 DB (no latency, no
rate limits, no external dependency), but the API approach is a great way to
learn async HTTP client patterns.

CONCEPT — The In-Memory Cache (Why It Matters Here)
─────────────────────────────────────────────────────
A single attacker IP often sends hundreds of requests in a short burst.
Without caching, each request would fire one GeoIP HTTP call, easily blowing
past the 45 req/min free-tier limit and adding latency to every DB write.

With caching:
  • First request from 1.2.3.4  → HTTP call to ip-api.com → cache result
  • All subsequent requests      → instant dict lookup, zero network I/O

The cache is a plain dict because it only grows (we never evict — an IP's
location doesn't change).  For a process running for months, you might want
an LRU cache with a max size, but for a portfolio honeypot this is fine.

CONCEPT — Private/Reserved IPs
────────────────────────────────
IPs like 127.0.0.1 (loopback), 10.x.x.x (RFC1918), 172.16.x.x–172.31.x.x
(Docker), and 192.168.x.x (LAN) are not routable on the internet — ip-api.com
would return an error for them.  We detect these and return "Local/Private"
immediately without hitting the API.
"""

from __future__ import annotations

import ipaddress
import logging
from dataclasses import dataclass

import httpx

from app.config import settings

logger = logging.getLogger("honeypot.geoip")


# ── Result type ───────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class GeoInfo:
    country: str
    city: str
    isp: str
    region: str
    country_code: str  # ISO 3166-1 alpha-2, e.g. "IN", "US", "CN"


_UNKNOWN = GeoInfo(country="Unknown", city="Unknown", isp="Unknown", region="Unknown", country_code="XX")
_LOCAL   = GeoInfo(country="Local",   city="Private", isp="Private", region="Private", country_code="XX")


# ── Private IP detection ──────────────────────────────────────────────────────

_PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),       # Loopback
    ipaddress.ip_network("169.254.0.0/16"),    # Link-local
    ipaddress.ip_network("::1/128"),           # IPv6 loopback
    ipaddress.ip_network("fc00::/7"),          # IPv6 ULA
]


def _is_private(ip: str) -> bool:
    """Return True if the IP is in a reserved/private range."""
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in _PRIVATE_NETWORKS)
    except ValueError:
        return True  # Unparseable IP → treat as private to avoid API errors


# ── In-memory cache ───────────────────────────────────────────────────────────

# Plain dict: ip_str → GeoInfo.  Grows only; never evicted.
_cache: dict[str, GeoInfo] = {}


# ── Async HTTP client (shared, connection-pooled) ─────────────────────────────
# CONCEPT — Why a shared httpx.AsyncClient?
# Creating a new HTTP client per request is expensive: each one opens a new
# TCP connection, performs a TLS handshake, etc.  A shared client maintains a
# connection pool, re-using existing connections for subsequent requests to the
# same host.  This is equivalent to using requests.Session in synchronous code.
_http_client: httpx.AsyncClient | None = None


def get_http_client() -> httpx.AsyncClient:
    """Lazy-initialise the shared HTTP client."""
    global _http_client
    if _http_client is None or _http_client.is_closed:
        _http_client = httpx.AsyncClient(timeout=3.0)  # 3-second timeout
    return _http_client


async def close_http_client() -> None:
    """Called at shutdown to cleanly close the connection pool."""
    global _http_client
    if _http_client and not _http_client.is_closed:
        await _http_client.aclose()


# ── Public API ────────────────────────────────────────────────────────────────

async def lookup(ip: str) -> GeoInfo:
    """
    Return GeoIP information for an IP address.

    Flow:
      1. Private IP?  → return _LOCAL immediately.
      2. In cache?    → return cached result immediately.
      3. Otherwise    → call ip-api.com, cache result, return it.
      4. Any error    → log warning, return _UNKNOWN (never raise).

    This function NEVER raises — the middleware can safely fire-and-forget it.
    """
    if ip in ("unknown", "", "localhost"):
        return _LOCAL

    if _is_private(ip):
        return _LOCAL

    if ip in _cache:
        return _cache[ip]

    # ── HTTP lookup ───────────────────────────────────────────────────────────
    url = f"{settings.GEOIP_API_URL}/{ip}?fields=status,country,countryCode,city,isp,regionName,query"
    try:
        client = get_http_client()
        response = await client.get(url)
        response.raise_for_status()
        data = response.json()

        if data.get("status") != "success":
            logger.warning("GeoIP lookup failed for %s: %s", ip, data.get("message"))
            _cache[ip] = _UNKNOWN
            return _UNKNOWN

        geo = GeoInfo(
            country=data.get("country", "Unknown"),
            city=data.get("city", "Unknown"),
            isp=data.get("isp", "Unknown"),
            region=data.get("regionName", "Unknown"),
            country_code=data.get("countryCode", "XX"),
        )
        _cache[ip] = geo
        logger.debug("GeoIP: %s → %s, %s (%s)", ip, geo.city, geo.country, geo.isp)
        return geo

    except httpx.TimeoutException:
        logger.warning("GeoIP timeout for %s", ip)
    except httpx.HTTPError as exc:
        logger.warning("GeoIP HTTP error for %s: %s", ip, exc)
    except Exception as exc:
        logger.warning("GeoIP unexpected error for %s: %s", ip, exc)

    _cache[ip] = _UNKNOWN
    return _UNKNOWN
