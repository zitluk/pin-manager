"""Domény pro DNS sinkhole – apex + www + známé aliasy."""

from pin_manager.store import _normalize_domain

KNOWN_ALIASES: dict[str, list[str]] = {
    "youtube.com": ["googlevideo.com", "ytimg.com", "youtube-nocookie.com"],
    "tiktok.com": ["tiktokv.com", "tiktokcdn.com"],
}

# HSTS – nepřesměrovávat na portál (jinak dítě vidí „připojení není soukromé“).
# Blok „natvrdo“ (0.0.0.0); PIN zadá rodič na http://PORTAL_IP/
HSTS_SIMPLE_BLOCK_APEX: frozenset[str] = frozenset(
    {
        "youtube.com",
        "googlevideo.com",
        "ytimg.com",
        "youtube-nocookie.com",
        "tiktok.com",
        "tiktokv.com",
        "tiktokcdn.com",
    }
)


def partition_apex_for_sinkhole(
    apex_domains: list[str], *, https_silent: bool
) -> tuple[list[str], list[str]]:
    portal: list[str] = []
    silent: list[str] = []
    for raw in apex_domains:
        from pin_manager.store import _normalize_domain

        a = _normalize_domain(raw)
        if not a:
            continue
        if https_silent and a in HSTS_SIMPLE_BLOCK_APEX:
            silent.append(a)
        else:
            portal.append(a)
    return portal, silent


def expand_sinkhole_domains(domains: list[str]) -> list[str]:
    out: set[str] = set()
    for raw in domains:
        d = _normalize_domain(raw)
        if not d:
            continue
        out.add(d)
        out.add(f"www.{d}")
        for alias in KNOWN_ALIASES.get(d, []):
            out.add(alias)
            out.add(f"www.{alias}")
    return sorted(out)
