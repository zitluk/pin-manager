"""Domény pro DNS sinkhole – apex + www + známé aliasy."""

KNOWN_ALIASES: dict[str, list[str]] = {
    "youtube.com": ["googlevideo.com", "ytimg.com", "youtube-nocookie.com"],
    "tiktok.com": ["tiktokv.com", "tiktokcdn.com"],
}


def expand_sinkhole_domains(domains: list[str]) -> list[str]:
    out: set[str] = set()
    for raw in domains:
        d = raw.strip().lower()
        if not d:
            continue
        out.add(d)
        if not d.startswith("www."):
            out.add(f"www.{d}")
        for alias in KNOWN_ALIASES.get(d, []):
            out.add(alias)
            out.add(f"www.{alias}")
    return sorted(out)
