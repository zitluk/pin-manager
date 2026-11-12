"""Známé alternativy domén – služby, které obsah tahají i z dalších domén (CDN, krátké odkazy).

Každá skupina platí oběma směry: přidání kterékoli domény přidá ostatní jako alternativy.
Do skupin nepatří sdílené domény (googleapis.com, fbcdn.net…) – jejich blok by rozbil
i jiné služby. Pravidlo v Pi-hole pokrývá vždy doménu i všechny poddomény.
"""

from __future__ import annotations

KNOWN_GROUPS: tuple[tuple[str, ...], ...] = (
    (
        "youtube.com", "youtu.be", "googlevideo.com", "ytimg.com", "youtube-nocookie.com",
        "youtubei.googleapis.com", "youtube.googleapis.com", "yt3.ggpht.com", "yt4.ggpht.com",
    ),
    ("tiktok.com", "tiktokv.com", "tiktokcdn.com", "tiktokcdn-us.com", "tiktokv.us", "musical.ly"),
    ("instagram.com", "cdninstagram.com", "instagr.am", "ig.me"),
    ("facebook.com", "fb.com", "facebook.net", "fb.me", "fbsbx.com"),
    ("x.com", "twitter.com", "twimg.com", "t.co"),
    ("reddit.com", "redd.it", "redditmedia.com", "redditstatic.com"),
    ("twitch.tv", "ttvnw.net", "jtvnw.net", "twitchcdn.net", "twitchsvc.net"),
    ("netflix.com", "nflxvideo.net", "nflximg.net", "nflxext.com", "nflxso.net"),
    ("discord.com", "discord.gg", "discordapp.com", "discordapp.net", "discord.media"),
    ("snapchat.com", "sc-cdn.net", "snapkit.com"),
    ("roblox.com", "rbxcdn.com"),
    ("pinterest.com", "pinimg.com", "pin.it"),
)


def known_aliases(domain: str) -> list[str]:
    """Alternativy pro doménu podle známých skupin (bez ní samotné)."""
    for group in KNOWN_GROUPS:
        if domain in group:
            return [d for d in group if d != domain]
    return []
