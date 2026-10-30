from __future__ import annotations

from dataclasses import dataclass

import feedparser


@dataclass(frozen=True, slots=True)
class FeedItem:
    title: str
    url: str
    summary: str
    published: str | None = None


class RssCollector:
    """Collect untrusted news text. It is never executed or used for version matching."""

    def collect(self, urls: list[str], limit_per_feed: int = 25) -> list[FeedItem]:
        items = []
        for url in urls:
            parsed = feedparser.parse(url)
            for entry in parsed.entries[:limit_per_feed]:
                items.append(FeedItem(
                    title=str(entry.get("title", "Untitled")), url=str(entry.get("link", url)),
                    summary=str(entry.get("summary", ""))[:10_000],
                    published=entry.get("published"),
                ))
        return items
