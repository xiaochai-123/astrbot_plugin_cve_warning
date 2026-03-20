from __future__ import annotations

import aiohttp
from typing import Any


class CisaKevClient:
    def __init__(self, session: aiohttp.ClientSession, feed_url: str, timeout_s: int):
        self.session = session
        self.feed_url = feed_url
        self.timeout_s = timeout_s

    async def fetch_catalog(self) -> dict[str, Any]:
        async with self.session.get(self.feed_url, timeout=self.timeout_s) as resp:
            resp.raise_for_status()
            data = await resp.json(content_type=None)
            if not isinstance(data, dict):
                raise ValueError("KEV feed 返回的 JSON 不是对象")
            return data

