from __future__ import annotations

import asyncio
from typing import Any

import aiohttp


class CisaKevClient:
    def __init__(self, session: aiohttp.ClientSession, feed_url: str, timeout_s: int):
        self.session = session
        self.feed_url = feed_url
        self.timeout_s = int(timeout_s)

    async def fetch_catalog(self) -> dict[str, Any]:
        try:
            timeout = aiohttp.ClientTimeout(total=self.timeout_s)
            headers = {"User-Agent": "astrbot-cve-warning"}

            async with self.session.get(
                self.feed_url,
                timeout=timeout,
                headers=headers,
            ) as resp:
                resp.raise_for_status()
                data = await resp.json(content_type=None)

            if not isinstance(data, dict):
                raise ValueError("KEV feed 返回的 JSON 不是对象")
            return data

        except asyncio.TimeoutError as e:
            raise RuntimeError(f"KEV 请求超时（{self.timeout_s}s）: {e!r}") from e
        except aiohttp.ClientResponseError as e:
            raise RuntimeError(f"KEV HTTP 错误: {e.status} {e.message}") from e
        except aiohttp.ClientError as e:
            raise RuntimeError(f"KEV 网络错误: {type(e).__name__} {e!r}") from e