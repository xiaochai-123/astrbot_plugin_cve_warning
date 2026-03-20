import asyncio
import json
import os
from collections import deque
from datetime import datetime, timezone
from typing import Any

from astrbot.api import logger
from astrbot.api.star import StarTools


class JsonStateStore:
    """
    轻量状态存储：
    - 记录已推送过的 CVE ID（去重）
    - 记录已查询过的 CVSS 信息（减少 NVD 请求）
    """

    def __init__(
        self,
        plugin_name: str,
        state_file_name: str = "state.json",
        state_max_entries: int = 5000,
        cvss_cache_ttl_days: int = 30,
    ) -> None:
        self.plugin_name = plugin_name
        self.storage_dir = StarTools.get_data_dir(plugin_name)
        self.state_file_path = os.path.join(self.storage_dir, state_file_name)
        self.state_max_entries = max(100, int(state_max_entries))

        self._lock = asyncio.Lock()

        # in-memory
        self.pushed_at_by_cve: dict[str, str] = {}
        # cvss_cache[cve_id] = {"stored_at_iso": "...", "data": {...}}
        # 兼容旧版本：如果 value 本身是 dict，则直接按 dict 视为 data（不做过期判断）
        self.cvss_cache: dict[str, dict[str, Any]] = {}
        self.last_catalog_version: str | None = None
        self.last_fetch_at_iso: str | None = None
        self.last_push_at_iso: str | None = None

        # keep insertion order for pruning
        self._pushed_order: deque[str] = deque()
        self.cvss_cache_ttl_days = max(1, int(cvss_cache_ttl_days))

    async def load(self) -> None:
        async with self._lock:
            try:
                os.makedirs(self.storage_dir, exist_ok=True)
                if not os.path.exists(self.state_file_path):
                    self._rebuild_order()
                    return

                with open(self.state_file_path, encoding="utf-8") as f:
                    data = json.load(f)

                if isinstance(data, dict):
                    pushed = data.get("pushed_at_by_cve", {})
                    if isinstance(pushed, dict):
                        self.pushed_at_by_cve = {
                            str(k): str(v)
                            for k, v in pushed.items()
                            if isinstance(k, str) and isinstance(v, str)
                        }

                    cache = data.get("cvss_cache", {})
                    if isinstance(cache, dict):
                        # 兼容历史格式：如果 v 直接是 dict 数据，则视为 data
                        rebuilt: dict[str, dict[str, Any]] = {}
                        for k, v in cache.items():
                            if not isinstance(k, str) or not isinstance(v, dict):
                                continue
                            if "data" in v and isinstance(v.get("data"), dict):
                                rebuilt[k] = v
                            else:
                                rebuilt[k] = {"stored_at_iso": None, "data": v}
                        self.cvss_cache = rebuilt

                    self.last_catalog_version = data.get("last_catalog_version")
                    self.last_fetch_at_iso = data.get("last_fetch_at_iso")
                    self.last_push_at_iso = data.get("last_push_at_iso")

                self._rebuild_order()
            except Exception as e:
                logger.error(f"[CVE漏洞推送] 状态加载失败，将使用空状态: {e}")

    def _rebuild_order(self) -> None:
        # order based on pushed_at_by_cve insertion isn't guaranteed after JSON,
        # but sufficient for pruning via "unknown order": keep sorted by timestamp string.
        items = list(self.pushed_at_by_cve.items())
        items.sort(key=lambda kv: kv[1])
        self._pushed_order = deque([cve for cve, _ in items])

    async def save(self) -> None:
        async with self._lock:
            try:
                os.makedirs(self.storage_dir, exist_ok=True)
                payload = {
                    "pushed_at_by_cve": self.pushed_at_by_cve,
                    "cvss_cache": self.cvss_cache,
                    "last_catalog_version": self.last_catalog_version,
                    "last_fetch_at_iso": self.last_fetch_at_iso,
                    "last_push_at_iso": self.last_push_at_iso,
                }
                tmp_path = self.state_file_path + ".tmp"
                with open(tmp_path, "w", encoding="utf-8") as f:
                    json.dump(payload, f, ensure_ascii=False, indent=2)
                os.replace(tmp_path, self.state_file_path)
            except Exception as e:
                logger.error(f"[CVE漏洞推送] 状态保存失败: {e}")

    def is_cve_pushed(self, cve_id: str) -> bool:
        return cve_id in self.pushed_at_by_cve

    async def mark_cve_pushed(self, cve_id: str) -> None:
        now_iso = datetime.now(timezone.utc).isoformat()
        self.pushed_at_by_cve[cve_id] = now_iso

        # update order
        if cve_id in self._pushed_order:
            # deque removal is O(n), but this is rare and bounded by max entries
            try:
                self._pushed_order.remove(cve_id)
            except ValueError:
                pass
        self._pushed_order.append(cve_id)

        # prune by max entries
        while len(self._pushed_order) > self.state_max_entries:
            old = self._pushed_order.popleft()
            self.pushed_at_by_cve.pop(old, None)

    def get_cvss_cached(self, cve_id: str) -> dict[str, Any] | None:
        val = self.cvss_cache.get(cve_id)
        if not isinstance(val, dict):
            return None

        data = val.get("data")
        if not isinstance(data, dict):
            return None

        stored_at_iso = val.get("stored_at_iso")
        if isinstance(stored_at_iso, str) and stored_at_iso.strip():
            try:
                stored_dt = datetime.fromisoformat(stored_at_iso)
                if stored_dt.tzinfo is None:
                    stored_dt = stored_dt.replace(tzinfo=timezone.utc)
                age_days = (datetime.now(timezone.utc) - stored_dt).days
                if age_days >= self.cvss_cache_ttl_days:
                    # expired
                    self.cvss_cache.pop(cve_id, None)
                    return None
            except Exception:
                # 如果时间解析失败，保留数据（避免因为状态损坏导致大量重试）
                return data

        return data

    async def set_cvss_cached(self, cve_id: str, cvss_info: dict[str, Any]) -> None:
        now_iso = datetime.now(timezone.utc).isoformat()
        self.cvss_cache[cve_id] = {"stored_at_iso": now_iso, "data": cvss_info}

    def set_last_catalog_version(self, version: str | None) -> None:
        self.last_catalog_version = version

    def set_last_fetch_at(self, when_iso: str) -> None:
        self.last_fetch_at_iso = when_iso

    def set_last_push_at(self, when_iso: str) -> None:
        self.last_push_at_iso = when_iso

