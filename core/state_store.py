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
    - pushed_at_by_cve: 全局“该 CVE 已完成推送”（legacy；用于 push_only_new 逻辑）
    - seen_at_by_cve:   “该 CVE 已被扫描到/处理过”（severity 过滤时避免每轮都命中）
    - delivered_at_by_session: 按 session 粒度记录投递成功状态
      delivered_at_by_session[session][cve_id] = iso
    - cvss_cache: CVSS 缓存（减少 NVD 请求）
      cvss_cache[cve_id] = {"stored_at_iso": "...", "data": {...}}
    """

    def __init__(
        self,
        plugin_name: str,
        state_file_name: str = "state.json",
        state_max_entries: int = 5000,
        cvss_cache_ttl_days: int = 30,
        *,
        seen_max_entries: int = 20000,
        delivered_max_entries_per_session: int = 5000,
        cvss_cache_max_entries: int = 20000,
    ) -> None:
        self.plugin_name = plugin_name
        self.storage_dir = StarTools.get_data_dir(plugin_name)
        self.state_file_path = os.path.join(self.storage_dir, state_file_name)

        self.state_max_entries = max(100, int(state_max_entries))
        self.seen_max_entries = max(100, int(seen_max_entries))
        self.delivered_max_entries_per_session = max(100, int(delivered_max_entries_per_session))
        self.cvss_cache_max_entries = max(100, int(cvss_cache_max_entries))

        self.cvss_cache_ttl_days = max(1, int(cvss_cache_ttl_days))

        self._lock = asyncio.Lock()

        self.pushed_at_by_cve: dict[str, str] = {}
        self.seen_at_by_cve: dict[str, str] = {}
        self.delivered_at_by_session: dict[str, dict[str, str]] = {}
        self.cvss_cache: dict[str, dict[str, Any]] = {}

        self.last_catalog_version: str | None = None
        self.last_fetch_at_iso: str | None = None
        self.last_push_at_iso: str | None = None

        self._pushed_order: deque[str] = deque()
        self._seen_order: deque[str] = deque()
        self._delivered_order_by_session: dict[str, deque[str]] = {}
        self._cvss_order: deque[str] = deque()

    async def load(self) -> None:
        async with self._lock:
            try:
                os.makedirs(self.storage_dir, exist_ok=True)
                if not os.path.exists(self.state_file_path):
                    self._rebuild_orders()
                    return

                with open(self.state_file_path, encoding="utf-8") as f:
                    data = json.load(f)

                if not isinstance(data, dict):
                    self._rebuild_orders()
                    return

                pushed = data.get("pushed_at_by_cve", {})
                if isinstance(pushed, dict):
                    self.pushed_at_by_cve = {
                        str(k): str(v)
                        for k, v in pushed.items()
                        if isinstance(k, str) and isinstance(v, str)
                    }

                seen = data.get("seen_at_by_cve", {})
                if isinstance(seen, dict):
                    self.seen_at_by_cve = {
                        str(k): str(v)
                        for k, v in seen.items()
                        if isinstance(k, str) and isinstance(v, str)
                    }

                delivered = data.get("delivered_at_by_session", {})
                rebuilt_delivered: dict[str, dict[str, str]] = {}
                if isinstance(delivered, dict):
                    for sess, sess_map in delivered.items():
                        if not isinstance(sess, str) or not isinstance(sess_map, dict):
                            continue
                        rebuilt_delivered[sess] = {
                            str(cve): str(ts)
                            for cve, ts in sess_map.items()
                            if isinstance(cve, str) and isinstance(ts, str)
                        }
                self.delivered_at_by_session = rebuilt_delivered

                cache = data.get("cvss_cache", {})
                if isinstance(cache, dict):
                    rebuilt_cvss: dict[str, dict[str, Any]] = {}
                    for k, v in cache.items():
                        if not isinstance(k, str) or not isinstance(v, dict):
                            continue
                        if "data" in v and isinstance(v.get("data"), dict):
                            rebuilt_cvss[k] = v
                        else:
                            rebuilt_cvss[k] = {"stored_at_iso": None, "data": v}
                    self.cvss_cache = rebuilt_cvss

                self.last_catalog_version = data.get("last_catalog_version")
                self.last_fetch_at_iso = data.get("last_fetch_at_iso")
                self.last_push_at_iso = data.get("last_push_at_iso")

                self._rebuild_orders()
                self._prune_all_unsafe()
            except Exception as e:
                logger.error(f"[CVE漏洞推送] 状态加载失败，将使用空状态: {e}")
                self._rebuild_orders()

    def _rebuild_orders(self) -> None:
        pushed_items = list(self.pushed_at_by_cve.items())
        pushed_items.sort(key=lambda kv: kv[1])
        self._pushed_order = deque([cve for cve, _ in pushed_items])

        seen_items = list(self.seen_at_by_cve.items())
        seen_items.sort(key=lambda kv: kv[1])
        self._seen_order = deque([cve for cve, _ in seen_items])

        self._delivered_order_by_session = {}
        for sess, m in self.delivered_at_by_session.items():
            if not isinstance(m, dict):
                continue
            items = list(m.items())
            items.sort(key=lambda kv: kv[1])
            self._delivered_order_by_session[sess] = deque([cve for cve, _ in items])

        cvss_items: list[tuple[str, str]] = []
        for cve_id, v in self.cvss_cache.items():
            if not isinstance(v, dict):
                continue
            stored_at = v.get("stored_at_iso")
            cvss_items.append((cve_id, stored_at if isinstance(stored_at, str) else ""))
        cvss_items.sort(key=lambda kv: kv[1])
        self._cvss_order = deque([cve for cve, _ in cvss_items])

    async def save(self) -> None:
        async with self._lock:
            try:
                os.makedirs(self.storage_dir, exist_ok=True)
                payload = {
                    "pushed_at_by_cve": self.pushed_at_by_cve,
                    "seen_at_by_cve": self.seen_at_by_cve,
                    "delivered_at_by_session": self.delivered_at_by_session,
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
        self._touch_order(self._pushed_order, cve_id)
        self._prune_dict_by_order(self.pushed_at_by_cve, self._pushed_order, self.state_max_entries)

    def is_cve_seen(self, cve_id: str) -> bool:
        return cve_id in self.seen_at_by_cve

    async def mark_cve_seen(self, cve_id: str) -> None:
        now_iso = datetime.now(timezone.utc).isoformat()
        self.seen_at_by_cve[cve_id] = now_iso
        self._touch_order(self._seen_order, cve_id)
        self._prune_dict_by_order(self.seen_at_by_cve, self._seen_order, self.seen_max_entries)

    def is_cve_delivered(self, session: str, cve_id: str) -> bool:
        m = self.delivered_at_by_session.get(session)
        return bool(isinstance(m, dict) and cve_id in m)

    async def mark_cve_delivered(self, session: str, cve_id: str) -> None:
        now_iso = datetime.now(timezone.utc).isoformat()
        if session not in self.delivered_at_by_session or not isinstance(
            self.delivered_at_by_session.get(session), dict
        ):
            self.delivered_at_by_session[session] = {}
        self.delivered_at_by_session[session][cve_id] = now_iso

        order = self._delivered_order_by_session.get(session)
        if order is None:
            order = deque()
            self._delivered_order_by_session[session] = order

        self._touch_order(order, cve_id)
        self._prune_dict_by_order(
            self.delivered_at_by_session[session],
            order,
            self.delivered_max_entries_per_session,
        )

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
                    self._delete_cvss_entry(cve_id)
                    return None
            except Exception:
                self._delete_cvss_entry(cve_id)
                return None

        return data

    async def set_cvss_cached(self, cve_id: str, cvss_info: dict[str, Any]) -> None:
        now_iso = datetime.now(timezone.utc).isoformat()
        self.cvss_cache[cve_id] = {"stored_at_iso": now_iso, "data": cvss_info}
        self._touch_order(self._cvss_order, cve_id)
        self._prune_dict_by_order(self.cvss_cache, self._cvss_order, self.cvss_cache_max_entries)

    def _delete_cvss_entry(self, cve_id: str) -> None:
        self.cvss_cache.pop(cve_id, None)
        try:
            self._cvss_order.remove(cve_id)
        except ValueError:
            pass

    def set_last_catalog_version(self, version: str | None) -> None:
        self.last_catalog_version = version

    def set_last_fetch_at(self, when_iso: str) -> None:
        self.last_fetch_at_iso = when_iso

    def set_last_push_at(self, when_iso: str) -> None:
        self.last_push_at_iso = when_iso

    @staticmethod
    def _touch_order(order: deque[str], key: str) -> None:
        if key in order:
            try:
                order.remove(key)
            except ValueError:
                pass
        order.append(key)

    @staticmethod
    def _prune_dict_by_order(d: dict[str, Any], order: deque[str], max_entries: int) -> None:
        while len(order) > max_entries:
            old = order.popleft()
            d.pop(old, None)

    def _prune_all_unsafe(self) -> None:
        self._prune_dict_by_order(self.pushed_at_by_cve, self._pushed_order, self.state_max_entries)
        self._prune_dict_by_order(self.seen_at_by_cve, self._seen_order, self.seen_max_entries)
        self._prune_dict_by_order(self.cvss_cache, self._cvss_order, self.cvss_cache_max_entries)

        for sess, m in list(self.delivered_at_by_session.items()):
            if not isinstance(m, dict):
                self.delivered_at_by_session.pop(sess, None)
                self._delivered_order_by_session.pop(sess, None)
                continue

            order = self._delivered_order_by_session.get(sess)
            if order is None:
                items = list(m.items())
                items.sort(key=lambda kv: kv[1])
                order = deque([cve for cve, _ in items])
                self._delivered_order_by_session[sess] = order

            self._prune_dict_by_order(m, order, self.delivered_max_entries_per_session)