from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
from typing import Any

import aiohttp
import astrbot.api.message_components as Comp
from astrbot.api import logger
from astrbot.api.event import MessageChain

from .cisa_kev_client import CisaKevClient
from .message_formatter import build_cve_message, get_severity_bucket
from .nvd_client import NvdClient
from .state_store import JsonStateStore


@dataclass
class RefreshResult:
    ok: bool = True
    error: str | None = None

    pushed: int = 0  # 本轮“全局完成推送”的数量（所有 session 都成功）
    processed: int = 0
    total_candidates: int = 0

    skipped_already_pushed: int = 0
    skipped_by_severity: int = 0
    skipped_already_delivered: int = 0

    last_catalog_version: str | None = None


class CVEWarningService:
    def __init__(self, config: dict[str, Any], context) -> None:
        self.config = config
        self.context = context

        self.plugin_name = "astrbot_plugin_cve_warning"

        self.kev_feed_url = str(config.get("kev_feed_url") or "").strip()
        self.interval_hours = int(config.get("push_interval_hours", 6))
        self.interval_seconds = max(60, self.interval_hours * 3600)
        self.max_push_per_run = int(config.get("max_push_per_run", 30))

        self.display_timezone = str(config.get("display_timezone") or "UTC+8")
        self.enable_low_medium = bool(config.get("enable_low_medium", False))

        self.nvd_api_key = str(config.get("nvd_api_key") or "")
        self.nvd_timeout_seconds = int(config.get("nvd_timeout_seconds", 12))

        fmt_cfg = config.get("message_format", {}) if isinstance(config.get("message_format"), dict) else {}
        self.critical_high_detailed = bool(fmt_cfg.get("critical_high_detailed", True))
        self.short_description_max_len = int(fmt_cfg.get("short_description_max_len", 220))
        self.include_cwe = bool(fmt_cfg.get("include_cwe", True))

        dedup_cfg = config.get("dedup", {}) if isinstance(config.get("dedup"), dict) else {}
        self.push_only_new = bool(dedup_cfg.get("push_only_new", True))
        self.state_max_entries = int(dedup_cfg.get("state_max_entries", 5000))

        # 新增：state 里其他集合的容量（不写 schema 也能工作，直接取默认）
        self.seen_max_entries = int(dedup_cfg.get("seen_max_entries", 20000)) if isinstance(dedup_cfg, dict) else 20000
        self.delivered_max_entries_per_session = (
            int(dedup_cfg.get("delivered_max_entries_per_session", self.state_max_entries))
            if isinstance(dedup_cfg, dict)
            else self.state_max_entries
        )
        self.cvss_cache_max_entries = (
            int(dedup_cfg.get("cvss_cache_max_entries", 20000)) if isinstance(dedup_cfg, dict) else 20000
        )

        self.kev_fetch_retry_count = int(config.get("kev_fetch_retry_count", 3))
        self.kev_fetch_retry_interval_seconds = int(config.get("kev_fetch_retry_interval_seconds", 10))

        self.failure_notify_sessions = self._normalize_sessions(config.get("failure_notify_sessions", []))
        self.cvss_cache_ttl_days = int(config.get("cvss_cache_ttl_days", 30))

        self.target_sessions: list[str] = []

        self._state = JsonStateStore(
            plugin_name=self.plugin_name,
            state_file_name="state.json",
            state_max_entries=self.state_max_entries,
            cvss_cache_ttl_days=self.cvss_cache_ttl_days,
            seen_max_entries=self.seen_max_entries,
            delivered_max_entries_per_session=self.delivered_max_entries_per_session,
            cvss_cache_max_entries=self.cvss_cache_max_entries,
        )

        self._session: aiohttp.ClientSession | None = None
        self._kev_client: CisaKevClient | None = None
        self._nvd_client: NvdClient | None = None

        self._running = False
        self._loop_task: asyncio.Task[None] | None = None
        self._refresh_lock = asyncio.Lock()

        self._next_run_at: datetime | None = None
        self._last_refresh_at: datetime | None = None

    async def start(self) -> None:
        if not self.kev_feed_url:
            logger.error("[CVE漏洞推送] 未配置 kev_feed_url")
            return

        self.target_sessions = self._normalize_sessions(self.config.get("target_sessions", []))
        if not self.target_sessions:
            logger.warning("[CVE漏洞推送] 当前未配置 target_sessions，将只更新状态不推送消息。")

        self._session = aiohttp.ClientSession()
        self._kev_client = CisaKevClient(self._session, feed_url=self.kev_feed_url, timeout_s=30)
        self._nvd_client = NvdClient(
            self._session,
            api_key=self.nvd_api_key,
            timeout_s=self.nvd_timeout_seconds,
        )

        await self._state.load()

        self._running = True
        # 启动时立即执行一次（启动失败会记录并通知）
        await self.refresh_and_push(reason="startup")

        # 定时循环
        self._loop_task = asyncio.create_task(self._run_loop(), name="cve_keV_scheduler")
        await self._loop_task

    async def _run_loop(self) -> None:
        while self._running:
            self._next_run_at = datetime.now(timezone.utc) + timedelta(seconds=self.interval_seconds)
            try:
                await asyncio.sleep(self.interval_seconds)
                await self.refresh_and_push(reason="scheduled")
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"[CVE漏洞推送] 定时刷新失败: {e}")

    async def stop(self) -> None:
        self._running = False
        if self._loop_task and not self._loop_task.done():
            self._loop_task.cancel()
            try:
                await self._loop_task
            except asyncio.CancelledError:
                pass

        if self._session:
            try:
                await self._session.close()
            except Exception:
                pass

    def get_status(self) -> dict[str, Any]:
        return {
            "running": self._running,
            "last_catalog_version": self._state.last_catalog_version,
            "last_fetch_at_iso": self._state.last_fetch_at_iso,
            "last_push_at_iso": self._state.last_push_at_iso,
            "last_refresh_at": self._last_refresh_at.isoformat() if self._last_refresh_at else None,
            "next_run_at": self._next_run_at.isoformat() if self._next_run_at else None,
            "pushed_count": len(self._state.pushed_at_by_cve),
        }

    async def refresh_and_push(self, reason: str) -> RefreshResult:
        """
        重要语义：
        - 发生“拉取失败/关键异常”时：返回 ok=False 且（对于 manual/startup）会抛异常，保证上层提示可信。
        - severity 过滤：只 mark_seen，不 mark_pushed（避免开启低中危后无法补发）。
        - 投递去重：按 session 记录 delivered；失败的 session 下次仍会补发；成功的 session 不会重复轰炸。
        - 只有当所有目标 session 都 delivered 成功时，才 mark_cve_pushed（全局完成）。
        """
        if not self._kev_client or not self._nvd_client:
            return RefreshResult(ok=False, error="service_not_ready")

        async with self._refresh_lock:
            self._last_refresh_at = datetime.now(timezone.utc)
            result = RefreshResult()

            def _should_raise() -> bool:
                # 手动刷新/启动时，强制让错误可见；定时任务不抛，避免把 loop 打死
                return reason in {"startup", "manual"}

            try:
                catalog = None
                last_fetch_err: Exception | None = None
                for attempt in range(1, max(1, self.kev_fetch_retry_count) + 1):
                    try:
                        catalog = await self._kev_client.fetch_catalog()
                        break
                    except Exception as fetch_e:
                        last_fetch_err = fetch_e
                        logger.warning(
                            f"[CVE漏洞推送] KEV 拉取失败（第 {attempt}/{self.kev_fetch_retry_count} 次）: {fetch_e}"
                        )
                        if attempt < self.kev_fetch_retry_count:
                            await asyncio.sleep(self.kev_fetch_retry_interval_seconds)

                if catalog is None:
                    raise RuntimeError(f"KEV 拉取失败: {last_fetch_err}")

                catalog_version = catalog.get("catalogVersion") if isinstance(catalog, dict) else None
                entries = []
                vulns = catalog.get("vulnerabilities") if isinstance(catalog, dict) else None
                if isinstance(vulns, list):
                    entries = [v for v in vulns if isinstance(v, dict)]

                result.last_catalog_version = catalog_version if isinstance(catalog_version, str) else None
                result.total_candidates = len(entries)

                self._state.set_last_catalog_version(result.last_catalog_version)
                self._state.set_last_fetch_at(datetime.now(timezone.utc).isoformat())

                if not entries:
                    await self._state.save()
                    return result

                # 先筛“候选”：push_only_new 时，跳过已全局 pushed 的（legacy 语义）
                candidates: list[dict[str, Any]] = []
                skipped = 0
                for e in entries:
                    cve_id = str(e.get("cveID") or "").strip()
                    if not cve_id:
                        continue
                    if self.push_only_new and self._state.is_cve_pushed(cve_id):
                        skipped += 1
                        continue
                    candidates.append(e)
                result.skipped_already_pushed = skipped

                # 限流：最多处理 N 个候选
                candidates = candidates[: self.max_push_per_run]

                for entry in candidates:
                    cve_id = str(entry.get("cveID") or "").strip()
                    if not cve_id:
                        continue

                    # 注意：如果所有 session 都已 delivered，就可以直接算“已处理”
                    if self.target_sessions:
                        all_delivered = all(self._state.is_cve_delivered(s, cve_id) for s in self.target_sessions)
                        if all_delivered:
                            result.skipped_already_delivered += 1
                            result.processed += 1
                            # 同步一下全局 pushed（用于 push_only_new 的快速跳过）
                            if not self._state.is_cve_pushed(cve_id):
                                await self._state.mark_cve_pushed(cve_id)
                            continue

                    # CVSS cache
                    cvss_info = self._state.get_cvss_cached(cve_id)
                    if not cvss_info:
                        try:
                            cvss_info = await self._nvd_client.get_cvss(cve_id)
                        except Exception as nvd_e:
                            logger.warning(f"[CVE漏洞推送] NVD 查询失败 {cve_id}: {nvd_e}")
                            cvss_info = {
                                "cvss_base_score": None,
                                "cvss_base_severity": None,
                                "cvss_vector": None,
                                "cwe": [],
                            }
                        await self._state.set_cvss_cached(cve_id, cvss_info)

                    bucket = get_severity_bucket(
                        cvss_info.get("cvss_base_severity"),
                        cvss_info.get("cvss_base_score"),
                    )

                    # 严重等级过滤（默认只推 Critical/High）
                    if (not self.enable_low_medium) and bucket in {"MEDIUM", "LOW", "UNKNOWN"}:
                        result.skipped_by_severity += 1
                        result.processed += 1
                        # 只标记“已见过”，不标记 pushed（避免后续打开低中危无法补发）
                        await self._state.mark_cve_seen(cve_id)
                        continue

                    msg_text = build_cve_message(
                        entry,
                        cvss_info,
                        short_description_max_len=self.short_description_max_len,
                        include_cwe=self.include_cwe,
                        critical_high_detailed=self.critical_high_detailed,
                        display_timezone=self.display_timezone,
                    )

                    # 目标会话推送：按 session 粒度去重与补发
                    ok_any = False
                    ok_all = True

                    for session in self.target_sessions:
                        # 已成功投递过的 session 不重复发
                        if self._state.is_cve_delivered(session, cve_id):
                            continue

                        try:
                            msg_chain = MessageChain([Comp.Plain(msg_text)])
                            await self.context.send_message(session, msg_chain)
                            ok_any = True
                            await self._state.mark_cve_delivered(session, cve_id)
                        except Exception as send_e:
                            ok_all = False
                            logger.warning(f"[CVE漏洞推送] 推送失败 session={session} cve={cve_id}: {send_e}")

                    result.processed += 1

                    # 没有 target_sessions 也算处理过（仅更新状态）
                    if not self.target_sessions:
                        ok_any = True
                        ok_all = True

                    # 只有当“所有目标会话”都投递成功时才算全局 pushed
                    if ok_any and ok_all:
                        if not self._state.is_cve_pushed(cve_id):
                            await self._state.mark_cve_pushed(cve_id)
                        result.pushed += 1
                        self._state.set_last_push_at(datetime.now(timezone.utc).isoformat())
                    else:
                        # 至少标记 seen，避免下次每次都重新走一遍重逻辑（但不影响补发失败会话）
                        await self._state.mark_cve_seen(cve_id)

                await self._state.save()
                return result

            except Exception as e:
                result.ok = False
                result.error = str(e)
                logger.error(f"[CVE漏洞推送] refresh_and_push 失败: {e}")

                # 失败不保存 pushed 状态，避免误去重（但本次 run 内可能写了 delivered/seen；这里不保存即可回滚到上次持久化）
                if self.failure_notify_sessions and reason in {"startup", "manual"}:
                    try:
                        fail_text = f"❌ [CVE漏洞推送] 初始化/手动刷新失败：{e}"
                        for session in self.failure_notify_sessions:
                            msg_chain = MessageChain([Comp.Plain(fail_text)])
                            await self.context.send_message(session, msg_chain)
                    except Exception:
                        pass

                if _should_raise():
                    raise
                return result

    @staticmethod
    def _normalize_sessions(value: Any) -> list[str]:
        if not isinstance(value, list):
            return []
        result: list[str] = []
        for v in value:
            if isinstance(v, str) and v.strip():
                result.append(v.strip())
        return result