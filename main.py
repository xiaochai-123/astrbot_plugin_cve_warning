import asyncio

from astrbot.api import AstrBotConfig, logger
from astrbot.api.event import AstrMessageEvent, filter
from astrbot.api.star import Context, Star

from .core.cve_warning_service import CVEWarningService


class CVEWarningPlugin(Star):
    """CVE 漏洞（CISA KEV）定时推送插件"""

    def __init__(self, context: Context, config: AstrBotConfig) -> None:
        super().__init__(context)
        self.context = context
        self.config: AstrBotConfig = config

        self.service: CVEWarningService | None = None
        self._service_task: asyncio.Task[None] | None = None

    async def initialize(self) -> None:
        logger.info("[CVE漏洞推送] 正在初始化...")
        if not self.config.get("enabled", True):
            logger.info("[CVE漏洞推送] 插件已禁用，跳过初始化")
            return

        self.service = CVEWarningService(config=dict(self.config), context=self.context)
        self._service_task = asyncio.create_task(
            self.service.start(), name="cve_warning_service_task"
        )
        self._service_task.add_done_callback(self._on_service_task_done)
        logger.info("[CVE漏洞推送] 初始化完成，服务已启动")

    def _on_service_task_done(self, task: asyncio.Task[None]) -> None:
        try:
            exc = task.exception()
        except asyncio.CancelledError:
            return
        except Exception as e:
            logger.error(f"[CVE漏洞推送] 后台任务状态获取失败: {e}")
            return

        if exc is not None:
            logger.error(f"[CVE漏洞推送] 后台服务异常退出: {exc!r}")
            self.service = None
            self._service_task = None

    async def terminate(self) -> None:
        logger.info("[CVE漏洞推送] 正在停止服务...")
        try:
            if self.service:
                await self.service.stop()

            if self._service_task and not self._service_task.done():
                self._service_task.cancel()
                try:
                    await self._service_task
                except asyncio.CancelledError:
                    pass
        except Exception as e:
            logger.error(f"[CVE漏洞推送] 停止时出错: {e}")

    @filter.command("CVE漏洞推送")
    async def cve_help(self, event: AstrMessageEvent):
        help_text = """🛡️ CVE漏洞推送（CISA KEV）使用说明

📋 可用命令：
• /CVE漏洞推送 - 显示本帮助
• /CVE漏洞推送状态 - 查看服务运行状态（管理员）
• /CVE漏洞推送手动刷新 - 立即拉取并推送新增 CVE（管理员）

配置项请在插件 WebUI 中修改。"""
        yield event.plain_result(help_text)

    @filter.command("CVE漏洞推送状态")
    async def cve_status(self, event: AstrMessageEvent):
        if not await self.is_plugin_admin(event):
            yield event.plain_result("🚫 权限不足：此命令仅限管理员使用。")
            return

        if not self.service:
            yield event.plain_result("❌ 服务未启动（或已异常退出）")
            return

        try:
            st = self.service.get_status()
            lines = [
                "📊 CVE漏洞推送状态",
                f"🟢 running: {st.get('running')}",
                f"🧾 last_catalog_version: {st.get('last_catalog_version')}",
                f"⏰ last_fetch_at_iso: {st.get('last_fetch_at_iso')}",
                f"📣 last_push_at_iso: {st.get('last_push_at_iso')}",
                f"⏭️ next_run_at: {st.get('next_run_at')}",
                f"🔢 pushed_count: {st.get('pushed_count')}",
                f"ℹ️ enable_low_medium: {self.config.get('enable_low_medium', False)}",
                f"ℹ️ push_interval_hours: {self.config.get('push_interval_hours', 6)}",
            ]
            yield event.plain_result("\n".join(lines))
        except Exception as e:
            logger.error(f"[CVE漏洞推送] 获取状态失败: {e}")
            yield event.plain_result(f"❌ 获取状态失败: {e}")

    @filter.command("CVE漏洞推送手动刷新")
    async def cve_manual_refresh(self, event: AstrMessageEvent):
        if not await self.is_plugin_admin(event):
            yield event.plain_result("🚫 权限不足：此命令仅限管理员使用。")
            return

        if not self.service:
            yield event.plain_result("❌ 服务未启动（或已异常退出）")
            return

        try:
            res = await self.service.refresh_and_push(reason="manual")
            if getattr(res, "ok", True) is False:
                err = getattr(res, "error", None) or "unknown_error"
                yield event.plain_result(f"❌ 手动刷新失败：{err}")
                return

            yield event.plain_result(
                "✅ 手动刷新完成："
                f"pushed={getattr(res, 'pushed', 0)} "
                f"processed={getattr(res, 'processed', 0)} "
                f"skipped_by_severity={getattr(res, 'skipped_by_severity', 0)} "
                f"skipped_already_pushed={getattr(res, 'skipped_already_pushed', 0)} "
                f"skipped_already_delivered={getattr(res, 'skipped_already_delivered', 0)}"
            )
        except Exception as e:
            logger.error(f"[CVE漏洞推送] 手动刷新失败: {e}")
            yield event.plain_result(f"❌ 手动刷新失败: {e}")

    async def is_plugin_admin(self, event: AstrMessageEvent) -> bool:
        if event.is_admin():
            return True

        sender_id = event.get_sender_id()
        sender_id_str = str(sender_id).strip() if sender_id is not None else ""

        raw_admins = self.config.get("admin_users", []) or []
        if not isinstance(raw_admins, list):
            return False
        plugin_admins = [str(x).strip() for x in raw_admins if str(x).strip()]
        return sender_id_str in plugin_admins


@filter.on_astrbot_loaded()
async def _on_loaded():
    logger.debug("[CVE漏洞推送] AstrBot 已加载完成（插件将按生命周期启动服务）。")