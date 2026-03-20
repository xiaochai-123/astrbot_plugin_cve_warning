from __future__ import annotations

from typing import Any

import aiohttp


class NvdClient:
    def __init__(
        self,
        session: aiohttp.ClientSession,
        api_key: str = "",
        timeout_s: int = 12,
        user_agent: str = "astrbot-cve-warning",
    ) -> None:
        self.session = session
        self.api_key = api_key or ""
        self.timeout_s = timeout_s
        self.user_agent = user_agent

        self._base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    async def get_cvss(self, cve_id: str) -> dict[str, Any]:
        """
        返回结构示例：
        {
          "cvss_base_score": float|None,
          "cvss_base_severity": "CRITICAL"|"HIGH"|"MEDIUM"|"LOW"|None,
          "cvss_vector": str|None,
          "cwe": ["CWE-79", ...]
        }
        """
        params = {
            "cveId": cve_id,
            "resultsPerPage": "1",
        }
        headers: dict[str, str] = {"User-Agent": self.user_agent}
        if self.api_key:
            # NVD API 2.0 使用请求头 apiKey 字段
            headers["apiKey"] = self.api_key

        async with self.session.get(
            self._base_url,
            params=params,
            headers=headers,
            timeout=self.timeout_s,
        ) as resp:
            # 429/5xx 直接抛出，交给上层兜底
            resp.raise_for_status()
            data = await resp.json(content_type=None)

        vulns = data.get("vulnerabilities") if isinstance(data, dict) else None
        if not vulns or not isinstance(vulns, list):
            return {
                "cvss_base_score": None,
                "cvss_base_severity": None,
                "cvss_vector": None,
                "cwe": [],
            }

        cve_obj = vulns[0].get("cve", {}) if isinstance(vulns[0], dict) else {}
        metrics = cve_obj.get("metrics", {}) if isinstance(cve_obj, dict) else {}

        # CWE
        cwe_list: list[str] = []
        weaknesses = cve_obj.get("weaknesses", []) if isinstance(cve_obj, dict) else []
        if isinstance(weaknesses, list):
            for w in weaknesses:
                if not isinstance(w, dict):
                    continue
                descs = w.get("description", [])
                if isinstance(descs, list) and descs:
                    # 常见结构：{ "cweId": "...", "description":[{"lang":"en","value":"CWE-79"}] }
                    # 兜底：取 value
                    first = descs[0]
                    if isinstance(first, dict):
                        val = first.get("value")
                        if isinstance(val, str) and val.strip():
                            cwe_list.append(val.strip())

        # CVSS v3.1 > v3.0 > v2.0
        def _pick_cvss(cvss_metrics_key: str) -> dict[str, Any] | None:
            raw = metrics.get(cvss_metrics_key)
            if isinstance(raw, list) and raw:
                first = raw[0]
                if isinstance(first, dict):
                    return first
            return None

        cvss_entry = (
            _pick_cvss("cvssMetricV31")
            or _pick_cvss("cvssMetricV30")
            or _pick_cvss("cvssMetricV2")
        )

        cvss_base_score = None
        cvss_base_severity = None
        cvss_vector = None

        if isinstance(cvss_entry, dict):
            # v3/v2 的字段名略有差异：baseScore/baseSeverity/vectorString
            base_score = cvss_entry.get("baseScore")
            base_sev = cvss_entry.get("baseSeverity")
            vector = cvss_entry.get("vectorString")

            if isinstance(base_score, (int, float)):
                cvss_base_score = float(base_score)
            if isinstance(base_sev, str) and base_sev.strip():
                cvss_base_severity = base_sev.strip()
            if isinstance(vector, str) and vector.strip():
                cvss_vector = vector.strip()

        return {
            "cvss_base_score": cvss_base_score,
            "cvss_base_severity": cvss_base_severity,
            "cvss_vector": cvss_vector,
            "cwe": cwe_list,
        }

