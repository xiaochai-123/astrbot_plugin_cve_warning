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
            headers["apiKey"] = self.api_key

        async with self.session.get(
            self._base_url,
            params=params,
            headers=headers,
            timeout=self.timeout_s,
        ) as resp:
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

        first_v = vulns[0] if isinstance(vulns[0], dict) else {}
        cve_obj = first_v.get("cve", {}) if isinstance(first_v, dict) else {}
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
                    first_desc = descs[0]
                    if isinstance(first_desc, dict):
                        val = first_desc.get("value")
                        if isinstance(val, str) and val.strip():
                            cwe_list.append(val.strip())

        def _pick_metric(key: str) -> dict[str, Any] | None:
            raw = metrics.get(key)
            if isinstance(raw, list) and raw:
                first = raw[0]
                if isinstance(first, dict):
                    return first
            return None

        cvss_entry = (
            _pick_metric("cvssMetricV31")
            or _pick_metric("cvssMetricV30")
            or _pick_metric("cvssMetricV2")
        )

        cvss_base_score: float | None = None
        cvss_base_severity: str | None = None
        cvss_vector: str | None = None

        if isinstance(cvss_entry, dict):
            cvss_data = (
                cvss_entry.get("cvssData")
                if isinstance(cvss_entry.get("cvssData"), dict)
                else None
            )

            if isinstance(cvss_data, dict):
                base_score = cvss_data.get("baseScore")
                base_sev = cvss_data.get("baseSeverity") or cvss_entry.get("baseSeverity")
                vector = cvss_data.get("vectorString") or cvss_entry.get("vectorString")
            else:
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