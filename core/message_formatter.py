from __future__ import annotations

from typing import Any


def _truncate(text: str, max_len: int) -> str:
    if not isinstance(text, str):
        return ""
    text = text.strip()
    if len(text) <= max_len:
        return text
    # 留一点余量给省略号
    return text[: max(0, max_len - 1)] + "..."


def _severity_bucket(base_severity: str | None, base_score: float | None) -> str:
    if isinstance(base_severity, str) and base_severity.strip():
        s = base_severity.strip().upper()
        if s in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}:
            return s
    if isinstance(base_score, (int, float)):
        score = float(base_score)
        if score >= 9.0:
            return "CRITICAL"
        if score >= 7.0:
            return "HIGH"
        if score >= 4.0:
            return "MEDIUM"
    return "UNKNOWN"


def get_severity_bucket(
    base_severity: str | None,
    base_score: float | None,
) -> str:
    """对外暴露：将 CVSS baseSeverity/baseScore 映射到严重等级桶。"""
    return _severity_bucket(base_severity, base_score)


def build_cve_message(
    kev_entry: dict[str, Any],
    cvss_info: dict[str, Any],
    *,
    short_description_max_len: int = 220,
    include_cwe: bool = True,
    critical_high_detailed: bool = True,
    display_timezone: str = "UTC+8",
) -> str:
    cve_id = str(kev_entry.get("cveID") or "").strip()
    if not cve_id:
        raise ValueError("KEV entry 缺少 cveID")

    short_desc = str(kev_entry.get("shortDescription") or "").strip()
    vendor = str(kev_entry.get("vendorProject") or "").strip()
    product = str(kev_entry.get("product") or "").strip()
    vuln_name = str(kev_entry.get("vulnerabilityName") or "").strip()

    required_action = str(kev_entry.get("requiredAction") or "").strip()
    due_date = str(kev_entry.get("dueDate") or "").strip()
    date_added = str(kev_entry.get("dateAdded") or "").strip()
    known_ransom = str(kev_entry.get("knownRansomwareCampaignUse") or "").strip()

    base_score = cvss_info.get("cvss_base_score")
    base_sev = cvss_info.get("cvss_base_severity")
    vector = cvss_info.get("cvss_vector")
    cwe_list = cvss_info.get("cwe") or []

    bucket = _severity_bucket(base_sev, base_score)
    detailed = critical_high_detailed and bucket in {"CRITICAL", "HIGH"}

    # 简洁/详细两套模板
    description = _truncate(short_desc if short_desc else vuln_name, short_description_max_len)
    required_action = _truncate(required_action, short_description_max_len)
    nvd_link = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
    kev_link = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"

    sev_line = f"严重等级：{bucket}"
    if isinstance(base_score, (int, float)):
        sev_line += f"（CVSS {float(base_score):.1f}）"

    header = f"🛡️ [CISA KEV] CVE 漏洞推送\nCVE：{cve_id}"

    # 已知勒索使用信息（可选）
    ransom_line = ""
    if known_ransom:
        # schema 里为 'Known'/'Unknown'（或其它）
        ransom_line = f"\n🍷 勒索已知利用：{known_ransom}"

    # 详细字段
    vendor_line = ""
    if vendor or product:
        vendor_line = f"\n🏢 影响范围：{vendor}{' / ' if vendor and product else ''}{product}".strip()

    due_line = ""
    if due_date:
        due_line = f"\n⏰ 处置到期：{due_date}"
    added_line = ""
    if date_added:
        added_line = f"\n📌 加入日期：{date_added}"

    required_line = ""
    if detailed and required_action:
        required_line = f"\n📝 CISA 建议操作：{required_action}"

    vector_line = ""
    if detailed and vector:
        vector_line = f"\n🧾 CVSS 向量：{vector}"

    cwe_line = ""
    if detailed and include_cwe and isinstance(cwe_list, list) and cwe_list:
        cwe_line = f"\n🧩 CWE：{', '.join([str(x).strip() for x in cwe_list if str(x).strip()])}"

    # 内容：简略 or 详细
    if detailed:
        return "\n".join(
            [
                header,
                sev_line,
                f"📝 描述：{description}",
                vendor_line,
                required_line,
                due_line,
                added_line,
                vector_line,
                cwe_line,
                ransom_line,
                f"\n🔗 NVD：{nvd_link}",
                f"🔗 KEV：{kev_link}",
            ]
        ).replace("\n\n\n", "\n\n")

    # 简略模板
    return "\n".join(
        [
            header,
            sev_line,
            f"📝 描述：{description}",
            due_line,
            ransom_line,
            f"\n🔗 NVD：{nvd_link}",
        ]
    ).replace("\n\n\n", "\n\n")

