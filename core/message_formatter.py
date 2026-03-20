from __future__ import annotations

from datetime import datetime, timedelta, timezone
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


def _parse_tz(display_timezone: str) -> timezone | None:
    """
    支持：
    - "UTC"
    - "UTC+8" / "UTC+08:00" / "UTC-5" 等
    解析失败返回 None（则保持原字符串）
    """
    if not isinstance(display_timezone, str):
        return None
    s = display_timezone.strip().upper()
    if not s:
        return None
    if s == "UTC":
        return timezone.utc
    if not s.startswith("UTC"):
        return None

    tail = s[3:].strip()
    if not tail:
        return timezone.utc

    sign = 1
    if tail[0] == "+":
        sign = 1
        tail = tail[1:]
    elif tail[0] == "-":
        sign = -1
        tail = tail[1:]
    else:
        return None

    tail = tail.strip()
    if not tail:
        return None

    # "8" or "08:00"
    try:
        if ":" in tail:
            hh_str, mm_str = tail.split(":", 1)
            hh = int(hh_str)
            mm = int(mm_str)
        else:
            hh = int(tail)
            mm = 0
        offset = sign * (hh * 60 + mm)
        return timezone(timedelta(minutes=offset))
    except Exception:
        return None


def _format_kev_date(date_str: str, tz: timezone | None) -> str:
    """
    KEV 里 dateAdded/dueDate 通常是 YYYY-MM-DD（无时分秒）。
    将其当作 UTC 的 00:00:00，再转换为 tz 显示（仅显示日期）。
    解析失败返回原始字符串。
    """
    if not isinstance(date_str, str) or not date_str.strip():
        return ""
    raw = date_str.strip()
    if tz is None:
        return raw
    try:
        # treat as UTC date at midnight
        dt_utc = datetime.strptime(raw, "%Y-%m-%d").replace(tzinfo=timezone.utc)
        dt_local = dt_utc.astimezone(tz)
        return dt_local.strftime("%Y-%m-%d")
    except Exception:
        return raw


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

    tz = _parse_tz(display_timezone)
    due_date_fmt = _format_kev_date(due_date, tz) if due_date else ""
    date_added_fmt = _format_kev_date(date_added, tz) if date_added else ""

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
        ransom_line = f"\n🍷 勒索已知利用：{known_ransom}"

    # 详细字段
    vendor_line = ""
    if vendor or product:
        vendor_line = f"\n🏢 影响范围：{vendor}{' / ' if vendor and product else ''}{product}".strip()

    due_line = ""
    if due_date_fmt:
        due_line = f"\n⏰ 处置到期：{due_date_fmt}"
    added_line = ""
    if date_added_fmt:
        added_line = f"\n📌 加入日期：{date_added_fmt}"

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