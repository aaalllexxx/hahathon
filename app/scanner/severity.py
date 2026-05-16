SEVERITY_ORDER = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}


def normalize_severity(severity: str | None) -> str:
    normalized = (severity or "LOW").upper()
    return normalized if normalized in SEVERITY_ORDER else "LOW"


def highest_severity(severities: list[str]) -> str:
    if not severities:
        return "LOW"
    return max((normalize_severity(item) for item in severities), key=lambda item: SEVERITY_ORDER[item])


def build_summary(findings: list[object]) -> dict[str, int]:
    summary = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for finding in findings:
        severity = normalize_severity(getattr(finding, "severity", "LOW")).lower()
        summary[severity] += 1
    return summary


def should_block(
    findings: list[object],
    *,
    block_on_critical: bool = True,
    block_on_high: bool = True,
    block_on_warning: bool = False,
) -> bool:
    for finding in findings:
        severity = normalize_severity(getattr(finding, "severity", "LOW"))
        exploitable = bool(getattr(finding, "exploitable", True))
        if severity == "CRITICAL" and block_on_critical:
            return True
        if severity == "HIGH" and exploitable and block_on_high:
            return True
        if block_on_warning and severity in {"MEDIUM", "LOW"}:
            return True
    return False

