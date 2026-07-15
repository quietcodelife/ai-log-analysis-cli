from __future__ import annotations

import argparse
import json
import os
import re
import sys
import threading
import time
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib import error, request

from . import i18n
from .i18n import tr
from .ui import Style, print_status, terminal_width

def load_env_file(path: Path | None = None) -> None:
    env_path = path or Path.cwd() / ".env"
    try:
        content = env_path.read_text(encoding="utf-8")
    except OSError:
        return
    for line in content.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, _, value = stripped.partition("=")
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value


load_env_file()

DEFAULT_CONFIG_PATH = Path.cwd() / "log-sources.json"
DEFAULT_MODEL = os.getenv("OPENAI_MODEL", "gpt-4.1-mini")
DEFAULT_MAX_BYTES = int(os.getenv("LOG_MAX_BYTES", "120000"))
DEFAULT_LANG = os.getenv("AI_LOG_LANG", "pl").strip().lower() or "pl"
OUTPUT_DIR = Path.cwd() / "analysis-output"
API_URL = "https://api.openai.com/v1/responses"
SYSLOG_RE = re.compile(r"^([A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})")
APACHE_RE = re.compile(r"\[([0-9]{2}/[A-Z][a-z]{2}/[0-9]{4}:[0-9]{2}:[0-9]{2}:[0-9]{2}\s[+-][0-9]{4})\]")
ISO_RE = re.compile(r"([0-9]{4}-[0-9]{2}-[0-9]{2}[T ][0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)?(?:Z|[+-][0-9]{2}:[0-9]{2})?)")
IP_RE = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")
HTTP_STATUS_RE = re.compile(r"\s([1-5][0-9]{2})\s")
REQUEST_RE = re.compile(r'"(?:[A-Z]+)\s+([^\s]+)')
HTTP_METHOD_RE = re.compile(r'"([A-Z]+)\s+')
AUTH_USER_RE = re.compile(r'(?:invalid user|Failed password for(?: invalid user)?|Accepted password for|session opened for user)\s+([A-Za-z0-9_.-]+)')


class TimeFilter:
    def __init__(self, label: str, start: datetime | None, end: datetime | None) -> None:
        self.label = label
        self.start = start
        self.end = end


class LogFilteringError(RuntimeError):
    pass


class SourceProfile:
    def __init__(self, category: str, focus_areas: list[str], indicators: list[str]) -> None:
        self.category = category
        self.focus_areas = focus_areas
        self.indicators = indicators


class Spinner:
    def __init__(self, message: str) -> None:
        self.message = message
        self.active = False
        self.thread: threading.Thread | None = None
        self.frames = ["[=     ]", "[==    ]", "[===   ]", "[ ==== ]", "[  === ]", "[   == ]", "[    = ]"]

    def start(self) -> None:
        if not sys.stdout.isatty():
            print_status("AI", self.message, Style.yellow)
            return
        self.active = True
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def _run(self) -> None:
        index = 0
        while self.active:
            frame = self.frames[index % len(self.frames)]
            line = f"\r{Style.yellow}{Style.bold}{frame}{Style.reset} {self.message}"
            sys.stdout.write(line)
            sys.stdout.flush()
            time.sleep(0.12)
            index += 1
        sys.stdout.write("\r" + " " * max(terminal_width(), len(self.message) + 20) + "\r")
        sys.stdout.flush()

    def stop(self, final_message: str | None = None) -> None:
        self.active = False
        if self.thread:
            self.thread.join()
        if final_message:
            print_status("AI", final_message, Style.green)


def localized_source_text(entry: dict[str, Any], field: str) -> str:
    lang = i18n.CURRENT_LANG
    localized = entry.get(f"{field}_{lang}")
    if isinstance(localized, str) and localized.strip():
        return localized.strip()

    base_value = entry.get(field)
    if isinstance(base_value, str) and base_value.strip():
        return base_value.strip()

    fallback_lang = "en" if lang == "pl" else "pl"
    fallback_value = entry.get(f"{field}_{fallback_lang}")
    if isinstance(fallback_value, str) and fallback_value.strip():
        return fallback_value.strip()

    if field == "description":
        return tr("no_data")
    return ""


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=tr("arg_desc"))
    parser.add_argument("-c", "--config", default=str(DEFAULT_CONFIG_PATH), help=tr("arg_config"))
    parser.add_argument("--source", help=tr("arg_source"))
    parser.add_argument("--time", help=tr("arg_time"))
    parser.add_argument("--time-start", help=tr("arg_time_start"))
    parser.add_argument("--time-end", help=tr("arg_time_end"))
    parser.add_argument("--lang", default=DEFAULT_LANG, help=tr("arg_lang"))
    return parser.parse_args()


def load_sources(config_path: Path) -> list[dict[str, Any]]:
    if not config_path.exists():
        raise RuntimeError(tr("config_missing", path=config_path))

    try:
        parsed = json.loads(config_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise RuntimeError(tr("config_invalid_json", error=exc)) from exc

    if not isinstance(parsed, list) or not parsed:
        raise RuntimeError(tr("config_invalid_array"))

    sources: list[dict[str, Any]] = []
    for index, entry in enumerate(parsed, start=1):
        if not isinstance(entry, dict) or not entry.get("path"):
            raise RuntimeError(tr("config_invalid_source", index=index))

        display_name = localized_source_text(entry, "name")
        if not display_name:
            raise RuntimeError(tr("config_invalid_source", index=index))

        sources.append(
            {
                "id": entry.get("id", index),
                "name": display_name,
                "name_pl": entry.get("name_pl") or entry.get("name"),
                "name_en": entry.get("name_en") or entry.get("name"),
                "path": entry["path"],
                "description": localized_source_text(entry, "description"),
                "description_pl": entry.get("description_pl") or entry.get("description"),
                "description_en": entry.get("description_en") or entry.get("description"),
            }
        )
    return sources


def inspect_log_status(file_path: str | Path) -> tuple[str, str, str]:
    path = Path(file_path)
    if not path.exists():
        return (tr("status_missing"), tr("status_missing_desc"), Style.red)
    if not os.access(path, os.R_OK):
        return (tr("status_no_access"), tr("status_no_access_desc"), Style.yellow)
    try:
        if path.stat().st_size == 0:
            return (tr("status_empty"), tr("status_empty_desc"), Style.yellow)
    except OSError:
        return (tr("status_unknown"), tr("status_unknown_desc"), Style.yellow)
    return (tr("status_ok"), tr("status_ok_desc"), Style.green)


def resolve_source(sources: list[dict[str, Any]], source_value: str) -> dict[str, Any]:
    normalized = source_value.strip().lower()
    for source in sources:
        if str(source["id"]).lower() == normalized:
            return source
    for source in sources:
        names = [
            str(source.get("name", "")).strip().lower(),
            str(source.get("name_pl", "")).strip().lower(),
            str(source.get("name_en", "")).strip().lower(),
        ]
        if normalized in names:
            return source
    raise RuntimeError(tr("source_not_found", value=source_value))


def parse_user_datetime(value: str, now: datetime) -> datetime:
    formats = ["%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M"]
    for fmt in formats:
        try:
            parsed = datetime.strptime(value, fmt)
            return parsed.replace(tzinfo=now.tzinfo)
        except ValueError:
            continue
    raise ValueError(tr("date_format_error"))


def build_cli_time_filter(args: argparse.Namespace) -> TimeFilter | None:
    now = datetime.now().astimezone()
    if args.time_start or args.time_end:
        if not (args.time_start and args.time_end):
            raise RuntimeError(tr("custom_range_requires_both"))
        start = parse_user_datetime(args.time_start, now)
        end = parse_user_datetime(args.time_end, now)
        if start > end:
            raise RuntimeError(tr("custom_range_invalid_order"))
        return TimeFilter(f"{args.time_start} -> {args.time_end}", start, end)
    if not args.time:
        return None
    mapping = {
        "none": TimeFilter(tr("time_option_none"), None, None),
        "1h": TimeFilter(tr("time_option_1h"), now - timedelta(hours=1), now),
        "24h": TimeFilter(tr("time_option_24h"), now - timedelta(hours=24), now),
        "7d": TimeFilter(tr("time_option_7d"), now - timedelta(days=7), now),
    }
    selected = mapping.get(args.time.strip().lower())
    if not selected:
        raise RuntimeError(tr("time_arg_invalid"))
    return selected


def parse_log_timestamp(line: str, now: datetime) -> datetime | None:
    iso_match = ISO_RE.search(line)
    if iso_match:
        value = iso_match.group(1).replace("Z", "+00:00")
        try:
            parsed = datetime.fromisoformat(value)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=now.tzinfo)
            return parsed.astimezone(now.tzinfo)
        except ValueError:
            pass

    apache_match = APACHE_RE.search(line)
    if apache_match:
        try:
            parsed = datetime.strptime(apache_match.group(1), "%d/%b/%Y:%H:%M:%S %z")
            return parsed.astimezone(now.tzinfo)
        except ValueError:
            pass

    syslog_match = SYSLOG_RE.search(line)
    if syslog_match:
        base = syslog_match.group(1)
        for year in (now.year, now.year - 1, now.year + 1):
            try:
                parsed = datetime.strptime(f"{year} {base}", "%Y %b %d %H:%M:%S")
                parsed = parsed.replace(tzinfo=now.tzinfo)
                if abs((parsed - now).days) <= 370:
                    return parsed
            except ValueError:
                continue
    return None


def apply_time_filter(content: str, time_filter: TimeFilter) -> tuple[str, int, int, int]:
    if time_filter.start is None and time_filter.end is None:
        lines = content.splitlines()
        return content, len(lines), len(lines), 0

    now = datetime.now().astimezone()
    kept_lines: list[str] = []
    total = 0
    matched = 0
    skipped_without_timestamp = 0
    for line in content.splitlines():
        total += 1
        timestamp = parse_log_timestamp(line, now)
        if timestamp is None:
            skipped_without_timestamp += 1
            continue
        if time_filter.start and timestamp < time_filter.start:
            continue
        if time_filter.end and timestamp > time_filter.end:
            continue
        kept_lines.append(line)
        matched += 1

    if matched == 0:
        raise LogFilteringError(tr("time_filter_no_matches"))
    return "\n".join(kept_lines), matched, total, skipped_without_timestamp


def prepare_log_snippet(content: str) -> str:
    encoded = content.encode("utf-8")
    if len(encoded) <= DEFAULT_MAX_BYTES:
        return content
    truncated = encoded[-DEFAULT_MAX_BYTES:].decode("utf-8", errors="ignore")
    return f"{tr('log_trimmed', size=DEFAULT_MAX_BYTES)}\n{truncated}"


def read_log_file(file_path: Path) -> str:
    try:
        content = file_path.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise RuntimeError(tr("log_missing", path=file_path)) from exc
    except PermissionError as exc:
        raise RuntimeError(tr("log_no_access", path=file_path)) from exc
    if not content.strip():
        raise RuntimeError(tr("log_empty"))
    return content


def detect_source_profile(source: dict[str, Any]) -> SourceProfile:
    signature = f"{source['name']} {source['path']} {source['description']}".lower()
    profiles = [
        (("auth", "secure", "ssh", "sudo"), SourceProfile(tr("source_profile_auth"), [tr("focus_auth_1"), tr("focus_auth_2"), tr("focus_auth_3"), tr("focus_auth_4")], ["failed password", "accepted password", "sudo", "invalid user", "pam_unix"])),
        (("nginx", "access.log"), SourceProfile(tr("source_profile_nginx_access"), [tr("focus_nginx_access_1"), tr("focus_nginx_access_2"), tr("focus_nginx_access_3"), tr("focus_nginx_access_4")], ["/wp-login", "/xmlrpc.php", " 500 ", " 404 ", "curl", "sqlmap"])),
        (("error.log", "nginx error"), SourceProfile(tr("source_profile_nginx_error"), [tr("focus_nginx_error_1"), tr("focus_nginx_error_2"), tr("focus_nginx_error_3"), tr("focus_nginx_error_4")], ["upstream", "connect() failed", "timed out", "ssl", "crit", "emerg"])),
        (("apache", "httpd"), SourceProfile(tr("source_profile_apache"), [tr("focus_apache_1"), tr("focus_apache_2"), tr("focus_apache_3"), tr("focus_apache_4")], ["AH", "client denied", "seg fault", " 500 ", " 403 "])),
        (("fail2ban",), SourceProfile(tr("source_profile_fail2ban"), [tr("focus_fail2ban_1"), tr("focus_fail2ban_2"), tr("focus_fail2ban_3")], ["ban", "unban", "found", "jail"])),
        (("kern", "kernel"), SourceProfile(tr("source_profile_kernel"), [tr("focus_kernel_1"), tr("focus_kernel_2"), tr("focus_kernel_3")], ["oom", "i/o error", "segfault", "panic", "call trace"])),
        (("syslog", "messages"), SourceProfile(tr("source_profile_system"), [tr("focus_system_1"), tr("focus_system_2"), tr("focus_system_3")], ["systemd", "cron", "dns", "error", "warning", "failed"])),
    ]
    for needles, profile in profiles:
        if any(needle in signature for needle in needles):
            return profile
    return SourceProfile(tr("source_profile_generic"), [tr("focus_generic_1"), tr("focus_generic_2"), tr("focus_generic_3")], ["error", "warning", "failed", "critical"])


def find_top_matches(lines: list[str], pattern: re.Pattern[str], limit: int = 5) -> list[str]:
    counter: Counter[str] = Counter()
    for line in lines:
        match = pattern.search(line)
        if match:
            counter[match.group(1)] += 1
    return [f"{value} ({count})" for value, count in counter.most_common(limit)]


def find_top_ips(lines: list[str], limit: int = 5) -> list[str]:
    counter: Counter[str] = Counter()
    for line in lines:
        for ip in IP_RE.findall(line):
            counter[ip] += 1
    return [f"{value} ({count})" for value, count in counter.most_common(limit)]


def find_top_users(lines: list[str], limit: int = 5) -> list[str]:
    counter: Counter[str] = Counter()
    for line in lines:
        match = AUTH_USER_RE.search(line)
        if match:
            counter[match.group(1)] += 1
    return [f"{value} ({count})" for value, count in counter.most_common(limit)]


def count_http_classes(lines: list[str]) -> tuple[int, int]:
    status_counter: Counter[str] = Counter()
    for line in lines:
        match = HTTP_STATUS_RE.search(line)
        if match:
            status_counter[match.group(1)] += 1
    four_xx = sum(count for status, count in status_counter.items() if status.startswith("4"))
    five_xx = sum(count for status, count in status_counter.items() if status.startswith("5"))
    return four_xx, five_xx


def count_keyword_signals(lines: list[str]) -> dict[str, int]:
    lowered = [line.lower() for line in lines]
    return {
        "timeout": sum("timeout" in line or "timed out" in line for line in lowered),
        "upstream": sum("upstream" in line for line in lowered),
        "denied": sum("denied" in line or "forbidden" in line for line in lowered),
        "restart": sum("restart" in line or "starting" in line or "stopped" in line for line in lowered),
    }


def detect_security_findings(lines: list[str]) -> list[str]:
    lowered = [line.lower() for line in lines]
    findings: list[str] = []
    failed_passwords = sum("failed password" in line for line in lowered)
    invalid_users = sum("invalid user" in line for line in lowered)
    accepted_passwords = sum("accepted password" in line for line in lowered)
    bans = sum((" ban " in f" {line} ") or ("banned" in line) for line in lowered)
    exploit_paths = sum(any(marker in line for marker in ["/wp-login", "/xmlrpc.php", "/boaform", "/.env", "phpmyadmin"]) for line in lowered)
    scanners = sum(any(marker in line for marker in ["sqlmap", "nmap", "nikto", "masscan"]) for line in lowered)
    if failed_passwords >= 5:
        findings.append(tr("finding_bruteforce", value=failed_passwords))
    if invalid_users >= 3:
        findings.append(tr("finding_invalid_users", value=invalid_users))
    if accepted_passwords and failed_passwords >= accepted_passwords * 3:
        findings.append(tr("finding_failed_vs_success"))
    if bans >= 3:
        findings.append(tr("finding_bans", value=bans))
    if exploit_paths >= 3:
        findings.append(tr("finding_exploit_paths", value=exploit_paths))
    if scanners >= 1:
        findings.append(tr("finding_scanners", value=scanners))
    return findings


def build_rule_based_findings(profile: SourceProfile, lines: list[str]) -> list[str]:
    findings: list[str] = []
    four_xx, five_xx = count_http_classes(lines)
    signals = count_keyword_signals(lines)
    top_users = find_top_users(lines)
    if top_users:
        findings.append(tr("finding_top_users", value=", ".join(top_users[:3])))
    if four_xx >= 10:
        findings.append(tr("finding_many_4xx", value=four_xx))
    if five_xx >= 5:
        findings.append(tr("finding_many_5xx", value=five_xx))
    if signals["timeout"] >= 3:
        findings.append(tr("finding_many_timeout", value=signals["timeout"]))
    if signals["upstream"] >= 3:
        findings.append(tr("finding_many_upstream", value=signals["upstream"]))
    if signals["denied"] >= 5:
        findings.append(tr("finding_many_denied", value=signals["denied"]))
    if signals["restart"] >= 5 and ("system" in profile.category.lower() or "systemowe" in profile.category.lower()):
        findings.append(tr("finding_many_restart", value=signals["restart"]))
    return findings


def build_log_summary(log_content: str, profile: SourceProfile) -> str:
    lines = [line for line in log_content.splitlines() if line.strip()]
    lowered = [line.lower() for line in lines]
    counts = {
        "error": sum("error" in line for line in lowered),
        "warning": sum("warning" in line or "warn" in line for line in lowered),
        "failed": sum("failed" in line or "failure" in line for line in lowered),
        "critical": sum("critical" in line or "crit" in line or "panic" in line for line in lowered),
    }
    indicator_hits = []
    for indicator in profile.indicators:
        hits = sum(indicator.lower() in line for line in lowered)
        if hits:
            indicator_hits.append(f"{indicator}: {hits}")
    top_ips = find_top_ips(lines)
    top_statuses = find_top_matches(lines, HTTP_STATUS_RE)
    top_paths = find_top_matches(lines, REQUEST_RE)
    top_methods = find_top_matches(lines, HTTP_METHOD_RE)
    top_users = find_top_users(lines)
    security_findings = detect_security_findings(lines)
    technical_findings = build_rule_based_findings(profile, lines)
    four_xx, five_xx = count_http_classes(lines)
    signals = count_keyword_signals(lines)
    summary_lines = [
        tr("summary_non_empty", value=len(lines)),
        tr("summary_profile", value=profile.category),
        tr("summary_error", value=counts["error"]),
        tr("summary_warning", value=counts["warning"]),
        tr("summary_failed", value=counts["failed"]),
        tr("summary_critical", value=counts["critical"]),
        tr("summary_4xx", value=four_xx),
        tr("summary_5xx", value=five_xx),
        tr("summary_timeout", value=signals["timeout"]),
        tr("summary_upstream", value=signals["upstream"]),
        tr("summary_top_ips", value=", ".join(top_ips) if top_ips else tr("summary_none")),
        tr("summary_top_statuses", value=", ".join(top_statuses) if top_statuses else tr("summary_none")),
        tr("summary_top_paths", value=", ".join(top_paths) if top_paths else tr("summary_none")),
        tr("summary_top_methods", value=", ".join(top_methods) if top_methods else tr("summary_none")),
        tr("summary_top_users", value=", ".join(top_users) if top_users else tr("summary_none")),
        tr("summary_special_patterns", value=", ".join(indicator_hits) if indicator_hits else tr("summary_no_special")),
        tr("summary_security", value="; ".join(security_findings) if security_findings else tr("summary_no_security")),
        tr("summary_rules", value="; ".join(technical_findings) if technical_findings else tr("summary_no_rules")),
    ]
    return "\n".join(summary_lines)


def collect_local_summary(source: dict[str, Any], log_content: str, time_filter: TimeFilter) -> dict[str, Any]:
    profile = detect_source_profile(source)
    stats_text = build_log_summary(log_content, profile)
    return {
        "profile": profile.category,
        "time_filter": time_filter.label,
        "stats_text": stats_text,
        "stats_lines": stats_text.splitlines(),
    }


def build_prompt(source: dict[str, Any], log_content: str, time_filter: TimeFilter) -> str:
    summary = collect_local_summary(source, log_content, time_filter)
    profile = detect_source_profile(source)
    focus = "\n".join(f"- {item}" for item in profile.focus_areas)
    return "\n".join(
        [
            tr("prompt_intro"),
            tr("prompt_instruction"),
            "",
            tr("prompt_structure"),
            tr("prompt_section_1"),
            tr("prompt_section_2"),
            tr("prompt_section_3"),
            tr("prompt_section_4"),
            tr("prompt_section_5"),
            tr("prompt_section_6"),
            "",
            tr("prompt_risk"),
            tr("prompt_urgency"),
            tr("prompt_time", value=time_filter.label),
            tr("prompt_profile", value=profile.category),
            tr("prompt_focus"),
            focus,
            "",
            tr("prompt_source_name", value=source["name"]),
            tr("prompt_path", value=source["path"]),
            tr("prompt_description", value=source["description"]),
            tr("prompt_time_filter", value=time_filter.label),
            "",
            tr("prompt_stats"),
            summary["stats_text"],
            "",
            tr("prompt_logs"),
            log_content,
        ]
    ).strip()


def extract_output_text(data: dict[str, Any]) -> str:
    direct = data.get("output_text")
    if isinstance(direct, str) and direct.strip():
        return direct.strip()

    parts: list[str] = []
    for item in data.get("output") or []:
        if not isinstance(item, dict) or item.get("type") != "message":
            continue
        for content in item.get("content") or []:
            if isinstance(content, dict) and content.get("type") == "output_text":
                text = content.get("text")
                if isinstance(text, str) and text:
                    parts.append(text)
    return "\n".join(parts).strip()


def analyze_with_openai(source: dict[str, Any], log_content: str, time_filter: TimeFilter) -> str:
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        raise RuntimeError(tr("missing_api_key"))

    payload = json.dumps({"model": DEFAULT_MODEL, "input": build_prompt(source, log_content, time_filter)}).encode("utf-8")
    req = request.Request(
        API_URL,
        data=payload,
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {api_key}"},
        method="POST",
    )
    spinner = Spinner(tr("analysis_running", model=DEFAULT_MODEL))
    spinner.start()
    try:
        with request.urlopen(req, timeout=120) as response:
            data = json.loads(response.read().decode("utf-8"))
    except error.HTTPError as exc:
        spinner.stop()
        details = exc.read().decode("utf-8", errors="ignore")
        raise RuntimeError(tr("api_error", code=exc.code, details=details)) from exc
    except error.URLError as exc:
        spinner.stop()
        raise RuntimeError(tr("api_connect_error", reason=exc.reason)) from exc
    else:
        spinner.stop(tr("analysis_done"))

    text = extract_output_text(data)
    if not text:
        raise RuntimeError(tr("api_empty_error"))
    return text


def slugify(value: str) -> str:
    cleaned = []
    last_dash = False
    for char in value.lower():
        if char.isalnum():
            cleaned.append(char)
            last_dash = False
        elif not last_dash:
            cleaned.append("-")
            last_dash = True
    slug = "".join(cleaned).strip("-")
    return slug[:50] or "report"


def save_report(source: dict[str, Any], report: str, time_filter: TimeFilter, summary: dict[str, Any]) -> tuple[Path, Path]:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    generated_at = datetime.now(timezone.utc).isoformat()
    timestamp = generated_at.replace(":", "-").replace(".", "-")
    base_name = f"{timestamp}-{slugify(source['name'])}"
    report_path = OUTPUT_DIR / f"{base_name}.md"
    json_path = OUTPUT_DIR / f"{base_name}.json"

    content = (
        f"# {tr('report_title')}\n\n"
        f"- {tr('report_source')}: {source['name']}\n"
        f"- {tr('path_label')}: {source['path']}\n"
        f"- {tr('time_filter_label')}: {time_filter.label}\n"
        f"- {tr('report_generated')}: {generated_at}\n\n"
        f"{report}\n"
    )
    report_path.write_text(content, encoding="utf-8")

    payload = {
        "generated_at": generated_at,
        "language": i18n.CURRENT_LANG,
        "source": {
            "id": source.get("id"),
            "name": source.get("name"),
            "path": source.get("path"),
            "description": source.get("description"),
        },
        "time_filter": {
            "label": time_filter.label,
            "start": time_filter.start.isoformat() if time_filter.start else None,
            "end": time_filter.end.isoformat() if time_filter.end else None,
        },
        "local_summary": {
            "profile": summary["profile"],
            "stats_lines": summary["stats_lines"],
            "stats_text": summary["stats_text"],
        },
        "ai_report": report,
    }
    json_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    return report_path, json_path
