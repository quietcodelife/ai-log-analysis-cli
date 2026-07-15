from __future__ import annotations

import os
import re
import sys
import unicodedata
from shutil import get_terminal_size

from .i18n import tr

ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


class Style:
    enabled = sys.stdout.isatty() and os.getenv("TERM") not in {None, "dumb"} and not os.getenv("NO_COLOR")
    reset = "\033[0m" if enabled else ""
    bold = "\033[1m" if enabled else ""
    dim = "\033[2m" if enabled else ""
    cyan = "\033[36m" if enabled else ""
    blue = "\033[34m" if enabled else ""
    green = "\033[32m" if enabled else ""
    yellow = "\033[33m" if enabled else ""
    red = "\033[31m" if enabled else ""
    magenta = "\033[35m" if enabled else ""
    white = "\033[37m" if enabled else ""


def style(text: str, *effects: str) -> str:
    prefix = "".join(effects)
    return f"{prefix}{text}{Style.reset}" if prefix else text


def strip_ansi(text: str) -> str:
    return ANSI_RE.sub("", text)


def visible_len(text: str) -> int:
    return len(strip_ansi(text))


def pad_visible(text: str, width: int) -> str:
    padding = max(0, width - visible_len(text))
    return text + (" " * padding)


def wrap_visible(text: str, width: int) -> list[str]:
    if width <= 0:
        return [text]

    plain = strip_ansi(text)
    if not plain:
        return [""]

    lines: list[str] = []
    remaining = plain
    while remaining:
        if len(remaining) <= width:
            lines.append(remaining)
            break

        chunk = remaining[:width]
        split_at = chunk.rfind(" ")
        if split_at > 0:
            lines.append(remaining[:split_at])
            remaining = remaining[split_at + 1 :]
        else:
            lines.append(chunk)
            remaining = remaining[width:]

    return lines or [""]


def terminal_width() -> int:
    return max(72, min(get_terminal_size(fallback=(100, 30)).columns, 120))


def box_lines(lines: list[str], title: str | None = None, color: str = "") -> str:
    width = terminal_width()
    inner = width - 4
    top = "+" + "-" * (width - 2) + "+"
    bottom = top
    result = [style(top, color)]

    if title:
        title_text = f"[ {title} ]"
        result.append(style(f"| {pad_visible(title_text, inner)} |", color, Style.bold))
        result.append(style(f"| {'-' * inner} |", color))

    for line in lines:
        clean = line.rstrip()
        if not strip_ansi(clean):
            result.append(style(f"| {'':{inner}} |", color))
            continue

        wrapped = wrap_visible(clean, inner)
        for chunk in wrapped:
            result.append(style(f"| {pad_visible(chunk, inner)} |", color))

    result.append(style(bottom, color))
    return "\n".join(result)


def print_header() -> None:
    width = terminal_width()
    lines = [
        "",
        style("AI LOG ANALYSIS CLI".center(width - 4), Style.bold, Style.white),
        "",
        style(tr("app_subtitle").center(width - 4), Style.dim),
        "",
    ]
    print(box_lines(lines, color=Style.cyan))


def print_status(label: str, message: str, color: str = Style.blue) -> None:
    print(f"{style('[%s]' % label, Style.bold, color)} {message}")


def print_error(message: str) -> None:
    print(f"{style('[%s]' % tr('error_prefix'), Style.bold, Style.red)} {message}", file=sys.stderr)


def render_session_panel(config_path: str, sources: list[dict[str, object]], model: str, max_bytes: int, output_dir: str) -> None:
    config_name = os.path.basename(config_path)
    lines = [
        f"{tr('config_label')} : {config_name}",
        f"{tr('sources_count_label')}: {len(sources)}",
        f"{tr('model_label')}     : {model}",
        f"{tr('limit_label')}   : {max_bytes} bytes",
        f"{tr('reports_label')}      : {output_dir}",
    ]
    print()
    print(box_lines(lines, title=tr("sessions_title"), color=Style.magenta))


def render_menu(sources: list[dict[str, object]], inspect_log_status) -> None:
    lines: list[str] = []
    for source in sources:
        state_label, state_desc, state_color = inspect_log_status(source["path"])
        lines.append(style(f"{source['id']:>2}. {source['name']}", Style.bold, Style.white))
        lines.append(f"    {tr('path_label')}: {source['path']}")
        lines.append(f"    {tr('status_label')}:  {style(state_label, Style.bold, state_color)} - {state_desc}")
        lines.append(f"    {tr('description_label')}:    {source['description']}")
        lines.append("")
    if lines and not lines[-1]:
        lines.pop()
    print()
    print(box_lines(lines, title=tr("sources_title"), color=Style.blue))


def render_time_filter_menu() -> None:
    print()
    print(
        box_lines(
            [
                f"1. {tr('time_option_none')}",
                f"2. {tr('time_option_1h')}",
                f"3. {tr('time_option_24h')}",
                f"4. {tr('time_option_7d')}",
                f"5. {tr('time_option_custom')}",
            ],
            title=tr("time_filter_title"),
            color=Style.magenta,
        )
    )


def render_selection_panel(selected_source: dict[str, object], time_filter_label: str) -> None:
    print()
    print(
        box_lines(
            [
                f"{tr('selected_source_label')}: {selected_source['name']}",
                f"{tr('path_label')}: {selected_source['path']}",
                f"{tr('description_label')}: {selected_source['description']}",
                f"{tr('time_filter_label')}: {time_filter_label}",
            ],
            title=tr("selection_title"),
            color=Style.cyan,
        )
    )


def render_local_summary(summary: dict[str, object]) -> None:
    lines = [
        f"{tr('profile_label')}: {summary['profile']}",
        f"{tr('time_filter_label')}: {summary['time_filter']}",
        "",
        *summary["stats_lines"],
    ]
    print()
    print(box_lines(lines, title=tr("local_summary_title"), color=Style.magenta))


def normalize_for_match(text: str) -> str:
    decomposed = unicodedata.normalize("NFKD", text.lower())
    return "".join(char for char in decomposed if not unicodedata.combining(char))


def classify_risk(line: str) -> tuple[str, str] | None:
    lower = normalize_for_match(line)
    if any(token in lower for token in ["wysok", "krytycz", "high", "critical"]):
        return (tr("risk_high"), Style.red)
    if any(token in lower for token in ["sredni", "umiark", "medium", "moderate"]):
        return (tr("risk_medium"), Style.yellow)
    if any(token in lower for token in ["niski", "niskie", "low"]):
        return (tr("risk_low"), Style.green)
    return None


def classify_urgency(line: str) -> tuple[str, str] | None:
    lower = normalize_for_match(line)
    if any(token in lower for token in ["natychmiast", "krytycz", "pilne", "urgent", "critical", "immediate"]):
        return (tr("urgency_high"), Style.red)
    if any(token in lower for token in ["monitor", "observe"]):
        return (tr("urgency_monitor"), Style.yellow)
    if any(token in lower for token in ["brak", "nie", "none", "no immediate"]):
        return (tr("urgency_none"), Style.green)
    return None


def build_report_panels(report: str, current_lang: str) -> list[str]:
    sections: list[tuple[str, list[str]]] = []
    current_title = tr("report_title")
    current_lines: list[str] = []
    for raw_line in report.splitlines():
        line = raw_line.strip()
        if not line:
            if current_lines and current_lines[-1] != "":
                current_lines.append("")
            continue
        if re.fullmatch(r"[-*_]{3,}", line):
            continue
        line = line.replace("**", "")
        heading = re.sub(r"^#{1,6}\s*", "", line)
        if re.match(r"^\d+\.\s", heading):
            if current_lines:
                sections.append((current_title, current_lines))
            current_title = re.sub(r"^\d+\.\s*", "", heading)
            current_lines = []
            continue
        if line.startswith(("- ", "* ")):
            current_lines.append(f"-> {line[2:]}")
        else:
            current_lines.append(line)
    if current_lines:
        sections.append((current_title, current_lines))
    if not sections:
        sections = [(tr("report_title"), [report])]

    rendered: list[str] = []
    for title, lines in sections:
        color = Style.green
        upper_title = title.upper()
        if any(token in title.lower() for token in ["ryzyka", "risk"]):
            risk = classify_risk(" ".join(lines))
            if risk:
                upper_title = f"{upper_title} [{risk[0]}]"
                color = risk[1]
        if any(token in title.lower() for token in ["natychmiastowa reakcja", "immediate reaction"]):
            urgency = classify_urgency(" ".join(lines))
            if urgency:
                upper_title = f"{upper_title} [{urgency[0]}]"
                color = urgency[1]
        fallback = tr("no_data") if current_lang == "pl" else "No data"
        rendered.append(box_lines(lines or [fallback], title=upper_title, color=color))
    return rendered
