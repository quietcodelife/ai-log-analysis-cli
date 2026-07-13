from __future__ import annotations

from datetime import datetime, timedelta
from pathlib import Path

from . import i18n
from .analysis import (
    DEFAULT_MAX_BYTES,
    DEFAULT_MODEL,
    LogFilteringError,
    OUTPUT_DIR,
    TimeFilter,
    analyze_with_openai,
    apply_time_filter,
    build_cli_time_filter,
    collect_local_summary,
    inspect_log_status,
    load_sources,
    parse_args,
    parse_user_datetime,
    prepare_log_snippet,
    read_log_file,
    resolve_source,
    save_report,
)
from .i18n import set_language, tr
from .ui import (
    Style,
    build_report_panels,
    print_error,
    print_header,
    print_status,
    render_local_summary,
    render_menu,
    render_selection_panel,
    render_session_panel,
    render_time_filter_menu,
    style,
)


def choose_source(sources: list[dict[str, object]]) -> dict[str, object] | None:
    valid = {str(source["id"]): source for source in sources}
    while True:
        answer = input(style("\n" + tr("choose_source_prompt"), Style.bold, Style.white)).strip()
        if answer.lower() in {"q", "quit", "exit"}:
            return None
        source = valid.get(answer)
        if source:
            return source
        print_status("INFO", tr("invalid_choice"), Style.yellow)



def prompt_custom_time_filter(now: datetime) -> TimeFilter:
    print_status("TIME", tr("custom_time_format"), Style.blue)
    while True:
        start_raw = input(style(tr("from_prompt"), Style.bold, Style.white)).strip()
        end_raw = input(style(tr("to_prompt"), Style.bold, Style.white)).strip()
        try:
            start = parse_user_datetime(start_raw, now)
            end = parse_user_datetime(end_raw, now)
        except ValueError as exc:
            print_status("INFO", tr("invalid_date", error=exc), Style.yellow)
            continue
        if start > end:
            print_status("INFO", tr("invalid_date_order"), Style.yellow)
            continue
        return TimeFilter(f"{start_raw} -> {end_raw}", start, end)



def choose_time_filter() -> TimeFilter:
    now = datetime.now().astimezone()
    render_time_filter_menu()
    while True:
        answer = input(style("\n" + tr("choose_time_prompt"), Style.bold, Style.white)).strip()
        if answer == "1":
            return TimeFilter(tr("time_option_none"), None, None)
        if answer == "2":
            return TimeFilter(tr("time_option_1h"), now - timedelta(hours=1), now)
        if answer == "3":
            return TimeFilter(tr("time_option_24h"), now - timedelta(hours=24), now)
        if answer == "4":
            return TimeFilter(tr("time_option_7d"), now - timedelta(days=7), now)
        if answer == "5":
            return prompt_custom_time_filter(now)
        print_status("INFO", tr("invalid_time_choice"), Style.yellow)



def main() -> int:
    args = parse_args()
    try:
        set_language(args.lang)
        print_header()
        sources = load_sources(Path(args.config))
        print_status("CFG", tr("config_load", config=args.config), Style.green)
        render_session_panel(args.config, sources, DEFAULT_MODEL, DEFAULT_MAX_BYTES, str(OUTPUT_DIR))
        selected_source_cli = resolve_source(sources, args.source) if args.source else None
        time_filter_cli = build_cli_time_filter(args)

        while True:
            if selected_source_cli is None:
                render_menu(sources, inspect_log_status)
                selected_source = choose_source(sources)
                if selected_source is None:
                    print_status("STOP", tr("menu_exit"), Style.yellow)
                    return 0
            else:
                selected_source = selected_source_cli

            time_filter = time_filter_cli or choose_time_filter()
            render_selection_panel(selected_source, time_filter.label)
            print_status("READ", tr("read_log", path=selected_source["path"]), Style.blue)
            try:
                raw_log_content = read_log_file(Path(selected_source["path"]))
            except RuntimeError as exc:
                if selected_source_cli is not None:
                    raise
                print_status("WARN", str(exc), Style.yellow)
                print_status("INFO", tr("back_to_menu"), Style.blue)
                print()
                continue

            try:
                filtered_content, matched_lines, total_lines, skipped_without_timestamp = apply_time_filter(
                    raw_log_content,
                    time_filter,
                )
            except LogFilteringError as exc:
                if selected_source_cli is not None or time_filter_cli is not None:
                    raise
                print_status("WARN", str(exc), Style.yellow)
                print_status("INFO", tr("back_to_menu_time"), Style.blue)
                print()
                continue

            log_content = prepare_log_snippet(filtered_content)
            print_status(
                "TIME",
                tr(
                    "time_filter_kept",
                    matched=matched_lines,
                    total=total_lines,
                    skipped=skipped_without_timestamp,
                ),
                Style.magenta,
            )
            print_status("META", tr("snippet_size", size=len(log_content.encode("utf-8"))), Style.magenta)
            local_summary = collect_local_summary(selected_source, log_content, time_filter)
            render_local_summary(local_summary)
            report = analyze_with_openai(selected_source, log_content, time_filter)
            report_path, json_path = save_report(selected_source, report, time_filter, local_summary)
            print()
            for panel in build_report_panels(report, i18n.CURRENT_LANG):
                print(panel)
                print()
            print_status("SAVE", tr("report_saved", path=report_path), Style.green)
            print_status("JSON", tr("json_saved", path=json_path), Style.green)
            return 0
    except (KeyboardInterrupt, EOFError):
        print()
        print_status("STOP", tr("stopped"), Style.yellow)
        return 130
    except RuntimeError as exc:
        print()
        print_error(str(exc))
        return 1
