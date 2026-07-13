#!/usr/bin/env python3
"""CLI do analizy logow serwerowych przy pomocy OpenAI."""

from __future__ import annotations

import argparse
import json
from collections import Counter
import os
import re
import sys
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from shutil import get_terminal_size
from typing import Any
from urllib import error, request

DEFAULT_CONFIG_PATH = Path.cwd() / "log-sources.json"
DEFAULT_MODEL = os.getenv("OPENAI_MODEL", "gpt-4.1-mini")
DEFAULT_MAX_BYTES = int(os.getenv("LOG_MAX_BYTES", "120000"))
DEFAULT_LANG = os.getenv("AI_LOG_LANG", "pl").strip().lower() or "pl"
OUTPUT_DIR = Path.cwd() / "analysis-output"
API_URL = "https://api.openai.com/v1/responses"
ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
SYSLOG_RE = re.compile(r"^([A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})")
APACHE_RE = re.compile(r"\[([0-9]{2}/[A-Z][a-z]{2}/[0-9]{4}:[0-9]{2}:[0-9]{2}:[0-9]{2}\s[+-][0-9]{4})\]")
ISO_RE = re.compile(r"([0-9]{4}-[0-9]{2}-[0-9]{2}[T ][0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)?(?:Z|[+-][0-9]{2}:[0-9]{2})?)")
IP_RE = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")
HTTP_STATUS_RE = re.compile(r"\s([1-5][0-9]{2})\s")
REQUEST_RE = re.compile(r'"(?:[A-Z]+)\s+([^\s]+)')
HTTP_METHOD_RE = re.compile(r'"([A-Z]+)\s+')
AUTH_USER_RE = re.compile(r'(?:invalid user|Failed password for(?: invalid user)?|Accepted password for|session opened for user)\s+([A-Za-z0-9_.-]+)')
CURRENT_LANG = DEFAULT_LANG if DEFAULT_LANG in {"pl", "en"} else "pl"

TRANSLATIONS = {
    "pl": {
        "app_subtitle": "Analiza logow serwerowych Linux z czytelnym raportem dla administratora",
        "error_prefix": "BLAD",
        "status_missing": "BRAK",
        "status_no_access": "BRAK DOSTEPU",
        "status_empty": "PUSTY",
        "status_unknown": "NIEZNANY",
        "status_ok": "OK",
        "status_missing_desc": "Plik nie istnieje",
        "status_no_access_desc": "Brak uprawnien do odczytu",
        "status_empty_desc": "Plik istnieje, ale jest pusty",
        "status_unknown_desc": "Nie udalo sie odczytac metadanych",
        "status_ok_desc": "Gotowy do analizy",
        "sessions_title": "Sesja",
        "sources_title": "Dostepne logi",
        "selection_title": "Wybor",
        "time_filter_title": "Filtr czasu",
        "local_summary_title": "Szybka analiza techniczna",
        "config_label": "Konfiguracja",
        "sources_count_label": "Liczba zrodel",
        "model_label": "Model AI",
        "limit_label": "Limit logu",
        "reports_label": "Raporty",
        "path_label": "Sciezka",
        "status_label": "Status",
        "description_label": "Opis",
        "selected_source_label": "Wybrane zrodlo",
        "time_filter_label": "Filtr czasu",
        "profile_label": "Profil logu",
        "choose_source_prompt": "Wybierz numer logu do analizy lub q aby wyjsc: ",
        "choose_time_prompt": "Wybierz filtr czasu [1-5]: ",
        "time_option_none": "Bez filtra czasu",
        "time_option_1h": "Ostatnia 1 godzina",
        "time_option_24h": "Ostatnie 24 godziny",
        "time_option_7d": "Ostatnie 7 dni",
        "time_option_custom": "Wlasny zakres od-do",
        "custom_time_format": "Format daty: YYYY-MM-DD HH:MM albo YYYY-MM-DD HH:MM:SS",
        "from_prompt": "Od kiedy: ",
        "to_prompt": "Do kiedy: ",
        "invalid_choice": "Niepoprawny wybor. Sprobuj ponownie.",
        "invalid_time_choice": "Niepoprawny wybor filtra. Sprobuj ponownie.",
        "invalid_date": "Niepoprawna data: {error}",
        "invalid_date_order": "Data poczatkowa nie moze byc pozniejsza od koncowej.",
        "date_format_error": "uzyj formatu YYYY-MM-DD HH:MM albo YYYY-MM-DD HH:MM:SS",
        "config_load": "Zaladowano konfiguracje: {config}",
        "menu_exit": "Zakonczono prace programu z menu wyboru.",
        "read_log": "Wczytywanie logu z {path}",
        "back_to_menu": "Wrocilem do listy logow. Mozesz wybrac inne zrodlo.",
        "back_to_menu_time": "Wrocilem do listy logow. Zmien filtr czasu albo wybierz inne zrodlo.",
        "time_filter_kept": "Filtr czasu zachowal {matched} z {total} linii, pominieto bez daty: {skipped}",
        "snippet_size": "Rozmiar przekazanego wycinka: {size} bajtow",
        "analysis_running": "Analiza AI w toku modelem {model}",
        "analysis_done": "Analiza AI zakonczona",
        "report_saved": "Raport zapisano do pliku: {path}",
        "json_saved": "Eksport JSON zapisano do pliku: {path}",
        "stopped": "Przerwano przez uzytkownika lub brak interaktywnego wejscia.",
        "missing_api_key": "Brak zmiennej srodowiskowej OPENAI_API_KEY.",
        "api_error": "Blad API OpenAI ({code}): {details}",
        "api_connect_error": "Nie mozna polaczyc sie z API OpenAI: {reason}",
        "api_empty_error": "API OpenAI nie zwrocilo tresci raportu.",
        "config_missing": "Nie znaleziono pliku konfiguracji: {path}. Skopiuj log-sources.example.json do log-sources.json i uzupelnij sciezki.",
        "config_invalid_json": "Niepoprawny JSON w pliku konfiguracji: {error}",
        "config_invalid_array": "Plik konfiguracyjny musi zawierac niepusta tablice zrodel logow.",
        "config_invalid_source": "Nieprawidlowe zrodlo logow na pozycji {index}.",
        "source_not_found": "Nie znaleziono zrodla logu dla parametru --source: {value}",
        "custom_range_requires_both": "Dla wlasnego zakresu czasu podaj jednoczesnie --time-start i --time-end.",
        "custom_range_invalid_order": "Parametr --time-start nie moze byc pozniejszy od --time-end.",
        "time_arg_invalid": "Niepoprawny parametr --time. Uzyj: none, 1h, 24h albo 7d.",
        "time_filter_no_matches": "Filtr czasu nie zwrocil zadnych wpisow albo ten format logu nie zawiera rozpoznawalnych znacznikow czasu.",
        "log_missing": "Plik logu nie istnieje: {path}",
        "log_no_access": "Brak uprawnien do odczytu pliku logu: {path}",
        "log_empty": "Wybrany plik logow jest pusty.",
        "log_trimmed": "[UWAGA: Log zostal obciety do ostatnich {size} bajtow]",
        "report_title": "Raport AI",
        "report_source": "Zrodlo",
        "report_generated": "Wygenerowano",
        "json_field_local_summary": "local_summary",
        "risk_high": "WYSOKIE",
        "risk_medium": "SREDNIE",
        "risk_low": "NISKIE",
        "urgency_high": "PILNE",
        "urgency_monitor": "MONITOROWANIE",
        "urgency_none": "BRAK",
        "source_profile_auth": "bezpieczenstwo i uwierzytelnianie",
        "source_profile_nginx_access": "ruch HTTP nginx",
        "source_profile_nginx_error": "bledy serwera nginx",
        "source_profile_apache": "ruch i bledy apache",
        "source_profile_fail2ban": "ochrona przed brute force",
        "source_profile_kernel": "jadro systemu linux",
        "source_profile_system": "logi systemowe ogolne",
        "source_profile_generic": "log ogolny",
        "focus_auth_1": "udane i nieudane logowania",
        "focus_auth_2": "proby brute force",
        "focus_auth_3": "uzycie sudo i eskalacja uprawnien",
        "focus_auth_4": "nietypowe adresy IP lub uzytkownicy",
        "focus_nginx_access_1": "nietypowe statusy HTTP 4xx/5xx",
        "focus_nginx_access_2": "skanowanie endpointow i probe exploitow",
        "focus_nginx_access_3": "nagly wzrost ruchu lub bledow",
        "focus_nginx_access_4": "podejrzane user-agenty i adresy IP",
        "focus_nginx_error_1": "awarie upstreamu i time-outy",
        "focus_nginx_error_2": "problemy TLS lub konfiguracji",
        "focus_nginx_error_3": "bledy aplikacji backendowej",
        "focus_nginx_error_4": "nagly wzrost ostrzezen i bledow krytycznych",
        "focus_apache_1": "bledy 4xx/5xx i restarty serwera",
        "focus_apache_2": "proby skanowania i exploitacji",
        "focus_apache_3": "problemy z modulami i virtual hostami",
        "focus_apache_4": "nietypowe wzorce ruchu",
        "focus_fail2ban_1": "nowe bany i unbany adresow IP",
        "focus_fail2ban_2": "powtarzalne ataki z jednego zrodla",
        "focus_fail2ban_3": "czy fail2ban reaguje skutecznie",
        "focus_kernel_1": "bledy sprzetowe i I/O",
        "focus_kernel_2": "problemy z pamiecia i procesami",
        "focus_kernel_3": "warningi jadra i modulem",
        "focus_system_1": "restarty uslug i bledy daemonow",
        "focus_system_2": "ostrzezenia systemowe i sieciowe",
        "focus_system_3": "problemy z cronem, dyskiem lub DNS",
        "focus_generic_1": "najwazniejsze anomalie i bledy",
        "focus_generic_2": "nietypowe wzorce zdarzen",
        "focus_generic_3": "powtarzajace sie problemy wymagajace reakcji",
        "summary_non_empty": "Liczba niepustych linii: {value}",
        "summary_profile": "Wykryty profil logu: {value}",
        "summary_error": "Szacowane wystapienia error: {value}",
        "summary_warning": "Szacowane wystapienia warning: {value}",
        "summary_failed": "Szacowane wystapienia failed: {value}",
        "summary_critical": "Szacowane wystapienia critical: {value}",
        "summary_4xx": "Liczba odpowiedzi HTTP 4xx: {value}",
        "summary_5xx": "Liczba odpowiedzi HTTP 5xx: {value}",
        "summary_timeout": "Timeout/timed out: {value}",
        "summary_upstream": "Upstream/backend issues: {value}",
        "summary_top_ips": "Top adresy IP: {value}",
        "summary_top_statuses": "Top statusy HTTP: {value}",
        "summary_top_paths": "Top endpointy: {value}",
        "summary_top_methods": "Top metody HTTP: {value}",
        "summary_top_users": "Top uzytkownicy: {value}",
        "summary_special_patterns": "Wykryte wzorce specjalne: {value}",
        "summary_security": "Wstepne sygnaly bezpieczenstwa: {value}",
        "summary_rules": "Wnioski techniczne regułowe: {value}",
        "summary_none": "brak",
        "summary_no_special": "brak jednoznacznych trafien",
        "summary_no_security": "brak silnych sygnalow heurystycznych",
        "summary_no_rules": "brak mocnych sygnalow regułowych",
        "finding_bruteforce": "mozliwe brute force: failed password = {value}",
        "finding_invalid_users": "proby logowania na nieistniejace konta: {value}",
        "finding_failed_vs_success": "duzo wiecej nieudanych logowan niz udanych",
        "finding_bans": "fail2ban lub podobny mechanizm zareagowal wielokrotnie: {value}",
        "finding_exploit_paths": "mozliwe skanowanie znanych endpointow: {value}",
        "finding_scanners": "wykryto nazwy narzedzi skanujacych: {value}",
        "finding_top_users": "najczesciej wystepujacy uzytkownicy: {value}",
        "finding_many_4xx": "duzo odpowiedzi 4xx: {value}",
        "finding_many_5xx": "podwyzszona liczba odpowiedzi 5xx: {value}",
        "finding_many_timeout": "wiele timeoutow lub timed out: {value}",
        "finding_many_upstream": "wiele problemow upstream/backend: {value}",
        "finding_many_denied": "czeste odmowy dostepu lub denied: {value}",
        "finding_many_restart": "duzo wpisow sugerujacych restarty uslug: {value}",
        "prompt_intro": "Jestes doswiadczonym administratorem Linux i analitykiem incydentow.",
        "prompt_instruction": "Przeanalizuj logi i odpowiedz po polsku w sposob bardzo czytelny dla administratora.",
        "prompt_structure": "Zwroc raport w tej strukturze:",
        "prompt_section_1": "1. Krotkie podsumowanie sytuacji",
        "prompt_section_2": "2. Najwazniejsze zdarzenia",
        "prompt_section_3": "3. Wykryte problemy lub anomalie",
        "prompt_section_4": "4. Ocena ryzyka",
        "prompt_section_5": "5. Rekomendowane dzialania",
        "prompt_section_6": "6. Czy wymagana jest natychmiastowa reakcja? (TAK/NIE + uzasadnienie)",
        "prompt_risk": "Jesli potrafisz, nazwij poziom ryzyka wprost jako: niski, sredni lub wysoki.",
        "prompt_urgency": "Jesli potrafisz, ocen pilnosc reakcji jako: brak, monitorowanie, pilne lub krytyczne.",
        "prompt_time": "Uwzglednij, ze analizowany material moze byc ograniczony filtrem czasu: {value}.",
        "prompt_profile": "Dopasuj wnioski do profilu logu: {value}.",
        "prompt_focus": "Zwracaj uwage szczegolnie na:",
        "prompt_source_name": "Nazwa zrodla: {value}",
        "prompt_path": "Sciezka: {value}",
        "prompt_description": "Opis: {value}",
        "prompt_time_filter": "Filtr czasu: {value}",
        "prompt_stats": "Statystyki wstepne:",
        "prompt_logs": "Logi:",
        "arg_desc": "CLI do analizy logow serwerowych przez AI",
        "arg_config": "Sciezka do pliku log-sources.json",
        "arg_source": "Id lub nazwa zrodla logu do analizy, np. 4 albo 'Auth Log'",
        "arg_time": "Filtr czasu dla trybu bez interakcji: none, 1h, 24h, 7d",
        "arg_time_start": "Poczatek wlasnego zakresu czasu, np. '2026-07-13 10:00'",
        "arg_time_end": "Koniec wlasnego zakresu czasu, np. '2026-07-13 18:00'",
        "arg_lang": "Jezyk interfejsu i raportu AI: pl albo en",
    },
    "en": {
        "app_subtitle": "Linux server log analysis with a readable report for administrators",
        "error_prefix": "ERROR",
        "status_missing": "MISSING",
        "status_no_access": "NO ACCESS",
        "status_empty": "EMPTY",
        "status_unknown": "UNKNOWN",
        "status_ok": "OK",
        "status_missing_desc": "File does not exist",
        "status_no_access_desc": "No read permission",
        "status_empty_desc": "File exists but is empty",
        "status_unknown_desc": "Could not read file metadata",
        "status_ok_desc": "Ready for analysis",
        "sessions_title": "Session",
        "sources_title": "Available logs",
        "selection_title": "Selection",
        "time_filter_title": "Time filter",
        "local_summary_title": "Quick technical analysis",
        "config_label": "Configuration",
        "sources_count_label": "Sources count",
        "model_label": "AI model",
        "limit_label": "Log limit",
        "reports_label": "Reports",
        "path_label": "Path",
        "status_label": "Status",
        "description_label": "Description",
        "selected_source_label": "Selected source",
        "time_filter_label": "Time filter",
        "profile_label": "Log profile",
        "choose_source_prompt": "Choose log number to analyze or q to quit: ",
        "choose_time_prompt": "Choose time filter [1-5]: ",
        "time_option_none": "No time filter",
        "time_option_1h": "Last 1 hour",
        "time_option_24h": "Last 24 hours",
        "time_option_7d": "Last 7 days",
        "time_option_custom": "Custom from-to range",
        "custom_time_format": "Date format: YYYY-MM-DD HH:MM or YYYY-MM-DD HH:MM:SS",
        "from_prompt": "From: ",
        "to_prompt": "To: ",
        "invalid_choice": "Invalid choice. Please try again.",
        "invalid_time_choice": "Invalid time filter choice. Please try again.",
        "invalid_date": "Invalid date: {error}",
        "invalid_date_order": "Start date cannot be later than end date.",
        "date_format_error": "use format YYYY-MM-DD HH:MM or YYYY-MM-DD HH:MM:SS",
        "config_load": "Loaded configuration: {config}",
        "menu_exit": "Program ended from the selection menu.",
        "read_log": "Reading log from {path}",
        "back_to_menu": "Returned to the log list. You can choose another source.",
        "back_to_menu_time": "Returned to the log list. Change the time filter or choose another source.",
        "time_filter_kept": "Time filter kept {matched} of {total} lines, skipped without timestamp: {skipped}",
        "snippet_size": "Submitted snippet size: {size} bytes",
        "analysis_running": "AI analysis in progress with model {model}",
        "analysis_done": "AI analysis completed",
        "report_saved": "Markdown report saved to: {path}",
        "json_saved": "JSON export saved to: {path}",
        "stopped": "Stopped by user or missing interactive input.",
        "missing_api_key": "Missing OPENAI_API_KEY environment variable.",
        "api_error": "OpenAI API error ({code}): {details}",
        "api_connect_error": "Cannot connect to OpenAI API: {reason}",
        "api_empty_error": "OpenAI API returned no report text.",
        "config_missing": "Configuration file not found: {path}. Copy log-sources.example.json to log-sources.json and update the paths.",
        "config_invalid_json": "Invalid JSON in configuration file: {error}",
        "config_invalid_array": "Configuration file must contain a non-empty array of log sources.",
        "config_invalid_source": "Invalid log source at position {index}.",
        "source_not_found": "No log source found for --source: {value}",
        "custom_range_requires_both": "For a custom time range you must provide both --time-start and --time-end.",
        "custom_range_invalid_order": "--time-start cannot be later than --time-end.",
        "time_arg_invalid": "Invalid --time value. Use: none, 1h, 24h or 7d.",
        "time_filter_no_matches": "The time filter returned no entries or this log format has no recognizable timestamps.",
        "log_missing": "Log file does not exist: {path}",
        "log_no_access": "No permission to read log file: {path}",
        "log_empty": "Selected log file is empty.",
        "log_trimmed": "[WARNING: Log was trimmed to the last {size} bytes]",
        "report_title": "AI report",
        "report_source": "Source",
        "report_generated": "Generated at",
        "risk_high": "HIGH",
        "risk_medium": "MEDIUM",
        "risk_low": "LOW",
        "urgency_high": "URGENT",
        "urgency_monitor": "MONITOR",
        "urgency_none": "NONE",
        "source_profile_auth": "security and authentication",
        "source_profile_nginx_access": "nginx HTTP traffic",
        "source_profile_nginx_error": "nginx server errors",
        "source_profile_apache": "apache traffic and errors",
        "source_profile_fail2ban": "brute-force protection",
        "source_profile_kernel": "linux kernel",
        "source_profile_system": "general system logs",
        "source_profile_generic": "generic log",
        "focus_auth_1": "successful and failed logins",
        "focus_auth_2": "brute-force attempts",
        "focus_auth_3": "sudo usage and privilege escalation",
        "focus_auth_4": "unusual IP addresses or users",
        "focus_nginx_access_1": "unusual HTTP 4xx/5xx statuses",
        "focus_nginx_access_2": "endpoint scanning and exploitation attempts",
        "focus_nginx_access_3": "sudden spikes in traffic or errors",
        "focus_nginx_access_4": "suspicious user agents and IPs",
        "focus_nginx_error_1": "upstream failures and timeouts",
        "focus_nginx_error_2": "TLS or configuration problems",
        "focus_nginx_error_3": "backend application errors",
        "focus_nginx_error_4": "spikes in warnings and critical errors",
        "focus_apache_1": "4xx/5xx errors and server restarts",
        "focus_apache_2": "scanning and exploitation attempts",
        "focus_apache_3": "module and virtual host problems",
        "focus_apache_4": "unusual traffic patterns",
        "focus_fail2ban_1": "new bans and unbans",
        "focus_fail2ban_2": "repeated attacks from the same source",
        "focus_fail2ban_3": "whether fail2ban reacts effectively",
        "focus_kernel_1": "hardware and I/O errors",
        "focus_kernel_2": "memory and process problems",
        "focus_kernel_3": "kernel and module warnings",
        "focus_system_1": "service restarts and daemon errors",
        "focus_system_2": "system and network warnings",
        "focus_system_3": "cron, disk or DNS problems",
        "focus_generic_1": "most important anomalies and errors",
        "focus_generic_2": "unusual event patterns",
        "focus_generic_3": "repeated issues that need action",
        "summary_non_empty": "Non-empty lines: {value}",
        "summary_profile": "Detected log profile: {value}",
        "summary_error": "Estimated error occurrences: {value}",
        "summary_warning": "Estimated warning occurrences: {value}",
        "summary_failed": "Estimated failed occurrences: {value}",
        "summary_critical": "Estimated critical occurrences: {value}",
        "summary_4xx": "HTTP 4xx responses: {value}",
        "summary_5xx": "HTTP 5xx responses: {value}",
        "summary_timeout": "Timeout/timed out: {value}",
        "summary_upstream": "Upstream/backend issues: {value}",
        "summary_top_ips": "Top IP addresses: {value}",
        "summary_top_statuses": "Top HTTP statuses: {value}",
        "summary_top_paths": "Top endpoints: {value}",
        "summary_top_methods": "Top HTTP methods: {value}",
        "summary_top_users": "Top users: {value}",
        "summary_special_patterns": "Detected special patterns: {value}",
        "summary_security": "Preliminary security signals: {value}",
        "summary_rules": "Rule-based technical findings: {value}",
        "summary_none": "none",
        "summary_no_special": "no clear matches",
        "summary_no_security": "no strong heuristic security signals",
        "summary_no_rules": "no strong rule-based signals",
        "finding_bruteforce": "possible brute force: failed password = {value}",
        "finding_invalid_users": "attempts against non-existing accounts: {value}",
        "finding_failed_vs_success": "many more failed logins than successful ones",
        "finding_bans": "fail2ban or similar reacted multiple times: {value}",
        "finding_exploit_paths": "possible scanning of known endpoints: {value}",
        "finding_scanners": "detected scanner tool names: {value}",
        "finding_top_users": "most frequent users: {value}",
        "finding_many_4xx": "high amount of 4xx responses: {value}",
        "finding_many_5xx": "elevated amount of 5xx responses: {value}",
        "finding_many_timeout": "many timeouts or timed out messages: {value}",
        "finding_many_upstream": "many upstream/backend problems: {value}",
        "finding_many_denied": "frequent access denied events: {value}",
        "finding_many_restart": "many entries suggesting service restarts: {value}",
        "prompt_intro": "You are an experienced Linux administrator and incident analyst.",
        "prompt_instruction": "Analyze the logs and answer in clear English for a system administrator.",
        "prompt_structure": "Return the report in this structure:",
        "prompt_section_1": "1. Short situation summary",
        "prompt_section_2": "2. Most important events",
        "prompt_section_3": "3. Detected problems or anomalies",
        "prompt_section_4": "4. Risk assessment",
        "prompt_section_5": "5. Recommended actions",
        "prompt_section_6": "6. Is immediate reaction required? (YES/NO + justification)",
        "prompt_risk": "If possible, explicitly name the risk level as: low, medium or high.",
        "prompt_urgency": "If possible, explicitly name the urgency as: none, monitor, urgent or critical.",
        "prompt_time": "Consider that the analyzed material may be limited by this time filter: {value}.",
        "prompt_profile": "Adjust conclusions to this log profile: {value}.",
        "prompt_focus": "Pay particular attention to:",
        "prompt_source_name": "Source name: {value}",
        "prompt_path": "Path: {value}",
        "prompt_description": "Description: {value}",
        "prompt_time_filter": "Time filter: {value}",
        "prompt_stats": "Preliminary statistics:",
        "prompt_logs": "Logs:",
        "arg_desc": "CLI for AI-powered server log analysis",
        "arg_config": "Path to the log-sources.json file",
        "arg_source": "Id or name of the log source to analyze, e.g. 4 or 'Auth Log'",
        "arg_time": "Time filter for non-interactive mode: none, 1h, 24h, 7d",
        "arg_time_start": "Start of custom time range, e.g. '2026-07-13 10:00'",
        "arg_time_end": "End of custom time range, e.g. '2026-07-13 18:00'",
        "arg_lang": "CLI and AI report language: pl or en",
    },
}


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


def tr(key: str, **kwargs: Any) -> str:
    template = TRANSLATIONS.get(CURRENT_LANG, TRANSLATIONS["pl"]).get(key)
    if template is None:
        template = TRANSLATIONS["pl"].get(key, key)
    return template.format(**kwargs)


def set_language(lang: str) -> None:
    global CURRENT_LANG
    normalized = (lang or "pl").strip().lower()
    if normalized not in {"pl", "en"}:
        raise RuntimeError("Invalid --lang value. Use: pl or en.")
    CURRENT_LANG = normalized


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
        if not isinstance(entry, dict) or not entry.get("name") or not entry.get("path"):
            raise RuntimeError(tr("config_invalid_source", index=index))
        sources.append({
            "id": entry.get("id", index),
            "name": entry["name"],
            "path": entry["path"],
            "description": entry.get("description", "Brak opisu"),
        })
    return sources


def render_session_panel(config_path: str, sources: list[dict[str, Any]]) -> None:
    config_name = Path(config_path).name
    lines = [
        f"{tr('config_label')} : {config_name}",
        f"{tr('sources_count_label')}: {len(sources)}",
        f"{tr('model_label')}     : {DEFAULT_MODEL}",
        f"{tr('limit_label')}   : {DEFAULT_MAX_BYTES} bytes",
        f"{tr('reports_label')}      : {OUTPUT_DIR}",
    ]
    print()
    print(box_lines(lines, title=tr("sessions_title"), color=Style.magenta))


def inspect_log_status(file_path: Path) -> tuple[str, str, str]:
    if not file_path.exists():
        return (tr("status_missing"), tr("status_missing_desc"), Style.red)
    if not os.access(file_path, os.R_OK):
        return (tr("status_no_access"), tr("status_no_access_desc"), Style.yellow)
    try:
        if file_path.stat().st_size == 0:
            return (tr("status_empty"), tr("status_empty_desc"), Style.yellow)
    except OSError:
        return (tr("status_unknown"), tr("status_unknown_desc"), Style.yellow)
    return (tr("status_ok"), tr("status_ok_desc"), Style.green)


def render_menu(sources: list[dict[str, Any]]) -> None:
    lines: list[str] = []
    for source in sources:
        state_label, state_desc, state_color = inspect_log_status(Path(source["path"]))
        lines.append(style(f"{source['id']:>2}. {source['name']}", Style.bold, Style.white))
        lines.append(f"    {tr('path_label')}: {source['path']}")
        lines.append(f"    {tr('status_label')}:  {style(state_label, Style.bold, state_color)} - {state_desc}")
        lines.append(f"    {tr('description_label')}:    {source['description']}")
        lines.append("")
    if lines and not lines[-1]:
        lines.pop()
    print()
    print(box_lines(lines, title=tr("sources_title"), color=Style.blue))


def choose_source(sources: list[dict[str, Any]]) -> dict[str, Any] | None:
    valid = {str(source["id"]): source for source in sources}
    while True:
        answer = input(style("\n" + tr("choose_source_prompt"), Style.bold, Style.white)).strip()
        if answer.lower() in {"q", "quit", "exit"}:
            return None
        source = valid.get(answer)
        if source:
            return source
        print_status("INFO", tr("invalid_choice"), Style.yellow)


def resolve_source(sources: list[dict[str, Any]], source_value: str) -> dict[str, Any]:
    normalized = source_value.strip().lower()
    for source in sources:
        if str(source["id"]) == normalized:
            return source
    for source in sources:
        if source["name"].strip().lower() == normalized:
            return source
    raise RuntimeError(tr("source_not_found", value=source_value))


def choose_time_filter() -> TimeFilter:
    now = datetime.now().astimezone()
    print()
    print(box_lines([
        f"1. {tr('time_option_none')}",
        f"2. {tr('time_option_1h')}",
        f"3. {tr('time_option_24h')}",
        f"4. {tr('time_option_7d')}",
        f"5. {tr('time_option_custom')}",
    ], title=tr("time_filter_title"), color=Style.magenta))

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


def parse_user_datetime(value: str, now: datetime) -> datetime:
    formats = ["%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M"]
    for fmt in formats:
        try:
            parsed = datetime.strptime(value, fmt)
            return parsed.replace(tzinfo=now.tzinfo)
        except ValueError:
            continue
    raise ValueError(tr("date_format_error"))


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
    ]
    summary_lines.append(tr("summary_special_patterns", value=", ".join(indicator_hits) if indicator_hits else tr("summary_no_special")))
    summary_lines.append(tr("summary_security", value="; ".join(security_findings) if security_findings else tr("summary_no_security")))
    summary_lines.append(tr("summary_rules", value="; ".join(technical_findings) if technical_findings else tr("summary_no_rules")))
    return "\n".join(summary_lines)


def collect_local_summary(source: dict[str, Any], log_content: str, time_filter: TimeFilter) -> dict[str, Any]:
    profile = detect_source_profile(source)
    stats_text = build_log_summary(log_content, profile)
    return {"profile": profile.category, "time_filter": time_filter.label, "stats_text": stats_text, "stats_lines": stats_text.splitlines()}


def render_local_summary(summary: dict[str, Any]) -> None:
    lines = [f"{tr('profile_label')}: {summary['profile']}", f"{tr('time_filter_label')}: {summary['time_filter']}", "", *summary["stats_lines"]]
    print()
    print(box_lines(lines, title=tr("local_summary_title"), color=Style.magenta))


def build_prompt(source: dict[str, Any], log_content: str, time_filter: TimeFilter) -> str:
    summary = collect_local_summary(source, log_content, time_filter)
    profile = detect_source_profile(source)
    stats = summary["stats_text"]
    focus = "\n".join(f"- {item}" for item in profile.focus_areas)
    return "\n".join([
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
        tr("prompt_source_name", value=source['name']),
        tr("prompt_path", value=source['path']),
        tr("prompt_description", value=source['description']),
        tr("prompt_time_filter", value=time_filter.label),
        "",
        tr("prompt_stats"),
        stats,
        "",
        tr("prompt_logs"),
        log_content,
    ]).strip()


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
            line = f"\r{style(frame, Style.yellow, Style.bold)} {self.message}"
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


def analyze_with_openai(source: dict[str, Any], log_content: str, time_filter: TimeFilter) -> str:
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        raise RuntimeError(tr("missing_api_key"))
    payload = json.dumps({"model": DEFAULT_MODEL, "input": build_prompt(source, log_content, time_filter)}).encode("utf-8")
    req = request.Request(API_URL, data=payload, headers={"Content-Type": "application/json", "Authorization": f"Bearer {api_key}"}, method="POST")
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
    text = (data.get("output_text") or "").strip()
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
        "language": CURRENT_LANG,
        "source": {"id": source.get("id"), "name": source.get("name"), "path": source.get("path"), "description": source.get("description")},
        "time_filter": {"label": time_filter.label, "start": time_filter.start.isoformat() if time_filter.start else None, "end": time_filter.end.isoformat() if time_filter.end else None},
        "local_summary": {"profile": summary["profile"], "stats_lines": summary["stats_lines"], "stats_text": summary["stats_text"]},
        "ai_report": report,
    }
    json_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    return report_path, json_path


def classify_risk(line: str) -> tuple[str, str] | None:
    lower = line.lower()
    if any(token in lower for token in ["wysok", "krytycz", "high", "critical"]):
        return (tr("risk_high"), Style.red)
    if any(token in lower for token in ["sredni", "umiark", "medium", "moderate"]):
        return (tr("risk_medium"), Style.yellow)
    if any(token in lower for token in ["niski", "niskie", "low"]):
        return (tr("risk_low"), Style.green)
    return None


def classify_urgency(line: str) -> tuple[str, str] | None:
    lower = line.lower()
    if any(token in lower for token in ["natychmiast", "krytycz", "pilne", "urgent", "critical", "immediate"]):
        return (tr("urgency_high"), Style.red)
    if any(token in lower for token in ["monitor", "observe"]):
        return (tr("urgency_monitor"), Style.yellow)
    if any(token in lower for token in ["brak", "nie", "none", "no immediate"]):
        return (tr("urgency_none"), Style.green)
    return None


def build_report_panels(report: str) -> list[str]:
    sections: list[tuple[str, list[str]]] = []
    current_title = "Summary"
    current_lines: list[str] = []
    for raw_line in report.splitlines():
        line = raw_line.strip()
        if not line:
            if current_lines and current_lines[-1] != "":
                current_lines.append("")
            continue
        if re.match(r"^\d+\.\s", line):
            if current_lines:
                sections.append((current_title, current_lines))
            current_title = re.sub(r"^\d+\.\s*", "", line)
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
        rendered.append(box_lines(lines or ["Brak danych" if CURRENT_LANG == 'pl' else "No data"], title=upper_title, color=color))
    return rendered


def main() -> int:
    args = parse_args()
    try:
        set_language(args.lang)
        print_header()
        sources = load_sources(Path(args.config))
        print_status("CFG", tr("config_load", config=args.config), Style.green)
        render_session_panel(args.config, sources)
        selected_source_cli = resolve_source(sources, args.source) if args.source else None
        time_filter_cli = build_cli_time_filter(args)
        while True:
            if selected_source_cli is None:
                render_menu(sources)
                selected_source = choose_source(sources)
                if selected_source is None:
                    print_status("STOP", tr("menu_exit"), Style.yellow)
                    return 0
            else:
                selected_source = selected_source_cli
            time_filter = time_filter_cli or choose_time_filter()
            print()
            print(box_lines([
                f"{tr('selected_source_label')}: {selected_source['name']}",
                f"{tr('path_label')}: {selected_source['path']}",
                f"{tr('description_label')}: {selected_source['description']}",
                f"{tr('time_filter_label')}: {time_filter.label}",
            ], title=tr("selection_title"), color=Style.cyan))
            print_status("READ", tr("read_log", path=selected_source['path']), Style.blue)
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
                filtered_content, matched_lines, total_lines, skipped_without_timestamp = apply_time_filter(raw_log_content, time_filter)
            except LogFilteringError as exc:
                if selected_source_cli is not None or time_filter_cli is not None:
                    raise
                print_status("WARN", str(exc), Style.yellow)
                print_status("INFO", tr("back_to_menu_time"), Style.blue)
                print()
                continue
            log_content = prepare_log_snippet(filtered_content)
            print_status("TIME", tr("time_filter_kept", matched=matched_lines, total=total_lines, skipped=skipped_without_timestamp), Style.magenta)
            print_status("META", tr("snippet_size", size=len(log_content.encode('utf-8'))), Style.magenta)
            local_summary = collect_local_summary(selected_source, log_content, time_filter)
            render_local_summary(local_summary)
            report = analyze_with_openai(selected_source, log_content, time_filter)
            report_path, json_path = save_report(selected_source, report, time_filter, local_summary)
            print()
            for panel in build_report_panels(report):
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


if __name__ == "__main__":
    raise SystemExit(main())
