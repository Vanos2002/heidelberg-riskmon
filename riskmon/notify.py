"""E-mail notification (one digest e-mail per run with all new alerts)."""
from __future__ import annotations

import html
import os
import smtplib
from datetime import datetime
from email.message import EmailMessage
from email.utils import parsedate_to_datetime
from zoneinfo import ZoneInfo

from .sources import Alert, _ssl_context, severity_rank

LOCAL_TZ = ZoneInfo("Europe/Berlin")  # Heidelberg time, handles CET/CEST automatically


def local_time(stamp: str) -> str:
    """Convert a feed timestamp (ISO 8601 or RFC 2822, any zone) to Heidelberg time."""
    for parse in (datetime.fromisoformat, parsedate_to_datetime):
        try:
            dt = parse(stamp)
        except (TypeError, ValueError):
            continue
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=LOCAL_TZ)
        return dt.astimezone(LOCAL_TZ).strftime("%d.%m.%Y %H:%M %Z")
    return stamp

SEV_COLOR = {
    "extreme": "#7b1fa2",
    "severe": "#c62828",
    "moderate": "#ef6c00",
    "minor": "#f9a825",
    "info": "#607d8b",
}


def is_public_safety(a: Alert) -> bool:
    """NINA warnings and police reports: things that can affect you physically in Heidelberg."""
    return not a.source.startswith("BSI")


def build_message(alerts: list[Alert], email_cfg: dict, urgent: bool = False) -> EmailMessage:
    alerts = sorted(alerts, key=lambda a: severity_rank(a.severity), reverse=True)
    top = alerts[0].severity
    msg = EmailMessage()
    if urgent:
        # Safety alerts: short, scannable subject naming the most important warning.
        more = f" (+{len(alerts) - 1} more)" if len(alerts) > 1 else ""
        msg["Subject"] = f"⚠️ Heidelberg {top.upper()}: {alerts[0].title}{more}"
        if severity_rank(top) >= severity_rank("severe"):
            msg["X-Priority"] = "1"
            msg["Importance"] = "high"
    else:
        msg["Subject"] = (
            f"[Heidelberg Risk Monitor] {len(alerts)} cyber-security advisor"
            f"{'ies' if len(alerts) != 1 else 'y'} (highest: {top})"
        )
    msg["From"] = email_cfg["from"]
    msg["To"] = email_cfg["to"]

    lines = []
    for a in alerts:
        lines += [f"[{a.severity.upper()}] {a.source}: {a.title}",
                  f"  {local_time(a.published)}", f"  {a.summary}", f"  {a.url}", ""]
    msg.set_content("\n".join(lines))

    rows = []
    for a in alerts:
        color = SEV_COLOR.get(a.severity, "#607d8b")
        rows.append(
            f'<div style="border-left:4px solid {color};padding:6px 12px;margin:0 0 14px">'
            f'<div style="font-size:12px;color:{color};font-weight:bold">'
            f"{html.escape(a.severity.upper())} · {html.escape(a.source)}</div>"
            f'<div style="font-size:15px;font-weight:bold;margin:2px 0">'
            f'<a href="{html.escape(a.url)}" style="color:#1a1a1a">{html.escape(a.title)}</a></div>'
            f'<div style="font-size:12px;color:#666">{html.escape(local_time(a.published))}</div>'
            f'<div style="font-size:13px;margin-top:4px">{html.escape(a.summary)}</div></div>'
        )
    msg.add_alternative(
        '<html><body style="font-family:Arial,sans-serif">'
        "<h2 style='margin:0 0 12px'>Heidelberg Risk Monitor</h2>"
        + "".join(rows)
        + "</body></html>",
        subtype="html",
    )
    return msg


def send(msg: EmailMessage, email_cfg: dict) -> None:
    password = os.environ.get("RISKMON_SMTP_PASSWORD")
    if not password:
        raise RuntimeError(
            "RISKMON_SMTP_PASSWORD is not set (put it in the .env file next to config.json)"
        )
    ctx = _ssl_context()  # includes macOS system root CAs
    with smtplib.SMTP_SSL(email_cfg["smtp_host"], int(email_cfg["smtp_port"]), context=ctx) as s:
        s.login(email_cfg["smtp_user"], password)
        s.send_message(msg)
