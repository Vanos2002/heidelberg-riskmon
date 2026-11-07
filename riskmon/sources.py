"""Collectors for public risk feeds relevant to Heidelberg.

Every collector returns a list of Alert objects in one common format.
"""
from __future__ import annotations

import json
import re
import ssl
import subprocess
import sys
import urllib.request
import xml.etree.ElementTree as ET
from dataclasses import dataclass

USER_AGENT = "heidelberg-riskmon/1.0 (personal alert monitor)"

# Common severity scale used across all sources (lowest -> highest).
SEVERITIES = ["info", "minor", "moderate", "severe", "extreme"]


def severity_rank(sev: str) -> int:
    return SEVERITIES.index(sev) if sev in SEVERITIES else 0


@dataclass
class Alert:
    uid: str          # stable unique id used for de-duplication
    source: str       # e.g. "NINA", "Polizei", "BSI WID"
    severity: str     # one of SEVERITIES
    title: str
    summary: str
    url: str
    published: str


_SSL_CTX: ssl.SSLContext | None = None


def _ssl_context() -> ssl.SSLContext:
    """Default context, plus the macOS system root CAs.

    python.org builds on macOS ship without a CA bundle, so we also load the
    roots from the system keychain (no extra packages needed).
    """
    global _SSL_CTX
    if _SSL_CTX is None:
        ctx = ssl.create_default_context()
        if sys.platform == "darwin":
            try:
                pem = subprocess.run(
                    ["/usr/bin/security", "find-certificate", "-a", "-p",
                     "/System/Library/Keychains/SystemRootCertificates.keychain"],
                    capture_output=True, text=True, timeout=20, check=True,
                ).stdout
                if pem:
                    ctx.load_verify_locations(cadata=pem)
            except Exception:
                pass
        _SSL_CTX = ctx
    return _SSL_CTX


def fetch(url: str, timeout: int = 20) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=timeout, context=_ssl_context()) as resp:
        return resp.read()


def _rss_items(raw: bytes):
    root = ET.fromstring(raw)
    for item in root.iter("item"):
        yield {child.tag: (child.text or "").strip() for child in item}


# --------------------------------------------------------------------------
# NINA (Bundesamt für Bevölkerungsschutz) – aggregates MoWaS, KATWARN,
# BIWAPP, DWD weather warnings and LHP flood warnings for a region key (ARS).
# --------------------------------------------------------------------------
NINA_BASE = "https://warnung.bund.de/api31"
NINA_SEVERITY = {
    "minor": "minor",
    "moderate": "moderate",
    "severe": "severe",
    "extreme": "extreme",
}


def _nina_details(warning_id: str) -> tuple[str, str]:
    """Return (description, web link) from the full CAP message, if available."""
    try:
        cap = json.loads(fetch(f"{NINA_BASE}/warnings/{warning_id}.json"))
        info = (cap.get("info") or [{}])[0]
        text = " ".join(
            part for part in (info.get("description", ""), info.get("instruction", "")) if part
        )
        text = re.sub(r"<[^>]+>", " ", text)  # some providers embed HTML
        return re.sub(r"\s+", " ", text).strip(), info.get("web", "")
    except Exception:
        return "", ""


def collect_nina(cfg: dict) -> list[Alert]:
    alerts = []
    for ars in cfg.get("ars", []):
        items = json.loads(fetch(f"{NINA_BASE}/dashboard/{ars}.json"))
        for item in items:
            wid = item.get("id", "")
            payload = item.get("payload", {})
            data = payload.get("data", {})
            sev = NINA_SEVERITY.get(str(data.get("severity", "")).lower(), "minor")
            title = data.get("headline") or item.get("i18nTitle", {}).get("de", "Warnung")
            if data.get("msgType") == "Cancel":
                title = f"Entwarnung/aufgehoben: {title}"
            provider = data.get("provider", "")
            desc, web = _nina_details(wid)
            alerts.append(Alert(
                uid=f"nina:{wid}:{payload.get('hash', '')}",
                source=f"NINA{f' / {provider}' if provider else ''}",
                severity=sev,
                title=title,
                summary=desc[:1200],
                url=web or f"https://warnung.bund.de/meldungen/{wid}",
                published=item.get("sent", ""),
            ))
    return alerts


# --------------------------------------------------------------------------
# Police press releases (Polizeipräsidium Mannheim covers Heidelberg)
# --------------------------------------------------------------------------
def collect_police(cfg: dict) -> list[Alert]:
    locations = [k.lower() for k in cfg.get("location_keywords", [])]
    escalate = [k.lower() for k in cfg.get("escalate_keywords", [])]
    alerts = []
    for feed in cfg.get("feeds", []):
        for it in _rss_items(fetch(feed)):
            text = f"{it.get('title', '')} {it.get('description', '')}".lower()
            if locations and not any(k in text for k in locations):
                continue
            sev = "moderate" if any(k in text for k in escalate) else "info"
            alerts.append(Alert(
                uid=f"police:{it.get('link') or it.get('guid') or it.get('title')}",
                source="Polizei",
                severity=sev,
                title=it.get("title", ""),
                summary=it.get("description", ""),
                url=it.get("link", ""),
                published=it.get("pubDate", ""),
            ))
    return alerts


# --------------------------------------------------------------------------
# BSI Warn- und Informationsdienst (CERT-Bund security advisories)
# --------------------------------------------------------------------------
WID_SEVERITY = {
    "niedrig": "minor",
    "mittel": "moderate",
    "hoch": "severe",
    "kritisch": "extreme",
}


def collect_bsi_wid(cfg: dict) -> list[Alert]:
    products = [k.lower() for k in cfg.get("product_keywords", [])]
    alerts = []
    for it in _rss_items(fetch(cfg["feed"])):
        title = it.get("title", "")
        if products and not any(k in title.lower() for k in products):
            continue
        level = it.get("category", "").lower()
        if not level:
            m = re.search(r"\[(niedrig|mittel|hoch|kritisch)\]", title, re.I)
            level = m.group(1).lower() if m else ""
        alerts.append(Alert(
            uid=f"wid:{it.get('link', '')}:{it.get('pubDate', '')}",
            source="BSI WID",
            severity=WID_SEVERITY.get(level, "minor"),
            title=title,
            summary=it.get("description", ""),
            url=it.get("link", ""),
            published=it.get("pubDate", ""),
        ))
    return alerts


COLLECTORS = {
    "nina": collect_nina,
    "police": collect_police,
    "bsi_wid": collect_bsi_wid,
}
