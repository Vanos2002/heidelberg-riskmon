"""Heidelberg Risk Monitor – entry point.

    python3 -m riskmon               fetch feeds, e-mail new alerts
    python3 -m riskmon --dry-run     print the e-mail instead of sending it
    python3 -m riskmon --baseline    mark everything currently published as seen (no e-mail)
    python3 -m riskmon --test-email  send a test e-mail to check SMTP settings
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime
from pathlib import Path

from . import notify
from .sources import COLLECTORS, Alert, severity_rank
from .store import Store

PROJECT_DIR = Path(__file__).resolve().parent.parent


def log(msg: str) -> None:
    print(f"{datetime.now():%Y-%m-%d %H:%M:%S} {msg}", flush=True)


def load_dotenv(path: Path) -> None:
    if not path.exists():
        return
    for line in path.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            key, val = line.split("=", 1)
            os.environ.setdefault(key.strip(), val.strip().strip('"').strip("'"))


def gather(cfg: dict) -> list[Alert]:
    found: list[Alert] = []
    for name, collector in COLLECTORS.items():
        src_cfg = cfg.get(name, {})
        if not src_cfg.get("enabled", False):
            continue
        try:
            alerts = collector(src_cfg)
        except Exception as exc:  # one broken feed must not stop the others
            log(f"[{name}] ERROR: {exc}")
            continue
        min_rank = severity_rank(src_cfg.get("min_severity", "info"))
        kept = [a for a in alerts if severity_rank(a.severity) >= min_rank]
        log(f"[{name}] {len(alerts)} items, {len(kept)} at/above '{src_cfg.get('min_severity', 'info')}'")
        found.extend(kept)
    return found


def main() -> int:
    ap = argparse.ArgumentParser(description="Heidelberg Risk Monitor")
    ap.add_argument("--config", default=str(PROJECT_DIR / "config.json"))
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--baseline", action="store_true")
    ap.add_argument("--test-email", action="store_true")
    args = ap.parse_args()

    load_dotenv(PROJECT_DIR / ".env")
    cfg = json.loads(Path(args.config).read_text())
    email_cfg = cfg["email"]
    # The address is kept out of the (public) repo: it comes from .env / a GitHub secret.
    address = os.environ.get("RISKMON_EMAIL", "")
    for key in ("to", "from", "smtp_user"):
        email_cfg.setdefault(key, address)
    if not email_cfg["to"]:
        log("RISKMON_EMAIL is not set (put it in .env, or as a GitHub secret)")
        return 1

    if args.test_email:
        test = Alert("test", "Test", "info", "Test e-mail from Heidelberg Risk Monitor",
                     "If you can read this, SMTP is configured correctly.", "https://warnung.bund.de",
                     datetime.now(notify.LOCAL_TZ).isoformat(timespec="seconds"))
        notify.send(notify.build_message([test], email_cfg), email_cfg)
        log("Test e-mail sent")
        return 0

    store = Store(str(PROJECT_DIR / cfg.get("state_db", "riskmon_state.sqlite3")))
    new = [a for a in gather(cfg) if store.is_new(a.uid)]
    # de-duplicate within the run (same item in several feeds)
    new = list({a.uid: a for a in new}.values())

    if args.baseline:
        store.mark(new)
        log(f"Baseline: marked {len(new)} current items as seen, no e-mail sent")
        return 0

    if not new:
        log("No new alerts")
        return 0

    # Public-safety alerts go out first, in their own e-mail, so they are never
    # buried under a pile of cyber-security advisories.
    groups = [
        ("public-safety", [a for a in new if notify.is_public_safety(a)], True),
        ("cyber-security", [a for a in new if not notify.is_public_safety(a)], False),
    ]
    status = 0
    for label, alerts, urgent in groups:
        if not alerts:
            continue
        msg = notify.build_message(alerts, email_cfg, urgent=urgent)
        if args.dry_run:
            print(f"Subject: {msg['Subject']}")
            print(msg.get_body(preferencelist=("plain",)).get_content())
            log(f"Dry run: {len(alerts)} {label} alerts (not sent, not marked as seen)")
            continue
        try:
            notify.send(msg, email_cfg)
        except Exception as exc:
            log(f"{label} e-mail FAILED, will retry next run: {exc}")
            status = 1
            continue
        store.mark(alerts)  # only after a successful send, so nothing is lost
        log(f"Sent {len(alerts)} {label} alerts")
    return status


if __name__ == "__main__":
    sys.exit(main())
