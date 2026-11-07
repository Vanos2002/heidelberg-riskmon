# Heidelberg Risk Monitor

Checks public feeds every 10 minutes and e-mails a digest of **new** alerts.

| Source | Covers | Default threshold |
|---|---|---|
| NINA (BBK), region key `082210000000` | Civil protection (MoWaS, KATWARN, BIWAPP), DWD weather warnings, flood warnings | all (`minor`+) |
| Presseportal – Polizeipräsidium Mannheim | Police press releases mentioning Heidelberg | all; escalated to `moderate` on keywords |
| BSI WID / CERT-Bund | Cyber-security advisories | `severe` (= BSI "hoch" / "kritisch") |

Python standard library only, no packages to install.

## Running on GitHub Actions (current setup)

Runs every 15 min in the public repo `Vanos2002/heidelberg-riskmon`, independent of the laptop.
The App Password is the repo secret `RISKMON_SMTP_PASSWORD`. After each run the bot commits
`riskmon_state.sqlite3`, so run `git pull` before running locally.
Manual run / SMTP test: *Actions → Heidelberg Risk Monitor → Run workflow* (tick "test e-mail").

## Local setup (alternative)

1. Create a Gmail **App Password** at https://myaccount.google.com/apppasswords (needs 2-Step Verification).
2. `cp .env.example .env && chmod 600 .env` and paste the app password into `.env`.
3. `python3 -m riskmon --test-email` to check that e-mail works.
4. Schedule it (every 10 min, survives reboots):
   ```sh
   cp com.matejvana.riskmon.plist ~/Library/LaunchAgents/
   launchctl load ~/Library/LaunchAgents/com.matejvana.riskmon.plist
   ```
   Stop with `launchctl unload ~/Library/LaunchAgents/com.matejvana.riskmon.plist`.
   Log: `logs/riskmon.log`.

## Commands

```sh
python3 -m riskmon               # fetch + e-mail new alerts
python3 -m riskmon --dry-run     # print the e-mail instead of sending
python3 -m riskmon --baseline    # mark all current items as seen (no e-mail)
python3 -m riskmon --test-email  # SMTP check
```

## Tuning (`config.json`)

- `bsi_wid.product_keywords`: e.g. `["Windows", "macOS", "Chrome", "Python"]` to get only advisories for software you use. `min_severity` can be `minor | moderate | severe | extreme`.
- `nina.ars`: add `"082260000000"` for the surrounding Rhein-Neckar-Kreis.
- `police.escalate_keywords`: words that raise a police report to `moderate`.

Failed e-mails are retried on the next run, because alerts are only marked as seen after a successful send.
