# Hydra-Radar

OSINT monitor for German commercial register publications. Hydra-Radar flags
**energy-sector companies** that have **any structural or personal link to
Switzerland** and posts each hit to a Discord channel.

```
 sources ──► Step 1: sector filter ──► Step 2: Swiss-link detection ──► SQLite dedup ──► Discord
 (register      "Energieversorgung",      persons (Name, Vorname, Ort/Schweiz, *DOB)
  publications,  "Strom", "Gas", …         Swiss legal entities (… AG, Zug / GmbH (Schweiz))
  OpenCorporates,                          identifiers (CHE-UID, CH-postcode, +41, .ch)
  local files)                             keywords (Schweiz, Zug, Stans, Zürich, …)
                                           + optional OpenCorporates officer/parent lookup
```

## Directory layout

```
hydra-radar/
├── radar.py                 # the whole tool (single file, Python ≥ 3.9)
├── config.json              # webhook, sources, keyword lists
├── requirements.txt
├── deploy/
│   ├── install.sh           # Debian installer (/opt/hydra-radar, system user "hydra")
│   └── hydra-radar.cron     # /etc/cron.d entry
├── tests/
│   ├── test_radar.py        # offline test-suite (python3 -m unittest discover -s tests)
│   └── fixtures/            # synthetic register texts incl. false-positive decoys
└── data/                    # created at runtime: SQLite DB, logs, lock, inbox
```

## Important: what data is publicly available

Since the DiRUG reform (1 Aug 2022), new registrations (*Neueintragungen*) and
changes of business purpose (*Gegenstandsänderungen*) are **no longer
published as announcement text**. The register entry itself counts as the
publication. The "Registerbekanntmachungen" page on handelsregister.de now only
carries the notices that HGB §10 still requires: conversions and mergers
(*Umwandlung*, including cross-border mergers with Swiss AGs), deletion notices
(*Löschungsankündigungen*), filed documents and other notices. That is roughly
100–200 per day nationwide.

Hydra-Radar therefore has four interchangeable sources:

| Source | Covers | Cost / limits | Default |
|---|---|---|---|
| `github_snapshots` | All handelsregister.de *Registerbekanntmachungen*, from the daily JSON mirror at [coezbek/registerbekanntmachungen](https://github.com/coezbek/registerbekanntmachungen) | free, no load on handelsregister.de, 1–3 days delay | **on** |
| `handelsregister` | Same data, scraped directly from `handelsregister.de/rp_web/xhtml/bekanntmachungen.xhtml` (JSF/PrimeFaces, no browser needed) | Terms of use: **max. 60 retrievals/hour**, enforced by the built-in limiter; ~8 weeks online | off |
| `opencorporates` | **Neueintragungen**: German companies incorporated in the date window whose *name* matches `name_queries`. Can also enrich every Step-1 candidate with officers, nationality, address and parent company | API token required (free for some uses, paid otherwise) | off |
| `local` | Any `.txt/.html/.xml/.json` you drop into `data/inbox/`, e.g. register prints (AD/CD/SI) from handelsregister.de or exports from a commercial provider | — | off |

To monitor *Neueintragungen* and *Gegenstandsänderungen* reliably at scale,
enable `opencorporates` or feed a commercial register-data API into
`data/inbox/` (JSON format below). `run.require_event_match: true` restricts
alerts to texts that look like a new registration or a change of purpose.

## Detection details

**Step 1 – sector.** Case-insensitive substring match on company name, purpose
and full text, so compounds like *Ökostrom*, *Erdgas* and *Gasversorgung*
count. `sector_exclude` blanks out look-alikes first: *Gaststätte*, *Gasthof*,
*Hauptgasse*, *Pegasus*, *Stromberg*, and so on.

**Step 2 – Swiss link.** The findings are listed in the alert, most specific
first:

* **person**: register-style entries in both orders,
  `Keller, Urs, Baar / Schweiz, *14.02.1971` and
  `Müller, Hans, *01.02.1970, Zürich/Schweiz`, with the role taken from the
  preceding label (*Geschäftsführer:*, *Prokura:*, *Vorstand:* …)
* **entity**: `… AG, Zug`, `… AG mit Sitz in Stans`, `… GmbH (Schweiz)`,
  `… SA, CH-6900 Lugano`, `… AG nach schweizerischem Recht`
* **identifier**: Swiss UID `CHE-123.456.789`, `CH-6300`, a 4-digit postcode
  followed by a Swiss town, `+41 …` phone numbers, `.ch` web or e-mail domains
* **keyword**: `Schweiz`, `Switzerland`, `CH-`, `Zug`, `Stans`, `Zürich`,
  `Luzern`, `Schwyz`, `Nidwalden`, plus the extended town list in `config.json`

Precautions against false positives (all configurable):

* Whole-word matching, so `Zug` does not match *Bezug* or *im Zuge*.
* `CH-` only matches in capitals, so *Bosch-Gruppe* does not trigger.
* Towns match in their exact case or in ALL CAPS.
* `swiss_exclude` removes *Sächsische/Fränkische/Holsteinische … Schweiz*,
  *Zug um Zug*, *Basel III* and similar phrases.
* `swiss_ambiguous_cities` (Cham, Rheinfelden, Laufenburg, …) only count when
  another Swiss signal appears within 120 characters.

Try the filter on any text:

```bash
./venv/bin/python radar.py --check tests/fixtures/neueintragung_ch_director.txt
```

## Deduplication (SQLite)

* `processed`: every announcement UID (`hrbk:<handelsregister id>`,
  `oc:de:<number>`, `file:<sha1>`), with court, HRB number, company name and
  the step results. Announcements already in this table are skipped, including
  the costly detail requests to handelsregister.de.
* `alerts`: one row per alert, keyed by *court + register number* **and** the
  normalised company name. HRB numbers are only unique per court. With
  `alert_once_per_company: true` a company triggers only one alert.
* An alert is written to the database in the same transaction that marks the
  announcement processed, and is sent afterwards. If Discord is unreachable,
  the alert stays `pending` and is retried at the start of the next run.

```bash
sqlite3 data/hydra_radar.sqlite3 "SELECT created_at, company_name, register_number, status FROM alerts;"
```

## Discord alert

Each alert is an embed containing the company name, register number, court,
**the exact Swiss connection** (summary plus the surrounding text with the
match in «»), the sector keywords and announcement type, and the registration
text. If the text exceeds `max_text_chars`, the full text is attached as a
`.txt` file. Discord 429 rate limits are handled with `retry_after`.

## Installation on Debian (headless)

```bash
# 1. copy the hydra-radar/ folder to the server, then as root:
cd hydra-radar
sh deploy/install.sh            # python3-venv, user "hydra", /opt/hydra-radar, venv, cron file

# 2. configure (or set HYDRA_DISCORD_WEBHOOK / OPENCORPORATES_API_TOKEN instead)
nano /opt/hydra-radar/config.json          # discord.webhook_url

# 3. test
runuser -u hydra -- /opt/hydra-radar/venv/bin/python /opt/hydra-radar/radar.py --test-webhook
runuser -u hydra -- /opt/hydra-radar/venv/bin/python /opt/hydra-radar/radar.py --dry-run --days 14
```

Manual setup without the installer:

```bash
apt install python3 python3-venv
python3 -m venv /opt/hydra-radar/venv
/opt/hydra-radar/venv/bin/pip install -r /opt/hydra-radar/requirements.txt
```

### Cron job

`deploy/install.sh` installs `/etc/cron.d/hydra-radar`:

```cron
MAILTO=root
17 7 * * *  hydra  cd /opt/hydra-radar && ./venv/bin/python radar.py --config config.json
```

If you prefer a user crontab (`crontab -e` as user `hydra`), drop the user
field:

```cron
17 7 * * * cd /opt/hydra-radar && ./venv/bin/python radar.py --config config.json
```

Notes:

* Each run re-checks the last `lookback_days` (default 4) because snapshots
  arrive late. The database prevents duplicate alerts, so a second evening run
  is safe (commented out in the cron file).
* The script holds its own lock (`data/radar.lock`), so overlapping runs exit
  with code 3. No `flock` wrapper is needed.
* Without a TTY only warnings and errors are written to stderr, so cron only
  sends mail when something is wrong. Full logs are in `data/logs/radar.log`
  (rotating, 10 × 5 MB).
* Exit codes: `0` ok, `1` a source or delivery failed (pending alerts are
  retried next run), `2` config error, `3` already running.
* With `handelsregister` enabled, a run sleeps to stay under 55 requests/hour,
  so ~150 new announcements take ~3 h. That is fine for a nightly job; use the
  snapshot source for fast runs.

## CLI

```
radar.py [-c config.json] [--dry-run] [--days N | --since D --until D]
         [--source NAME ...] [--reprocess] [--no-enrich]
         [--test-webhook] [--check FILE] [-v] [-q]
```

`--source` forces a source even if it is disabled in the config.
`--reprocess` ignores the dedup tables, which is useful after changing
keywords. Combine it with `--dry-run`.

## Local inbox JSON format

```json
[{"uid": "provider-123", "company_name": "X Energie GmbH", "court": "Amtsgericht München",
  "register_number": "HRB 123456", "published": "2026-11-17", "type": "Neueintragung",
  "purpose": "Energieversorgung …", "text": "full registration text …"}]
```

Records in the coezbek snapshot schema (`details`, `registernummer`, …) are
also accepted.

## Legal / ethics

The tool only reads public register publications. Respect the handelsregister.de
terms of use (60 retrievals per hour) and the OpenCorporates licence. Alerts
contain personal data (names, dates of birth, places of residence), so keep
the Discord channel private and process the data in line with the GDPR.
