#!/usr/bin/env python3
"""
Hydra-Radar - OSINT monitor for German commercial register publications.

Pipeline ("the funnel"):
    sources  ->  Step 1: sector filter (energy)  ->  Step 2: Swiss-connection
    detection (text + optional OpenCorporates enrichment)  ->  SQLite dedup
    ->  Discord webhook alert

Designed to run unattended once or twice a day from cron on a headless
Debian server. All behaviour is driven by config.json (see README.md).

Exit codes: 0 = ok, 1 = finished but at least one source/alert failed,
            2 = configuration / startup error, 3 = another run holds the lock.
"""
from __future__ import annotations

import argparse
import copy
import dataclasses
import datetime as dt
import hashlib
import html
import json
import logging
import logging.handlers
import os
import random
import re
import sqlite3
import sys
import time
import unicodedata
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, Iterator, List, Optional, Sequence, Tuple
from urllib.parse import quote

import requests
from bs4 import BeautifulSoup
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

__version__ = "1.0.0"

log = logging.getLogger("hydra_radar")
BASE_DIR = Path(__file__).resolve().parent

# --------------------------------------------------------------------------
# Defaults. config.json is deep-merged on top of this, so it may be partial.
# --------------------------------------------------------------------------
DEFAULT_CONFIG: Dict[str, Any] = {
    "discord": {
        "webhook_url": "",
        "username": "Hydra-Radar",
        "mention": "",
        "max_text_chars": 3000,
        "attach_full_text": True,
    },
    "database": {"path": "data/hydra_radar.sqlite3"},
    "logging": {"dir": "data/logs", "level": "INFO", "max_bytes": 5_242_880, "backups": 10},
    "run": {
        "lookback_days": 4,
        "alert_once_per_company": True,
        "require_event_match": False,
        "max_findings_per_alert": 15,
        "lock_file": "data/radar.lock",
    },
    "http": {
        "timeout": 30,
        "retries": 4,
        "backoff_factor": 2.0,
        "min_delay_seconds": 1.0,
        "user_agents": [
            "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
        ],
    },
    "sources": {
        "github_snapshots": {"enabled": True, "url_template": ""},
        "handelsregister": {"enabled": False},
        "register_search": {"enabled": False},
        "opencorporates": {"enabled": False},
        "local": {"enabled": False},
    },
    "detection": {
        "context_chars": 90,
        "sector_keywords": ["Energieversorgung", "Energiebelieferung", "Strom", "Gas"],
        "sector_exclude": [],
        "event_patterns": {},
        "swiss_keywords": ["Schweiz", "Switzerland", "CH-", "Zug", "Stans", "Zürich",
                           "Luzern", "Schwyz", "Nidwalden"],
        "swiss_cities": [],
        "swiss_ambiguous_cities": [],
        "swiss_exclude": [],
        "swiss_legal_forms": ["AG", "SA", "GmbH", "Sàrl", "Sagl", "S.A."],
        "swiss_places_file": "swiss_places.json",
    },
}

GITHUB_SNAPSHOT_TEMPLATE = (
    "https://raw.githubusercontent.com/coezbek/registerbekanntmachungen/main/"
    "db/{yyyy}-{mm}/registerbekanntmachungen-{date}.json"
)
ENV_WEBHOOK = "HYDRA_DISCORD_WEBHOOK"
ENV_OC_TOKEN = "OPENCORPORATES_API_TOKEN"

REGISTER_TYPES = r"(?:HRA|HRB|GnR|GsR|PR|VR)"
REGISTER_RE = re.compile(
    rf"(?P<court>Amtsgericht\s+[A-ZÄÖÜ][\wäöüß.\-]*(?:\s+[A-ZÄÖÜ(][\wäöüß.\-()]*){{0,3}}?)\s+"
    rf"(?P<type>{REGISTER_TYPES})\s+(?P<num>\d+(?:\s?[A-Z]{{1,2}}\b)?)"
)
DOB_RE = re.compile(r"\*\s?(\d{1,2}\.\d{1,2}\.\d{4})")


class ConfigError(Exception):
    pass


class SourceError(Exception):
    pass


class NotifyError(Exception):
    pass


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------
def deep_merge(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    out = copy.deepcopy(base)
    for key, value in (override or {}).items():
        if key.startswith("_"):  # "_comment" keys in config.json
            continue
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = deep_merge(out[key], value)
        else:
            out[key] = copy.deepcopy(value)
    return out


def normalize_text(value: Optional[str]) -> str:
    """Unescape entities, NFC-normalise umlauts, unify whitespace."""
    if not value:
        return ""
    s = html.unescape(str(value))
    s = unicodedata.normalize("NFC", s)
    s = s.replace(" ", " ").replace(" ", " ").replace(" ", " ")
    s = s.replace("\r\n", "\n").replace("\r", "\n")
    s = re.sub(r"[ \t\f\v]+", " ", s)
    s = re.sub(r" *\n *", "\n", s)
    s = re.sub(r"\n{3,}", "\n\n", s)
    return s.strip()


def norm_key(value: str) -> str:
    s = unicodedata.normalize("NFKD", value or "").encode("ascii", "ignore").decode().lower()
    return re.sub(r"[^a-z0-9]+", "", s)


def sha1(*parts: str) -> str:
    return hashlib.sha1("\x1f".join(parts).encode("utf-8")).hexdigest()


def utcnow() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def daterange(start: dt.date, end: dt.date) -> Iterator[dt.date]:
    day = start
    while day <= end:
        yield day
        day += dt.timedelta(days=1)


def parse_date(value: str) -> dt.date:
    for fmt in ("%Y-%m-%d", "%d.%m.%Y"):
        try:
            return dt.datetime.strptime(value, fmt).date()
        except ValueError:
            pass
    raise argparse.ArgumentTypeError(f"invalid date {value!r} (use YYYY-MM-DD or DD.MM.YYYY)")


def truncate(text: str, limit: int, suffix: str = "…") -> str:
    if len(text) <= limit:
        return text
    return text[: max(0, limit - len(suffix))].rstrip() + suffix


def discord_escape(text: str) -> str:
    return re.sub(r"([\\*_~`|>])", r"\\\1", text)


def extract_register(text: str) -> Tuple[str, str, str]:
    """Return (court, register_type, 'HRB 12345') found in free text, or empties."""
    m = REGISTER_RE.search(text or "")
    if not m:
        return "", "", ""
    return m.group("court").strip(), m.group("type"), f"{m.group('type')} {m.group('num').strip()}"


# --------------------------------------------------------------------------
# Data model
# --------------------------------------------------------------------------
@dataclasses.dataclass
class Announcement:
    uid: str
    source: str
    company_name: str
    text: str
    published: str = ""
    court: str = ""
    register_type: str = ""
    register_number: str = ""
    announcement_type: str = ""
    seat: str = ""
    state: str = ""
    url: str = ""
    purpose: str = ""
    event_hint: str = ""
    meta: Dict[str, Any] = dataclasses.field(default_factory=dict)

    def __post_init__(self) -> None:
        self.company_name = normalize_text(self.company_name)
        self.text = normalize_text(self.text)
        self.purpose = normalize_text(self.purpose)
        if not self.register_number:
            court, rtype, number = extract_register(self.text)
            self.court = self.court or court
            self.register_type, self.register_number = rtype, number

    @property
    def company_key(self) -> str:
        if self.register_number and self.court:
            court = norm_key(re.sub(r"(?i)amtsgericht", "", self.court))
            return f"reg|{court}|{norm_key(self.register_number)}"
        return self.name_key

    @property
    def name_key(self) -> str:
        return "name|" + norm_key(self.company_name)

    @property
    def register_label(self) -> str:
        parts = [p for p in (self.register_number, self.court) if p]
        return " · ".join(parts) if parts else "n/a"


@dataclasses.dataclass
class Finding:
    kind: str      # person | entity | identifier | keyword
    summary: str   # human readable description of the Swiss connection
    match: str     # exact matched text
    context: str   # surrounding text with «match» marked
    origin: str = "text"

    def as_dict(self) -> Dict[str, str]:
        return dataclasses.asdict(self)


@dataclasses.dataclass
class Evaluation:
    sector_hits: List[str]
    events: List[str]
    findings: List[Finding]
    enrichment_text: str = ""

    @property
    def alert(self) -> bool:
        return bool(self.sector_hits and self.findings)


# --------------------------------------------------------------------------
# Detection logic
# --------------------------------------------------------------------------
Pattern = Tuple[str, "re.Pattern[str]"]


def compile_terms(terms: Iterable[str], mode: str) -> List[Pattern]:
    """Compile config terms.

    * ``re:<regex>`` -> regex, case-insensitive.
    * plain term, mode ``substring`` -> case-insensitive anywhere (catches
      compounds such as "Ökostrom", "Gasversorgung").
    * plain term, mode ``word`` -> must not be glued to other letters
      ("Zug" will not match "Bezug"). Capitalised terms match in their
      exact case or in ALL CAPS ("Thun"/"THUN" but not the verb "thun");
      all-uppercase terms ("CH-") only in caps, so "Bosch-..." is ignored.
    """
    compiled: List[Pattern] = []
    for raw in terms or []:
        term = str(raw)
        if not term.strip():
            continue
        try:
            if term.startswith("re:"):
                compiled.append((term, re.compile(term[3:], re.IGNORECASE)))
                continue
            t = term.strip()

            def esc(s: str) -> str:
                return re.escape(s).replace(r"\ ", r"\s+")

            body = esc(t)
            flags = re.IGNORECASE
            if mode == "word":
                letters = [c for c in t if c.isalpha()]
                if letters and all(c.isupper() for c in letters):
                    flags = 0
                elif t[:1].isupper():
                    body = f"(?:{esc(t)}|{esc(t.upper())})"
                    flags = 0
                if t[0].isalnum():
                    body = r"(?<![\w])" + body
                if t[-1].isalnum():
                    body = body + r"(?![\w])"
            compiled.append((t, re.compile(body, flags)))
        except re.error as exc:
            raise ConfigError(f"invalid detection pattern {term!r}: {exc}") from exc
    return compiled


def mask(text: str, patterns: Sequence[Pattern]) -> str:
    """Blank out excluded phrases while keeping string offsets stable."""
    for _, pat in patterns:
        text = pat.sub(lambda m: " " * len(m.group(0)), text)
    return text


def spans_overlap(span: Tuple[int, int], spans: Sequence[Tuple[int, int]]) -> bool:
    return any(span[0] < e and s < span[1] for s, e in spans)


CANTON_CODES = ("ZH", "BE", "LU", "UR", "SZ", "OW", "NW", "GL", "ZG", "FR", "SO", "BS", "BL", "SH",
                "AR", "AI", "SG", "GR", "AG", "TG", "TI", "VD", "VS", "NE", "GE", "JU")
# canton names that are also first names / German regions -> need corroboration
AMBIGUOUS_CANTON_NAMES = {"Uri", "Jura", "Wallis", "Berna"}
COUNTRY_RE = r"(?:Schweiz|Switzerland|Suisse|Svizzera|Svizra|Swiss|CH)"


class SwissGazetteer:
    """Every Swiss locality/municipality with postcodes and cantons, loaded from
    swiss_places.json (built by tools/build_swiss_places.py). Names flagged 'de'
    also exist as German places and are only trusted with extra evidence."""

    CLEAN_RE = [
        re.compile(rf"\s*[/,(]\s*{COUNTRY_RE}\s*\)?\s*$"),
        re.compile(rf"\s+{COUNTRY_RE}\s*$"),
        re.compile(r"^\s*(?:CH-?\s?)?\d{4}\s+"),
        re.compile(r"^\s*(?:in|wohnhaft\s+in)\s+", re.IGNORECASE),
    ]

    def __init__(self, path: Optional[Path]) -> None:
        self.places: Dict[str, Tuple[frozenset, bool]] = {}
        self.plz: Dict[str, List[str]] = {}
        self.cantons: Dict[str, List[str]] = {}
        self.shared_canton_names: set = set()
        self.max_tokens = 1
        if not path:
            return
        if not path.is_file():
            log.warning("Swiss gazetteer %s not found - only keyword/city lists are used", path)
            return
        data = json.loads(path.read_text(encoding="utf-8"))
        for name, rec in (data.get("places") or {}).items():
            cantons = frozenset(c for c in re.split(r"[,\s]+", rec.get("c", "")) if c)
            self.places[name] = (cantons, bool(rec.get("de")))
            for code in rec.get("p") or []:
                self.plz.setdefault(code, []).append(name)
            self.max_tokens = max(self.max_tokens, min(6, len(name.split())))
        for names in self.plz.values():
            names.sort(key=len, reverse=True)
        for code, rec in (data.get("cantons") or {}).items():
            self.cantons[code] = list(rec.get("names") or [])
            self.shared_canton_names.update(rec.get("shared_de") or [])
        log.debug("Swiss gazetteer: %d places, %d postcodes", len(self.places), len(self.plz))

    def __bool__(self) -> bool:
        return bool(self.places)

    def lookup(self, fragment: str) -> Optional[Tuple[str, frozenset, bool]]:
        s = fragment.strip(" .;:")
        for rx in self.CLEAN_RE:
            s = rx.sub("", s)
        s = s.strip(" .;:")
        abbr = re.search(rf"\s*\(?\b({'|'.join(CANTON_CODES)})\)?$", s)
        candidates = [s]
        if abbr:
            candidates.append(s[:abbr.start()].strip())
        if "/" in s:  # bilingual names: "Biel/Bienne", "Disentis/Mustér"
            candidates += [p.strip() for p in s.split("/") if p.strip()]
        for cand in candidates:
            if cand in self.places:
                cantons, shared = self.places[cand]
                if abbr and abbr.group(1) in cantons:
                    shared = False  # "Wald ZH" is unambiguous
                return cand, cantons, shared
        return None

    def prefix(self, s: str) -> Optional[Tuple[str, frozenset, bool, int]]:
        """Longest Swiss place name at the start of s -> (name, cantons, shared, length)."""
        tokens = list(re.finditer(r"[^\s,;:()]+", s[:120]))
        for n in range(min(self.max_tokens, len(tokens)), 0, -1):
            end = tokens[n - 1].end()
            cand = s[:end].rstrip(".")
            if cand in self.places:
                cantons, shared = self.places[cand]
                return cand, cantons, shared, len(cand)
        return None


class Funnel:
    LEADING_NOISE = re.compile(
        r"^(?:(?:die|der|das|dem|den|des|the|firma|gesellschafterin|gesellschafter|"
        r"alleingesellschafterin|gründerin|inhaberin|komplementärin|zweigniederlassung|"
        r"übertragende|übernehmende|aufnehmende|rechtsträgerin|mit|von|und|als)\s+)+",
        re.IGNORECASE,
    )
    SEAT_RE = re.compile(
        r"(?:mit\s+(?:Sitz|Satzungssitz|Hauptsitz|Verwaltungssitz|Wohnsitz)\s+in"
        r"|wohnhaft\s+in|(?:Sitz|Wohnsitz)\s+(?:nach|in)|verlegt\s+nach"
        r"|domicilié(?:e)?\s+à|(?:avec\s+)?siège(?:\s+social)?\s+à|con\s+sede\s+a|residente\s+a)"
        r"\s+(?:CH-?\s?)?(?:(?P<plz>\d{4})\s+)?(?=[A-ZÄÖÜÉÈÂÎÔ])"
    )
    POSTCODE_RE = re.compile(r"(?<![\w.\-/+])(?P<ch>CH-?\s?)?(?P<plz>\d{4})\s+(?=[A-ZÄÖÜÉÈÂÎÔ])")

    def __init__(self, cfg: Dict[str, Any]) -> None:
        self.ctx = int(cfg.get("context_chars", 90))
        self.sector = compile_terms(cfg.get("sector_keywords"), "substring")
        self.sector_exclude = compile_terms(cfg.get("sector_exclude"), "substring")
        self.events = {
            name: compile_terms(pats, "substring")
            for name, pats in (cfg.get("event_patterns") or {}).items()
        }
        places_file = cfg.get("swiss_places_file")
        self.gaz = SwissGazetteer(Path(places_file) if places_file else None)

        canton_names = [n for names in self.gaz.cantons.values() for n in names]
        ambiguous_cantons = [n for n in canton_names
                             if n in self.gaz.shared_canton_names or n in AMBIGUOUS_CANTON_NAMES]
        strong_cantons = [n for n in canton_names if n not in ambiguous_cantons]

        cities = list(dict.fromkeys(cfg.get("swiss_cities") or []))
        self.swiss_keywords = compile_terms(cfg.get("swiss_keywords"), "word")
        self.swiss_cities = compile_terms(list(dict.fromkeys(cities + strong_cantons)), "word")
        self.ambiguous = compile_terms(
            list(dict.fromkeys(list(cfg.get("swiss_ambiguous_cities") or []) + ambiguous_cantons)), "word")
        self.swiss_exclude = compile_terms(cfg.get("swiss_exclude"), "substring")
        self.strong = self.swiss_keywords + self.swiss_cities

        def alt(names: Iterable[str]) -> str:
            return "|".join(sorted({re.escape(n).replace(r"\ ", r"\s+") for n in names},
                                   key=len, reverse=True)) or r"(?!x)x"

        curated = [c for c in cities + list(cfg.get("swiss_keywords") or [])
                   if not c.startswith("re:") and c[:1].isalpha() and c[0].isupper()
                   and not c.isupper() and c.lower() not in ("schweiz", "switzerland", "swiss", "suisse",
                                                             "svizzera", "kanton", "eidgenossenschaft")]
        self.curated_city_re = re.compile(rf"(?:{alt(curated)})(?![\w])")
        forms = alt(cfg.get("swiss_legal_forms") or ["AG"])
        seat_words = r"(?:mit\s+(?:Sitz|Satzungssitz|Hauptsitz|Verwaltungssitz)\s+in|in|aus)"
        self.entity_re = re.compile(
            rf"(?P<name>(?:[A-ZÄÖÜ0-9][\w&'’.+\-]*\s+(?:&\s+|und\s+)?){{1,7}}?(?:{forms}))(?![\w])"
            rf"(?:(?P<paren>\s*\(\s*{COUNTRY_RE}\s*\))"
            rf"|(?P<comma>\s*,\s*{COUNTRY_RE}(?![\w]))"
            rf"|(?P<law>\s+nach\s+schweizerischem\s+Recht)"
            rf"|(?:\s*,\s*|\s+{seat_words}\s+)(?:CH-?\s?)?(?:(?P<plz>\d{{4}})\s+)?(?=[A-ZÄÖÜÉÈÂÎÔ]))"
        )
        self.canton_ref_re = re.compile(
            rf"(?:Kantons?|Kt\.|[Cc]anton(?:e|s)?(?:\s+(?:de|du|des|di|del|dello))?|[Cc]anton\s+d['’])\s*"
            rf"(?P<c>{alt(canton_names + list(CANTON_CODES))})(?![\w])"
        )
        self.abbr_re = re.compile(rf"(?<![\w\-])(?P<open>\()?(?P<a>{'|'.join(CANTON_CODES)})(?P<close>\))?(?![\w\-])")
        self.identifiers: List[Tuple[str, "re.Pattern[str]"]] = [
            ("Swiss company UID", re.compile(r"(?<![\w])CHE[-\s]?\d{3}\.\d{3}\.\d{3}(?![\d])")),
            ("Swiss postcode", re.compile(r"(?<![\w])CH-\s?\d{4}(?!\d)")),
            ("Swiss phone number", re.compile(r"(?<![\w+])(?:\+|00)41[\s\-/]?\d{2}[\s\-/]?\d{3}")),
            ("Swiss web/e-mail domain",
             re.compile(r"(?:www\.|@|https?://)[\w.\-]+\.ch(?![\w.])", re.IGNORECASE)),
        ]
        if not self.gaz:  # fallback without gazetteer: postcode + curated city
            self.identifiers.append(("Swiss address", re.compile(rf"(?<![\d.])\d{{4}}\s+(?:{alt(curated)})(?![\w])")))

    # -- step 1 ------------------------------------------------------------
    def sector_hits(self, ann: Announcement) -> List[str]:
        text = "\n".join(p for p in (ann.company_name, ann.purpose, ann.text) if p)
        masked = mask(text, self.sector_exclude)
        hits: List[str] = []
        for label, pat in self.sector:
            m = pat.search(masked)
            if m:
                hits.append(m.group(0) if label.startswith("re:") else label)
        return list(dict.fromkeys(hits))

    def classify_events(self, ann: Announcement) -> List[str]:
        found = [ann.event_hint] if ann.event_hint else []
        text = "\n".join((ann.announcement_type, ann.text))
        for name, pats in self.events.items():
            if any(p.search(text) for _, p in pats):
                found.append(name)
        return list(dict.fromkeys(found))

    # -- step 2 helpers ----------------------------------------------------
    def _context(self, text: str, start: int, end: int) -> str:
        a, b = max(0, start - self.ctx), min(len(text), end + self.ctx)
        snippet = text[a:start] + "«" + text[start:end] + "»" + text[end:b]
        snippet = re.sub(r"\s+", " ", snippet).strip()
        return ("…" if a > 0 else "") + snippet + ("…" if b < len(text) else "")

    def swiss_signal(self, masked_fragment: str) -> Optional[str]:
        """Strong signal (country word, canton, curated city, identifier) in a fragment."""
        for _, pat in self.strong:
            m = pat.search(masked_fragment)
            if m:
                return m.group(0)
        for rx in [self.canton_ref_re] + [p for _, p in self.identifiers]:
            m = rx.search(masked_fragment)
            if m:
                return m.group(0)
        return None

    @staticmethod
    def _canton_label(cantons: frozenset) -> str:
        return "/".join(sorted(cantons))

    def _place_at(self, masked: str, pos: int, plz: Optional[str] = None) -> Optional[Tuple[str, str, int]]:
        """Validated Swiss place starting at masked[pos] -> (name, canton label, end).
        Places that also exist in Germany need a matching postcode, a canton
        abbreviation or a strong Swiss signal right after them."""
        m = self.curated_city_re.match(masked, pos)
        hit = self.gaz.prefix(masked[pos:]) if self.gaz else None
        if hit:
            name, cantons, shared, length = hit
            end = pos + length
            ok = (not shared) or (plz is not None and name in self.gaz.plz.get(plz, ())) \
                or bool(self.swiss_signal(masked[end:end + 60]))
            nxt = re.match(rf"\s*\(?({'|'.join(CANTON_CODES)})\)?(?![\w])", masked[end:])
            label = self._canton_label(cantons)
            if nxt and nxt.group(1) in cantons:
                ok, end, label = True, end + nxt.end(), nxt.group(1)
            if ok:
                return name, label, end
        if m:
            return m.group(0), "", m.end()
        return None

    def _location_part(self, masked_part: str) -> bool:
        if self.swiss_signal(masked_part):
            return True
        if not self.gaz:
            return False
        pm = re.search(r"(?<!\d)(\d{4})\s+(.+)$", masked_part)
        if pm and pm.group(2).strip(" .") in self.gaz.plz.get(pm.group(1), ()):
            return True
        hit = self.gaz.lookup(masked_part)
        return bool(hit and not hit[2])

    def _persons(self, text: str, masked: str) -> Iterator[Tuple[Finding, Tuple[int, int]]]:
        """Register-style person entries: 'Name, Vorname, Ort, *TT.MM.JJJJ' and
        'Name, Vorname, *TT.MM.JJJJ, Ort/Schweiz'. Ort can be any Swiss place."""
        role = ""
        for seg in re.finditer(r"[^;\n]+", masked):
            s0 = seg.start()
            pieces: List[Tuple[int, int]] = []
            last = 0
            seg_text = seg.group(0)
            for colon in re.finditer(r":\s", seg_text):
                label = seg_text[last:colon.start()].strip()
                if label and not DOB_RE.search(label):
                    label = re.split(r"[.;]\s+", label)[-1]
                    role = " ".join(label.split()[-4:])[:60]
                else:
                    pieces.append((last, colon.start()))
                last = colon.end()
            pieces.append((last, len(seg_text)))
            for ps, pe in pieces:
                piece_m = seg_text[ps:pe]
                if len(piece_m) > 260 or not DOB_RE.search(piece_m):
                    continue
                start, end = s0 + ps, s0 + pe
                piece = text[start:end]
                parts = [p.strip(" .") for p in piece.split(",")]
                masked_parts = [p.strip(" .") for p in piece_m.split(",")]
                keep = [i for i, p in enumerate(parts) if p]
                parts = [parts[i] for i in keep]
                masked_parts = [masked_parts[i] for i in keep]
                flagged = [i for i in range(2, len(parts))
                           if not DOB_RE.search(parts[i]) and self._location_part(masked_parts[i])]
                if not flagged:
                    continue
                # "Keller, Urs, Baar, Schweiz" -> show "Baar, Schweiz"
                for i in list(flagged):
                    if re.fullmatch(COUNTRY_RE, masked_parts[i]) and i - 1 >= 2 and i - 1 not in flagged \
                            and not DOB_RE.search(parts[i - 1]):
                        flagged.append(i - 1)
                flagged.sort()
                location = ", ".join(parts[i] for i in flagged)
                name = ", ".join(parts[:2])
                dob_m = DOB_RE.search(piece)
                dob = f" (*{dob_m.group(1)})" if dob_m else ""
                summary = f"{role or 'Person'}: {name}{dob} – residence: {location}"
                lead = len(piece) - len(piece.lstrip())
                yield (Finding("person", summary, piece.strip(),
                               self._context(text, start + lead, end)), (start, end))
            if not seg_text.strip():
                role = ""

    # -- step 2 ------------------------------------------------------------
    def swiss_findings(self, text: str, origin: str = "text") -> List[Finding]:
        text = normalize_text(text)
        if not text:
            return []
        masked = mask(text, self.swiss_exclude)
        findings: List[Finding] = []
        covered: List[Tuple[int, int]] = []

        def add(kind: str, summary: str, s: int, e: int) -> None:
            findings.append(Finding(kind, summary, text[s:e], self._context(text, s, e), origin))
            covered.append((s, e))

        for finding, span in self._persons(text, masked):
            finding.origin = origin
            findings.append(finding)
            covered.append(span)

        for m in self.entity_re.finditer(masked):
            if spans_overlap((m.start(), m.end()), covered):
                continue
            name = self.LEADING_NOISE.sub("", text[m.start("name"):m.end("name")]).strip()
            if m.group("paren") or m.group("comma") or m.group("law"):
                add("entity", f"Swiss legal entity: {name} ({text[m.end('name'):m.end()].strip(' ,()')})",
                    m.start(), m.end())
                continue
            place = self._place_at(masked, m.end(), m.group("plz"))
            if not place:
                continue
            pname, canton, end = place
            tail = re.match(rf"\s*[(/,]\s*{COUNTRY_RE}\)?", masked[end:])
            end += tail.end() if tail else 0
            add("entity", f"Swiss legal entity: {name} (seat: {pname}{' ' + canton if canton else ''})",
                m.start(), end)

        for m in self.SEAT_RE.finditer(masked):
            if spans_overlap((m.start(), m.end()), covered):
                continue
            place = self._place_at(masked, m.end(), m.group("plz"))
            if place:
                pname, canton, end = place
                add("location", f"Swiss seat/residence: {pname}{' (' + canton + ')' if canton else ''}",
                    m.start(), end)

        for m in self.canton_ref_re.finditer(masked):
            if not spans_overlap((m.start(), m.end()), covered):
                add("location", f"Swiss canton: {text[m.start():m.end()]}", m.start(), m.end())

        if self.gaz:
            for m in self.POSTCODE_RE.finditer(masked):
                if spans_overlap((m.start(), m.end()), covered):
                    continue
                for pname in self.gaz.plz.get(m.group("plz"), ()):
                    e = m.end() + len(pname)
                    if masked.startswith(pname, m.end()) and (e >= len(masked) or not masked[e].isalnum()):
                        canton = self._canton_label(self.gaz.places[pname][0])
                        add("identifier", f"Swiss address: {text[m.start():e]} ({canton})", m.start(), e)
                        break
            for m in self.abbr_re.finditer(masked):
                if spans_overlap((m.start(), m.end()), covered):
                    continue
                if m.group("a") == "AG" and not (m.group("open") and m.group("close")):
                    continue  # "Baden AG" is usually a legal form, "Baden (AG)" a canton
                before = masked[max(0, m.start() - 50):m.start()].rstrip()
                toks = list(re.finditer(r"[^\s,;:()]+", before))
                for n in range(min(4, len(toks)), 0, -1):
                    s = toks[-n].start()
                    cand = before[s:].strip()
                    info = self.gaz.places.get(cand)
                    if info and m.group("a") in info[0]:
                        abs_s = max(0, m.start() - 50) + s
                        add("location", f"Swiss place: {text[abs_s:m.end()]}", abs_s, m.end())
                        break

        for label, pat in self.identifiers:
            for m in pat.finditer(masked):
                if not spans_overlap((m.start(), m.end()), covered):
                    add("identifier", f"{label}: {text[m.start():m.end()]}", m.start(), m.end())

        # the same entity/person often appears in the header and in the body
        unique: Dict[Tuple[str, str], Finding] = {}
        counts: Dict[Tuple[str, str], int] = {}
        for f in findings:
            key = (f.kind, f.summary)
            counts[key] = counts.get(key, 0) + 1
            unique.setdefault(key, f)
        findings = []
        for key, f in unique.items():
            if counts[key] > 1:
                f.summary += f" ({counts[key]}×)"
            findings.append(f)

        keyword_hits: Dict[str, List[Tuple[int, int]]] = {}
        for label, pat in self.strong:
            for m in pat.finditer(masked):
                span = (m.start(), m.end())
                if not spans_overlap(span, covered):
                    keyword_hits.setdefault(label, []).append(span)
        strong_positions = [s for spans in keyword_hits.values() for s in spans] + covered
        for label, pat in self.ambiguous:
            for m in pat.finditer(masked):
                span = (m.start(), m.end())
                if spans_overlap(span, covered):
                    continue
                if any(abs(s - span[0]) <= 120 for s, _ in strong_positions):
                    keyword_hits.setdefault(label, []).append(span)
        for label, spans in keyword_hits.items():
            s, e = spans[0]
            count = f" ({len(spans)}×)" if len(spans) > 1 else ""
            findings.append(Finding("keyword", f"Swiss keyword “{text[s:e]}”{count}",
                                    text[s:e], self._context(text, s, e), origin))
        return findings

    def evaluate(self, ann: Announcement, enricher: Optional["OpenCorporatesClient"] = None) -> Evaluation:
        hits = self.sector_hits(ann)
        events = self.classify_events(ann)
        if not hits:
            return Evaluation([], events, [])
        findings = self.swiss_findings(
            "\n".join(p for p in (ann.company_name, ann.purpose, ann.text) if p), "text")
        extra = ""
        if enricher is not None:
            try:
                extra = enricher.enrich(ann) or ""
            except Exception as exc:  # enrichment must never kill the run
                log.warning("OpenCorporates enrichment failed for %s: %s", ann.company_name, exc)
            if extra:
                seen = {f.match for f in findings}
                findings += [f for f in self.swiss_findings(extra, "opencorporates")
                             if f.match not in seen]
        return Evaluation(hits, events, findings, extra)


# --------------------------------------------------------------------------
# HTTP layer: retries, rate limiting, User-Agent rotation
# --------------------------------------------------------------------------
class RateLimiter:
    def __init__(self, per_hour: float = 0, min_delay: float = 0.0, jitter: float = 0.25) -> None:
        interval = 3600.0 / per_hour if per_hour and per_hour > 0 else 0.0
        self.interval = max(interval, float(min_delay or 0))
        self.jitter = jitter
        self._next = 0.0

    def wait(self) -> None:
        now = time.monotonic()
        if self._next > now:
            time.sleep(self._next - now)
        self._next = time.monotonic() + self.interval * random.uniform(1.0, 1.0 + self.jitter)


class HttpClient:
    """One requests.Session per source. A random User-Agent is drawn from the
    configured pool for every new client (= per source and run); it stays
    fixed within the session because JSF/PrimeFaces sites bind the ViewState
    to the session."""

    def __init__(self, cfg: Dict[str, Any], limiter: Optional[RateLimiter] = None) -> None:
        self.timeout = float(cfg.get("timeout", 30))
        self.limiter = limiter or RateLimiter(0, cfg.get("min_delay_seconds", 1.0))
        agents = [a for a in cfg.get("user_agents") or [] if a.strip()]
        self.user_agent = random.choice(agents) if agents else f"Hydra-Radar/{__version__}"
        retry = Retry(
            total=int(cfg.get("retries", 4)),
            connect=int(cfg.get("retries", 4)),
            read=int(cfg.get("retries", 4)),
            backoff_factor=float(cfg.get("backoff_factor", 2.0)),
            status_forcelist=(429, 500, 502, 503, 504),
            allowed_methods=frozenset({"GET", "POST"}),
            respect_retry_after_header=True,
            raise_on_status=False,
        )
        self.session = requests.Session()
        adapter = HTTPAdapter(max_retries=retry)
        self.session.mount("https://", adapter)
        self.session.mount("http://", adapter)
        self.session.headers.update({
            "User-Agent": self.user_agent,
            "Accept-Language": "de-DE,de;q=0.9,en;q=0.5",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,application/json;q=0.8,*/*;q=0.7",
        })
        log.debug("HTTP client using User-Agent: %s", self.user_agent)

    def request(self, method: str, url: str, **kwargs: Any) -> requests.Response:
        self.limiter.wait()
        kwargs.setdefault("timeout", self.timeout)
        resp = self.session.request(method, url, **kwargs)
        log.debug("%s %s -> %s (%d bytes)", method, url.split("?")[0], resp.status_code, len(resp.content))
        return resp

    def get(self, url: str, **kwargs: Any) -> requests.Response:
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs: Any) -> requests.Response:
        return self.request("POST", url, **kwargs)


# --------------------------------------------------------------------------
# Sources
# --------------------------------------------------------------------------
KnownFn = Callable[[str], bool]


class Source:
    name = "base"

    def __init__(self, cfg: Dict[str, Any], http_cfg: Dict[str, Any]) -> None:
        self.cfg = cfg
        self.http_cfg = http_cfg

    def fetch(self, since: dt.date, until: dt.date, is_known: KnownFn) -> Iterator[Announcement]:
        raise NotImplementedError

    def attach_db(self, db: "Database", dry: bool) -> None:
        """Sources that keep their own state get the database here."""

    def commit(self, processed_uids: Iterable[str]) -> None:
        """Called after a successful (non-dry) run."""


def parse_register_line(line: str) -> Dict[str, str]:
    """'Bayern Amtsgericht München HRB 12345' -> parts."""
    m = re.match(rf"^(?P<state>.*?)\s*Amtsgericht\s+(?P<court>.*?)\s+(?P<rt>{REGISTER_TYPES})\s+"
                 rf"(?P<num>\d+(?:\s+[A-Z]{{1,2}})?)\b", line or "")
    if not m:
        return {}
    return {"state": m.group("state").strip(), "court": f"Amtsgericht {m.group('court').strip()}",
            "register_type": m.group("rt"), "register_number": f"{m.group('rt')} {m.group('num')}"}


def announcement_from_rbk(item: Dict[str, Any], source: str, url: str = "") -> Announcement:
    """Map a record in the registerbekanntmachungen JSON schema (also produced
    by HandelsregisterSource) to an Announcement."""
    rid = str(item.get("id") or "").strip()
    text = item.get("details") or item.get("original_text") or ""
    uid = f"hrbk:{rid}" if rid else "hrbk:" + sha1(
        str(item.get("date")), str(item.get("registernummer")), str(item.get("type")), text[:500])
    return Announcement(
        uid=uid,
        source=source,
        company_name=item.get("company_name") or "",
        text=text,
        published=str(item.get("date") or ""),
        court=item.get("amtsgericht") or item.get("court") or "",
        register_type=item.get("registerart") or "",
        register_number=item.get("registernummer") or item.get("registernumber") or "",
        announcement_type=item.get("type") or "",
        seat=item.get("company_seat") or "",
        state=item.get("state") or "",
        url=url,
    )


class GitHubSnapshotSource(Source):
    """Daily JSON snapshots of handelsregister.de 'Registerbekanntmachungen'
    maintained at github.com/coezbek/registerbekanntmachungen. Puts zero load
    on handelsregister.de; usually lags 1-3 days."""

    name = "github_snapshots"

    def fetch(self, since: dt.date, until: dt.date, is_known: KnownFn) -> Iterator[Announcement]:
        http = HttpClient(self.http_cfg)
        tmpl = self.cfg.get("url_template") or GITHUB_SNAPSHOT_TEMPLATE
        for day in daterange(since, until):
            url = tmpl.format(date=day.isoformat(), yyyy=f"{day.year:04d}", mm=f"{day.month:02d}",
                              dd=f"{day.day:02d}")
            try:
                resp = http.get(url)
            except requests.RequestException as exc:
                raise SourceError(f"snapshot {day}: {exc}") from exc
            if resp.status_code == 404:
                log.info("[%s] no snapshot for %s yet", self.name, day)
                continue
            if resp.status_code != 200:
                raise SourceError(f"snapshot {day}: HTTP {resp.status_code}")
            try:
                data = resp.json()
            except ValueError as exc:
                raise SourceError(f"snapshot {day}: invalid JSON") from exc
            items = data.get("announcements") or []
            log.info("[%s] %s: %d announcements", self.name, day, len(items))
            for item in items:
                try:
                    yield announcement_from_rbk(item, self.name, url)
                except Exception as exc:
                    log.warning("[%s] skipping malformed record %r: %s", self.name, item.get("id"), exc)


class HandelsregisterSource(Source):
    """Direct scraper for https://www.handelsregister.de/rp_web/xhtml/bekanntmachungen.xhtml
    (JSF/PrimeFaces). The portal's terms limit automated use to 60 searches/
    retrievals per hour; the built-in rate limiter enforces max_requests_per_hour.
    Only the last ~8 weeks are online."""

    name = "handelsregister"
    PAGE = "https://www.handelsregister.de/rp_web/xhtml/bekanntmachungen.xhtml"
    FORM = "bekanntMachungenForm"
    ONCLICK_RE = re.compile(r"fireBekanntmachung\d*\(\s*'([^']*)'\s*,\s*'([^']*)'\s*\)")
    AJAX_HEADERS = {
        "Faces-Request": "partial/ajax",
        "X-Requested-With": "XMLHttpRequest",
        "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
        "Accept": "application/xml, text/xml, */*; q=0.01",
    }

    def fetch(self, since: dt.date, until: dt.date, is_known: KnownFn) -> Iterator[Announcement]:
        page = self.cfg.get("page_url") or self.PAGE
        limiter = RateLimiter(float(self.cfg.get("max_requests_per_hour", 55)),
                              self.http_cfg.get("min_delay_seconds", 1.0))
        http = HttpClient(self.http_cfg, limiter)
        max_details = int(self.cfg.get("max_details_per_run", 400))
        earliest = dt.date.today() - dt.timedelta(days=55)
        if since < earliest:
            log.info("[%s] only ~8 weeks are online, clamping start to %s", self.name, earliest)
            since = earliest
        if since > until:
            return

        resp = http.get(page)
        soup = BeautifulSoup(resp.text, "lxml")
        form = soup.find("form", id=self.FORM) if resp.status_code == 200 else None
        if form is None:
            # the portal rejects deep links (HTTP 400) - navigate like a browser
            log.debug("[%s] direct URL refused (HTTP %s), navigating via start page", self.name, resp.status_code)
            start = http.get(RegisterPortal.BASE + "/rp_web/welcome.xhtml")
            navi = BeautifulSoup(start.text, "lxml").find("form", id="naviForm")
            if navi is None:
                raise SourceError("navigation form not found - portal layout changed?")
            data = RegisterPortal._hidden(navi)
            data.update({"naviForm:bekanntmachungenLink": "naviForm:bekanntmachungenLink",
                         "target": "bekanntmachungenLink"})
            resp = http.post(RegisterPortal.BASE + navi["action"], data=data)
            soup = BeautifulSoup(resp.text, "lxml")
            form = soup.find("form", id=self.FORM)
            if form is None:
                raise SourceError("announcement search form not found - page layout changed?")
        if form.get("action"):
            page = RegisterPortal.BASE + form["action"]
        fields = self.serialize_form(form)
        remote_id = self.find_remote_command(soup, resp.text)
        fields[f"{self.FORM}:datum_von_input"] = since.strftime("%d.%m.%Y")
        fields[f"{self.FORM}:datum_bis_input"] = until.strftime("%d.%m.%Y")
        button = f"{self.FORM}:rrbSuche"

        ajax = dict(fields)
        ajax.update({"javax.faces.partial.ajax": "true", "javax.faces.source": button,
                     "javax.faces.partial.execute": "@all", "javax.faces.partial.render": self.FORM,
                     button: button})
        resp = http.post(page, data=ajax, headers=self.AJAX_HEADERS)
        result_html, view_state = self.parse_partial_response(resp.text)
        entries = self.parse_result_list(result_html)
        if not entries and "datalistId" not in result_html:
            log.debug("[%s] AJAX search returned no list, retrying as full POST", self.name)
            full = dict(fields)
            full[button] = ""
            resp = http.post(page, data=full)
            result_html, view_state = resp.text, None
            entries = self.parse_result_list(result_html)
        if view_state is None:
            vs = BeautifulSoup(result_html, "lxml").find("input", attrs={"name": "javax.faces.ViewState"})
            view_state = vs.get("value") if vs else fields.get("javax.faces.ViewState", "")
        log.info("[%s] %s..%s: %d announcements listed", self.name, since, until, len(entries))

        fetched = 0
        for entry in entries:
            uid = f"hrbk:{entry['id']}"
            if is_known(uid):
                continue
            if fetched >= max_details:
                log.warning("[%s] max_details_per_run=%d reached, rest follows next run",
                            self.name, max_details)
                break
            data = {"javax.faces.partial.ajax": "true", "javax.faces.source": remote_id,
                    "javax.faces.partial.execute": self.FORM, "javax.faces.partial.render": self.FORM,
                    remote_id: remote_id, "datum": entry["datum"], "id": entry["id"],
                    self.FORM: self.FORM, "javax.faces.ViewState": view_state}
            try:
                detail = http.post(page, data=data, headers=self.AJAX_HEADERS)
            except requests.RequestException as exc:
                log.warning("[%s] detail %s failed: %s", self.name, entry["id"], exc)
                continue
            fetched += 1
            text, new_vs = self.parse_detail(detail.text)
            view_state = new_vs or view_state
            if not text:
                log.warning("[%s] empty detail text for %s (%s)", self.name, entry["id"], entry.get("company_name"))
            entry["details"] = text or entry.get("original_text", "")
            yield announcement_from_rbk(entry, self.name, page)

    # -- parsing helpers (static so they are unit-testable) -----------------
    @staticmethod
    def serialize_form(form: Any) -> Dict[str, str]:
        data: Dict[str, str] = {}
        for inp in form.find_all("input"):
            name = inp.get("name")
            itype = (inp.get("type") or "text").lower()
            if not name or itype in ("submit", "button", "image", "reset", "file"):
                continue
            if itype in ("checkbox", "radio") and not inp.has_attr("checked"):
                continue
            data[name] = inp.get("value", "on" if itype in ("checkbox", "radio") else "")
        for sel in form.find_all("select"):
            name = sel.get("name")
            if not name:
                continue
            opt = sel.find("option", selected=True) or sel.find("option")
            data[name] = opt.get("value", opt.get_text(strip=True)) if opt else ""
        for ta in form.find_all("textarea"):
            if ta.get("name"):
                data[ta["name"]] = ta.get_text()
        return data

    @classmethod
    def find_remote_command(cls, soup: Any, raw: str) -> str:
        for script in soup.find_all("script"):
            if script.get("id") and "fireBekanntmachung" in (script.string or script.get_text() or ""):
                return script["id"]
        m = re.search(r"fireBekanntmachung\d*\s*=\s*function.*?PrimeFaces\.ab\(\s*\{\s*s\s*:\s*[\"']([^\"']+)",
                      raw, re.DOTALL)
        if m:
            return m.group(1)
        m = re.search(r"name\s*:\s*[\"']fireBekanntmachung\d*[\"'].{0,500}?\bs\s*:\s*[\"']([^\"']+)", raw, re.DOTALL)
        if m:
            return m.group(1)
        log.warning("remote command id not found, falling back to %s:j_idt114", cls.FORM)
        return f"{cls.FORM}:j_idt114"

    @staticmethod
    def parse_partial_response(body: str) -> Tuple[str, Optional[str]]:
        if "<partial-response" not in body:
            return body, None
        soup = BeautifulSoup(body, "lxml-xml")
        html_parts, view_state = [], None
        for upd in soup.find_all("update"):
            uid = upd.get("id", "")
            if "ViewState" in uid:
                view_state = upd.get_text()
            else:
                html_parts.append(upd.get_text())
        return "\n".join(html_parts), view_state

    @classmethod
    def parse_result_list(cls, page_html: str) -> List[Dict[str, Any]]:
        soup = BeautifulSoup(page_html, "lxml")
        dl = soup.find("dl", id=re.compile(r"datalistId"))
        if dl is None:
            return []
        entries: List[Dict[str, Any]] = []
        current_date = ""
        for node in dl.find_all(["dt", "dd"], recursive=False):
            if node.name == "dt":
                try:
                    current_date = dt.datetime.strptime(node.get_text(strip=True), "%d.%m.%Y").date().isoformat()
                except ValueError:
                    current_date = node.get_text(strip=True)
                continue
            for a in node.find_all("a"):
                m = cls.ONCLICK_RE.search(a.get("onclick", ""))
                if not m:
                    continue
                lines = [ln.strip() for ln in a.get_text("\n").split("\n") if ln.strip()]
                if lines and lines[0].strip("–- ").lower() == "gelöscht":
                    lines = lines[1:]
                entry: Dict[str, Any] = {"date": current_date, "datum": m.group(1), "id": m.group(2),
                                         "original_text": "\n".join(lines),
                                         "type": lines[0] if lines else ""}
                reg = parse_register_line(lines[1]) if len(lines) > 1 else {}
                entry.update({"state": reg.get("state", ""), "amtsgericht": reg.get("court", ""),
                              "registernummer": reg.get("register_number", ""),
                              "registerart": reg.get("register_type", "")})
                name_line = lines[2] if len(lines) > 2 else ""
                name, _, seat = name_line.rpartition(" – ") if " – " in name_line else (name_line, "", "")
                entry["company_name"], entry["company_seat"] = name.strip(), seat.strip()
                entries.append(entry)
        return entries

    @staticmethod
    def parse_detail(body: str) -> Tuple[str, Optional[str]]:
        content, view_state = HandelsregisterSource.parse_partial_response(body)
        soup = BeautifulSoup(content, "lxml")
        panel = soup.find(id=re.compile(r"(?:rrb|srb)Panel_content$"))
        if panel is None:
            return "", view_state
        return normalize_text(panel.get_text("\n")), view_state


class OpenCorporatesClient:
    """Thin OpenCorporates API v0.4 client (API token required)."""

    API = "https://api.opencorporates.com/v0.4"

    def __init__(self, cfg: Dict[str, Any], http_cfg: Dict[str, Any]) -> None:
        self.token = os.environ.get(ENV_OC_TOKEN) or cfg.get("api_token") or ""
        if not self.token:
            raise ConfigError("OpenCorporates enabled but no api_token (config or $%s)" % ENV_OC_TOKEN)
        self.http = HttpClient(http_cfg, RateLimiter(float(cfg.get("max_requests_per_hour", 300)),
                                                     http_cfg.get("min_delay_seconds", 1.0)))
        self.max_enrich = int(cfg.get("max_enrichments_per_run", 50))
        self.enriched = 0

    def _get(self, path: str, **params: Any) -> Dict[str, Any]:
        params["api_token"] = self.token
        resp = self.http.get(f"{self.API}{path}", params=params, headers={"Accept": "application/json"})
        if resp.status_code == 401:
            raise SourceError("OpenCorporates rejected the API token (401)")
        if resp.status_code == 403:
            raise SourceError("OpenCorporates quota exceeded or access denied (403)")
        if resp.status_code != 200:
            raise SourceError(f"OpenCorporates HTTP {resp.status_code} for {path}")
        return resp.json().get("results") or {}

    def search(self, **params: Any) -> Dict[str, Any]:
        return self._get("/companies/search", **params)

    def company(self, jurisdiction: str, number: str) -> Dict[str, Any]:
        return (self._get(f"/companies/{quote(jurisdiction)}/{quote(number, safe='')}")
                .get("company") or {})

    @staticmethod
    def company_text(c: Dict[str, Any]) -> str:
        lines = []
        jur_label = {"ch": "Switzerland"}
        for key in ("registered_address_in_full", "company_type", "current_status"):
            if c.get(key):
                lines.append(f"{key}: {c[key]}")
        for prev in c.get("previous_names") or []:
            lines.append(f"previous name: {prev.get('company_name', '')}")
        for code in c.get("industry_codes") or []:
            ic = code.get("industry_code") or code
            lines.append(f"industry: {ic.get('description', '')}")
        for rel in ("home_company", "controlling_entity", "ultimate_beneficial_owner"):
            other = c.get(rel)
            if isinstance(other, dict) and other:
                jur = (other.get("jurisdiction_code") or "").lower()
                lines.append(f"{rel}: {other.get('name', '')} (jurisdiction: {jur}"
                             f"{' / ' + jur_label[jur] if jur in jur_label else ''})")
        for item in c.get("officers") or []:
            o = item.get("officer") or item
            bits = [f"{o.get('position') or 'officer'}: {o.get('name', '')}"]
            for k in ("nationality", "address", "occupation", "date_of_birth"):
                if o.get(k):
                    bits.append(f"{k}: {o[k]}")
            if o.get("end_date"):
                bits.append(f"until {o['end_date']}")
            lines.append(", ".join(bits))
        return "\n".join(lines)

    def enrich(self, ann: Announcement) -> str:
        if self.enriched >= self.max_enrich:
            log.debug("OpenCorporates enrichment budget exhausted")
            return ""
        self.enriched += 1
        number, jur = ann.meta.get("oc_number"), ann.meta.get("oc_jurisdiction", "de")
        if not number:
            res = self.search(q=ann.company_name, jurisdiction_code="de", per_page=10)
            candidates = [c.get("company") or {} for c in res.get("companies") or []]
            digits = re.sub(r"\D", "", ann.register_number)
            pick = None
            for c in candidates:
                cn = c.get("company_number", "")
                if digits and re.search(rf"(?<!\d){digits}(?!\d)", cn) and \
                        (not ann.register_type or ann.register_type in cn):
                    pick = c
                    break
            if pick is None:
                pick = next((c for c in candidates if norm_key(c.get("name", "")) == norm_key(ann.company_name)), None)
            if pick is None:
                log.debug("OpenCorporates: no match for %s", ann.company_name)
                return ""
            number, jur = pick["company_number"], pick.get("jurisdiction_code", "de")
        details = self.company(jur, number)
        text = self.company_text(details)
        log.debug("OpenCorporates enrichment for %s: %d chars", ann.company_name, len(text))
        return text


class OpenCorporatesSource(Source):
    """Newly incorporated German companies via OpenCorporates search
    (name queries + incorporation_date range). Covers 'Neueintragungen'."""

    name = "opencorporates"

    def __init__(self, cfg: Dict[str, Any], http_cfg: Dict[str, Any],
                 client: Optional[OpenCorporatesClient] = None) -> None:
        super().__init__(cfg, http_cfg)
        self.client = client or OpenCorporatesClient(cfg, http_cfg)

    def fetch(self, since: dt.date, until: dt.date, is_known: KnownFn) -> Iterator[Announcement]:
        seen: set = set()
        for query in self.cfg.get("name_queries") or ["Energie"]:
            for page in range(1, int(self.cfg.get("max_pages", 5)) + 1):
                res = self.client.search(q=query, jurisdiction_code="de", per_page=100, page=page,
                                         incorporation_date=f"{since.isoformat()}:{until.isoformat()}",
                                         order="incorporation_date")
                companies = res.get("companies") or []
                log.info("[%s] q=%r page %d: %d companies", self.name, query, page, len(companies))
                for item in companies:
                    c = item.get("company") or {}
                    number, jur = c.get("company_number", ""), c.get("jurisdiction_code", "de")
                    uid = f"oc:{jur}:{number}"
                    if not number or uid in seen or is_known(uid):
                        continue
                    seen.add(uid)
                    rt, num = "", ""
                    m = re.search(rf"({REGISTER_TYPES})[\s_]?(\d+\s?[A-Z]?)", number)
                    if m:
                        rt, num = m.group(1), f"{m.group(1)} {m.group(2).strip()}"
                    text = f"{c.get('name', '')}\n" + OpenCorporatesClient.company_text(c)
                    yield Announcement(
                        uid=uid, source=self.name, company_name=c.get("name", ""), text=text,
                        published=c.get("incorporation_date") or "", register_type=rt,
                        register_number=num, announcement_type="Neueintragung (OpenCorporates)",
                        seat=c.get("registered_address_in_full") or "", url=c.get("opencorporates_url", ""),
                        event_hint="Neueintragung", meta={"oc_number": number, "oc_jurisdiction": jur},
                    )
                if page >= int(res.get("total_pages") or 1):
                    break


class LocalInboxSource(Source):
    """Reads announcement texts dropped into a folder (.txt, .html, .xml, .json),
    e.g. exported register prints (CD/AD/SI) or texts from other tools."""

    name = "local"
    SUFFIXES = {".txt", ".html", ".htm", ".xml", ".json"}

    def __init__(self, cfg: Dict[str, Any], http_cfg: Dict[str, Any]) -> None:
        super().__init__(cfg, http_cfg)
        self.inbox = Path(cfg.get("inbox_dir") or "data/inbox")
        self.archive = Path(cfg.get("archive_dir") or self.inbox / "processed")
        self._files: Dict[str, Path] = {}

    def fetch(self, since: dt.date, until: dt.date, is_known: KnownFn) -> Iterator[Announcement]:
        if not self.inbox.is_dir():
            log.info("[%s] inbox %s does not exist", self.name, self.inbox)
            return
        for path in sorted(p for p in self.inbox.iterdir() if p.is_file() and p.suffix.lower() in self.SUFFIXES):
            try:
                raw = path.read_text(encoding="utf-8", errors="replace")
                anns = list(self.parse_file(path, raw))
            except Exception as exc:
                log.warning("[%s] cannot parse %s: %s", self.name, path.name, exc)
                continue
            for ann in anns:
                self._files[ann.uid] = path
                yield ann

    def parse_file(self, path: Path, raw: str) -> Iterator[Announcement]:
        suffix = path.suffix.lower()
        if suffix == ".json":
            data = json.loads(raw)
            items = data.get("announcements") if isinstance(data, dict) and "announcements" in data else data
            for item in items if isinstance(items, list) else [items]:
                if not isinstance(item, dict):
                    continue
                if "details" in item or "registernummer" in item:
                    ann = announcement_from_rbk(item, self.name, str(path))
                else:
                    text = item.get("text", "")
                    ann = Announcement(
                        uid=item.get("uid") or "file:" + sha1(path.name, text),
                        source=self.name, company_name=item.get("company_name", ""), text=text,
                        published=item.get("published", ""), court=item.get("court", ""),
                        register_number=item.get("register_number", ""), purpose=item.get("purpose", ""),
                        announcement_type=item.get("type", ""), url=str(path))
                yield ann
            return
        if suffix in (".html", ".htm", ".xml"):
            parser = "lxml-xml" if suffix == ".xml" else "lxml"
            text = BeautifulSoup(raw, parser).get_text("\n")
        else:
            text = raw
        text = normalize_text(text)
        court, rtype, number = extract_register(text)
        name = self.guess_company_name(text) or path.stem
        yield Announcement(uid="file:" + sha1(path.name, text), source=self.name, company_name=name,
                           text=text, court=court, register_type=rtype, register_number=number,
                           url=str(path), published=dt.date.fromtimestamp(path.stat().st_mtime).isoformat())

    @staticmethod
    def guess_company_name(text: str) -> str:
        legal = re.compile(r"\b(GmbH|AG|KG|SE|UG|OHG|eG|e\.K\.|GmbH & Co\. KG|mbH)\b")
        for line in text.splitlines()[:15]:
            line = line.strip()
            if 3 < len(line) < 160 and legal.search(line) and "Amtsgericht" not in line:
                return line.split(" – ")[0].strip()
        return ""

    def commit(self, processed_uids: Iterable[str]) -> None:
        done = {self._files[u] for u in processed_uids if u in self._files}
        if not done:
            return
        self.archive.mkdir(parents=True, exist_ok=True)
        for path in done:
            try:
                path.rename(self.archive / path.name)
            except OSError as exc:
                log.warning("[%s] cannot archive %s: %s", self.name, path.name, exc)


class DocumentUnavailable(Exception):
    pass


LAENDER = ["Baden-Württemberg", "Bayern", "Berlin", "Brandenburg", "Bremen", "Hamburg", "Hessen",
           "Mecklenburg-Vorpommern", "Niedersachsen", "Nordrhein-Westfalen", "Rheinland-Pfalz", "Saarland",
           "Sachsen", "Sachsen-Anhalt", "Schleswig-Holstein", "Thüringen"]
# first letter of the portal's court code -> federal state
COURT_PREFIX_LAND = {"B": "Baden-Württemberg", "D": "Bayern", "F": "Berlin", "G": "Brandenburg", "H": "Bremen",
                     "K": "Hamburg", "M": "Hessen", "N": "Mecklenburg-Vorpommern", "P": "Niedersachsen",
                     "R": "Nordrhein-Westfalen", "T": "Rheinland-Pfalz", "U": "Sachsen", "V": "Saarland",
                     "W": "Sachsen-Anhalt", "X": "Schleswig-Holstein", "Y": "Thüringen"}


@dataclasses.dataclass
class PortalHit:
    index: str
    land: str
    court: str
    register_type: str
    register_number: str
    name: str
    seat: str
    status: str
    documents: Dict[str, str]

    @property
    def company_key(self) -> str:
        return f"reg|{norm_key(re.sub(r'(?i)amtsgericht', '', self.court))}|{norm_key(self.register_number)}"


class RegisterPortal:
    """Client for the 'Erweiterte Suche' of www.handelsregister.de (JSF/PrimeFaces).

    Verified against the live portal (Nov 2026): max. 100 hits per search (sorted
    alphabetically, then an error), max. 5 keywords, register numbers only exact,
    'mindestens ein Schlagwort' needs a register type/court/state. Documents
    (AD = current print as PDF, SI = structured content as XML) are not available
    at night (error A 450)."""

    BASE = "https://www.handelsregister.de"
    UNAVAILABLE = "Der Abruf für dieses Dokument ist zur Zeit nicht möglich"

    def __init__(self, http: HttpClient) -> None:
        self.http = http
        self.page = ""          # current HTML page
        self.on_form = False
        self.courts: Dict[str, str] = {}   # "München" -> "D2601"

    # -- navigation ----------------------------------------------------------
    @staticmethod
    def _hidden(form: Any) -> Dict[str, str]:
        return {i["name"]: i.get("value", "") for i in form.find_all("input") if i.get("name")
                and (i.get("type") or "").lower() in ("hidden", "")}

    def _post_form(self, form: Any, extra: Dict[str, str], **kw: Any) -> requests.Response:
        data = self._hidden(form)
        data.update(extra)
        resp = self.http.post(self.BASE + form["action"], data=data, **kw)
        if resp.status_code != 200:
            raise SourceError(f"handelsregister.de HTTP {resp.status_code}")
        return resp

    def open(self) -> None:
        resp = self.http.get(self.BASE + "/rp_web/welcome.xhtml")
        if resp.status_code != 200:
            raise SourceError(f"handelsregister.de start page HTTP {resp.status_code}")
        self.page, self.on_form = resp.text, False
        self.to_search_form()

    def to_search_form(self) -> None:
        if self.on_form:
            return
        soup = BeautifulSoup(self.page, "lxml")
        navi = soup.find("form", id="naviForm")
        if navi is None:
            raise SourceError("navigation form not found - portal layout changed?")
        link = "naviForm:erweiterteSucheLink"
        resp = self._post_form(navi, {link: link, "target": "erweiterteSucheLink"})
        soup = BeautifulSoup(resp.text, "lxml")
        if soup.find("form", id="form") is None:
            raise SourceError("search form not found - portal layout changed?")
        self.page, self.on_form = resp.text, True
        sel = soup.find("select", attrs={"name": "form:registergericht_input"})
        if sel is not None:
            self.courts = {o.get_text(strip=True): o.get("value") for o in sel.find_all("option") if o.get("value")}

    def court_code(self, court: str) -> str:
        name = re.sub(r"(?i)^amtsgericht\s+", "", court).strip()
        return self.courts.get(name, "")

    def courts_of(self, land: str) -> List[Tuple[str, str]]:
        return sorted((n, c) for n, c in self.courts.items() if COURT_PREFIX_LAND.get(c[:1]) == land)

    # -- search ----------------------------------------------------------------
    def search(self, keywords: str = "", option: str = "1", register_type: str = "", register_number: str = "",
               court_code: str = "", land: str = "") -> Tuple[List[PortalHit], bool, str]:
        self.to_search_form()
        form = BeautifulSoup(self.page, "lxml").find("form", id="form")
        data = {
            "form:schlagwoerter": keywords, "form:schlagwortOptionen": option, "form:NiederlassungSitz": "",
            "form:registerArt_input": register_type, "form:registerNummer": register_number,
            "form:registergericht_input": court_code, "form:rechtsform_input": "", "form:staat_input": "",
            "form:postleitzahl": "", "form:ort": "", "form:strasse": "",
            "form:ergebnisseProSeite_input": "100", "form:btnSuche": "",
        }
        if land:
            data[f"form:{land}_input"] = "on"
        resp = self._post_form(form, data)
        hits, too_many, error = self.parse_results(resp.text)
        soup = BeautifulSoup(resp.text, "lxml")
        self.page = resp.text
        self.on_form = soup.find("form", id="ergebnissForm") is None and soup.find("form", id="form") is not None
        return hits, too_many, error

    @staticmethod
    def parse_results(page: str) -> Tuple[List[PortalHit], bool, str]:
        soup = BeautifulSoup(page, "lxml")
        text = soup.get_text(" ", strip=True)
        too_many = "maximale Trefferanzahl" in text
        errors = [m.get_text(" ", strip=True) for m in soup.select(".ui-messages-error-summary, .ui-messages-error")]
        error = next((e for e in errors if e and "Trefferanzahl" not in e), "")
        hits: List[PortalHit] = []
        body = soup.find(id="ergebnissForm:selectedSuchErgebnisFormTable_data")
        for row in body.find_all("tr", recursive=False) if body else []:
            trs = row.find_all("tr")
            if len(trs) < 2:
                continue
            head = " ".join(c.get_text(" ", strip=True) for c in trs[0].find_all("td"))
            main = trs[1].find_all("td")
            if len(main) < 3:
                continue
            m = re.match(rf"^(?P<land>.*?)\s*(?P<court>Amtsgericht\s+.*?)\s+(?P<rt>{REGISTER_TYPES})\s+"
                         rf"(?P<num>\d+(?:\s+[A-Z]{{1,2}})?)\b", head)
            if not m:
                continue
            docs = {}
            for a in trs[1].find_all("a"):
                label = a.get_text(strip=True)
                if label in ("AD", "CD", "HD", "DK", "UT", "VÖ", "SI") and a.get("id"):
                    docs[label] = a["id"]
            hits.append(PortalHit(
                index=row.get("data-ri", ""), land=m.group("land").strip(), court=m.group("court").strip(),
                register_type=m.group("rt"), register_number=f"{m.group('rt')} {m.group('num').strip()}",
                name=main[0].get_text(" ", strip=True), seat=main[1].get_text(" ", strip=True),
                status=main[2].get_text(" ", strip=True), documents=docs))
        return hits, too_many, error

    # -- documents -------------------------------------------------------------
    def download(self, hit: PortalHit, kind: str) -> Tuple[bytes, str]:
        link = hit.documents.get(kind)
        if not link:
            raise DocumentUnavailable(f"no {kind} link")
        form = BeautifulSoup(self.page, "lxml").find("form", id="ergebnissForm")
        if form is None:
            raise SourceError("result form missing for document download")
        resp = self._post_form(form, {link: link}, timeout=(20, 200))
        ctype = (resp.headers.get("Content-Type") or "").lower()
        if "html" in ctype:
            txt = BeautifulSoup(resp.text, "lxml").get_text(" ", strip=True)
            # the error page replaces the result page; navigate fresh next time
            self.page, self.on_form = resp.text, False
            if self.UNAVAILABLE in txt:
                raise DocumentUnavailable("portal: document currently not available (A 450)")
            raise DocumentUnavailable("portal returned an HTML page instead of the document")
        return resp.content, ctype


def pdf_to_text(data: bytes) -> str:
    try:
        from pypdf import PdfReader  # optional dependency
    except ImportError as exc:
        raise DocumentUnavailable("pypdf not installed - cannot read AD (PDF)") from exc
    import io
    reader = PdfReader(io.BytesIO(data))
    return normalize_text("\n".join(page.extract_text() or "" for page in reader.pages))


def xjustiz_to_text(data: bytes) -> str:
    """Structured register content (SI, XJustiz XML) -> text. Natural persons are
    rendered register-style ('Nachname, Vorname, Ort / Staat, *TT.MM.JJJJ') so the
    person detector can read them; the full text follows."""
    soup = BeautifulSoup(data, "lxml-xml")

    def local(tag: Any) -> str:
        return (tag.name or "").split(":")[-1].lower()

    def first(node: Any, *names: str) -> str:
        for el in node.find_all(True):
            if local(el) in names:
                t = el.get_text(" ", strip=True)
                if t:
                    return t
        return ""

    lines, seen = [], set()
    for node in soup.find_all(True):
        children = {local(c) for c in node.find_all(True, recursive=False)}
        if not ({"vorname", "nachname", "familienname"} & {local(c) for c in node.find_all(True)}):
            continue
        if not children & {"vorname", "nachname", "familienname", "name", "allgemeinername"} and \
                not any(local(c) in ("natuerlicheperson", "name") for c in node.find_all(True, recursive=False)):
            continue
        last = first(node, "nachname", "familienname")
        given = first(node, "vorname")
        if not last or (last, given) in seen:
            continue
        seen.add((last, given))
        place = first(node, "wohnort", "ort")
        state = first(node, "staat", "land", "staatsangehoerigkeit")
        dob = first(node, "geburtsdatum")
        m = re.match(r"(\d{4})-(\d{2})-(\d{2})", dob)
        dob = f"{m.group(3)}.{m.group(2)}.{m.group(1)}" if m else dob
        bits = [last, given] + ([f"{place} / {state}" if state and state.lower() not in ("deutschland", "de")
                                 else place] if place else []) + ([f"*{dob}"] if dob else [])
        lines.append(", ".join(b for b in bits if b) + ";")
    full = soup.get_text("\n", strip=True)
    return normalize_text(("Beteiligte:\n" + "\n".join(lines) + "\n\n" if lines else "") + full)


class RegisterSearchSource(Source):
    """Free detection of new energy companies via handelsregister.de 'Erweiterte
    Suche': daily keyword searches (auto-partitioned below the 100-hit limit),
    every register number not seen before becomes a candidate, its current print
    (AD) or structured content (SI) is downloaded and run through the funnel.
    Finds new registrations AND renamings into an energy name. The first scan of
    a query only builds the baseline (no alerts)."""

    name = "register_search"

    def __init__(self, cfg: Dict[str, Any], http_cfg: Dict[str, Any]) -> None:
        super().__init__(cfg, http_cfg)
        self.db: Optional["Database"] = None
        self.dry = False
        self._done: Dict[str, str] = {}

    def attach_db(self, db: "Database", dry: bool) -> None:
        self.db, self.dry = db, dry

    def fetch(self, since: dt.date, until: dt.date, is_known: KnownFn) -> Iterator[Announcement]:
        if self.db is None:
            raise SourceError("register_search needs the database")
        portal = self.make_portal()
        portal.open()
        for keyword in self.cfg.get("keywords") or []:
            for rtype in self.cfg.get("register_types") or ["HRB", "HRA"]:
                try:
                    self._scan(portal, keyword, rtype)
                except (SourceError, requests.RequestException) as exc:
                    log.warning("[%s] search %r/%s failed: %s", self.name, keyword, rtype, exc)
                    portal.on_form = False
        yield from self._resolve_candidates(portal)

    def make_portal(self) -> RegisterPortal:
        limiter = RateLimiter(float(self.cfg.get("max_requests_per_hour", 50)),
                              max(2.0, float(self.http_cfg.get("min_delay_seconds", 1.5))))
        return RegisterPortal(HttpClient(self.http_cfg, limiter))

    # -- phase 1: searches -------------------------------------------------------
    def _scan(self, portal: RegisterPortal, keyword: str, rtype: str) -> None:
        key = f"{keyword}|{rtype}"
        plan = self.db.search_plan(key) or [["all", ""]]
        leaves: List[List[str]] = []
        hits: List[PortalHit] = []
        queue = list(plan)
        complete = True
        while queue:
            level, value = queue.pop(0)
            kwargs: Dict[str, str] = {"keywords": keyword, "register_type": rtype}
            if level == "land":
                kwargs["land"] = value
            elif level == "court":
                kwargs["court_code"] = value
            found, too_many, error = portal.search(**kwargs)
            if error:
                log.warning("[%s] %r/%s %s=%s: portal says %r", self.name, keyword, rtype, level, value, error)
                complete = False
                continue
            if too_many:
                if level == "all":
                    queue += [["land", land] for land in LAENDER]
                elif level == "land":
                    queue += [["court", code] for _, code in portal.courts_of(value)]
                else:
                    log.warning("[%s] %r/%s still >100 hits at court %s - use a more specific keyword",
                                self.name, keyword, rtype, value)
                    complete = False
                continue
            leaves.append([level, value])
            hits += found
        log.info("[%s] %r/%s: %d hits in %d searches", self.name, keyword, rtype, len(hits), len(leaves))
        if self.dry:
            return
        self.db.save_search_plan(key, leaves)
        first_run = not self.db.search_baselined(key)
        new = 0
        for hit in hits:
            if self.db.register_seen(hit.company_key):
                continue
            self.db.mark_register_seen(hit, key)
            if first_run and not self.cfg.get("alert_on_first_run"):
                continue
            if self.db.add_register_candidate(hit, keyword):
                new += 1
        if first_run and complete:
            self.db.mark_search_baselined(key)
            log.info("[%s] %r/%s: baseline stored (%d companies, no alerts)", self.name, keyword, rtype, len(hits))
        elif new:
            log.info("[%s] %r/%s: %d new companies", self.name, keyword, rtype, new)

    # -- phase 2: documents --------------------------------------------------------
    def _resolve_candidates(self, portal: RegisterPortal) -> Iterator[Announcement]:
        budget = int(self.cfg.get("max_documents_per_run", 25))
        max_attempts = int(self.cfg.get("max_document_attempts", 6))
        kinds = [k for k in self.cfg.get("documents") or ["AD", "SI"] if k in ("AD", "SI", "CD")]
        for cand in self.db.register_candidates() if not self.dry else []:
            if budget <= 0:
                log.info("[%s] document budget used up, remaining candidates follow next run", self.name)
                break
            budget -= 1
            text, error = "", ""
            try:
                code = portal.court_code(cand["court"])
                hits, _, err = portal.search(register_type=cand["register_type"],
                                             register_number=re.sub(r"\D", "", cand["register_number"]),
                                             court_code=code)
                hit = next((h for h in hits if h.company_key == cand["company_key"]), hits[0] if hits else None)
                if hit is None:
                    raise DocumentUnavailable(err or "company not found by register number")
                for kind in kinds:
                    try:
                        data, ctype = portal.download(hit, kind)
                        text = pdf_to_text(data) if ("pdf" in ctype or data[:4] == b"%PDF") else xjustiz_to_text(data)
                        if text:
                            break
                    except DocumentUnavailable as exc:
                        error = str(exc)
                        if "A 450" in error:
                            break  # portal-wide outage, other kinds will fail too
            except (SourceError, requests.RequestException, DocumentUnavailable) as exc:
                error = str(exc)
                portal.on_form = False
            attempts = int(cand["attempts"]) + 1
            if not text and attempts < max_attempts:
                self.db.candidate_attempt(cand["company_key"], error)
                log.info("[%s] %s: document not available yet (%s) - retry next run", self.name, cand["name"], error)
                continue
            if not text:
                log.warning("[%s] %s: no document after %d attempts - checking name/seat only",
                            self.name, cand["name"], attempts)
            uid = "hrs:" + cand["company_key"]
            self._done[uid] = cand["company_key"]
            header = f"{cand['name']}\n{cand['court']} {cand['register_number']}\nSitz: {cand['seat']}"
            yield Announcement(
                uid=uid, source=self.name, company_name=cand["name"], text=header + "\n\n" + text,
                published=cand["found_at"][:10], court=cand["court"], register_type=cand["register_type"],
                register_number=cand["register_number"], seat=cand["seat"], state=cand["land"],
                announcement_type="Neu im Registerportal (Neueintragung oder Umfirmierung)",
                event_hint="Neueintragung/Umfirmierung", url=RegisterPortal.BASE,
                meta={"keyword": cand["keyword"]})

    def commit(self, processed_uids: Iterable[str]) -> None:
        if self.db is None or self.dry:
            return
        for uid in processed_uids:
            if uid in self._done:
                self.db.candidate_done(self._done[uid])


# --------------------------------------------------------------------------
# Persistence
# --------------------------------------------------------------------------
SCHEMA = """
CREATE TABLE IF NOT EXISTS processed (
    uid               TEXT PRIMARY KEY,
    source            TEXT NOT NULL,
    company_key       TEXT,
    company_name      TEXT,
    court             TEXT,
    register_number   TEXT,
    published         TEXT,
    announcement_type TEXT,
    sector_hit        INTEGER NOT NULL DEFAULT 0,
    swiss_hit         INTEGER NOT NULL DEFAULT 0,
    processed_at      TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_processed_company ON processed(company_key);
CREATE INDEX IF NOT EXISTS idx_processed_regnr ON processed(register_number);

CREATE TABLE IF NOT EXISTS alerts (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    uid             TEXT NOT NULL,
    company_key     TEXT NOT NULL,
    name_key        TEXT NOT NULL,
    company_name    TEXT,
    register_number TEXT,
    court           TEXT,
    payload         TEXT NOT NULL,
    status          TEXT NOT NULL DEFAULT 'pending',
    attempts        INTEGER NOT NULL DEFAULT 0,
    last_error      TEXT,
    created_at      TEXT NOT NULL,
    sent_at         TEXT
);
CREATE INDEX IF NOT EXISTS idx_alerts_company ON alerts(company_key);
CREATE INDEX IF NOT EXISTS idx_alerts_name ON alerts(name_key);
CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);

-- register_search: every company ever seen in a search result, the learned
-- partitioning per query and the candidates waiting for their documents
CREATE TABLE IF NOT EXISTS register_seen (
    company_key     TEXT PRIMARY KEY,
    company_name    TEXT,
    court           TEXT,
    register_number TEXT,
    query           TEXT,
    first_seen      TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS search_plans (
    query      TEXT PRIMARY KEY,
    plan       TEXT NOT NULL,
    baselined  INTEGER NOT NULL DEFAULT 0,
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS register_candidates (
    company_key     TEXT PRIMARY KEY,
    name            TEXT,
    court           TEXT,
    register_type   TEXT,
    register_number TEXT,
    land            TEXT,
    seat            TEXT,
    keyword         TEXT,
    found_at        TEXT NOT NULL,
    status          TEXT NOT NULL DEFAULT 'pending',
    attempts        INTEGER NOT NULL DEFAULT 0,
    last_error      TEXT
);
"""


class Database:
    def __init__(self, path: Path, read_only: bool = False) -> None:
        self.read_only = read_only
        path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(path), timeout=30)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA busy_timeout = 30000")
        if not read_only:
            self.conn.execute("PRAGMA journal_mode = WAL")
        self.conn.executescript(SCHEMA)
        self.conn.commit()

    def close(self) -> None:
        self.conn.close()

    def is_processed(self, uid: str) -> bool:
        return self.conn.execute("SELECT 1 FROM processed WHERE uid = ?", (uid,)).fetchone() is not None

    def company_alerted(self, ann: Announcement) -> bool:
        row = self.conn.execute(
            "SELECT 1 FROM alerts WHERE company_key = ? OR name_key = ? LIMIT 1",
            (ann.company_key, ann.name_key)).fetchone()
        return row is not None

    def uid_alerted(self, uid: str) -> bool:
        return self.conn.execute("SELECT 1 FROM alerts WHERE uid = ?", (uid,)).fetchone() is not None

    def record(self, ann: Announcement, ev: Evaluation, alert_payload: Optional[Dict[str, Any]]) -> Optional[int]:
        """Mark announcement processed and (optionally) queue an alert atomically."""
        if self.read_only:
            return None
        alert_id = None
        with self.conn:
            self.conn.execute(
                "INSERT OR REPLACE INTO processed (uid, source, company_key, company_name, court, "
                "register_number, published, announcement_type, sector_hit, swiss_hit, processed_at) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (ann.uid, ann.source, ann.company_key, ann.company_name, ann.court, ann.register_number,
                 ann.published, ann.announcement_type, int(bool(ev.sector_hits)), int(bool(ev.findings)),
                 utcnow()))
            if alert_payload is not None:
                cur = self.conn.execute(
                    "INSERT INTO alerts (uid, company_key, name_key, company_name, register_number, court, "
                    "payload, created_at) VALUES (?,?,?,?,?,?,?,?)",
                    (ann.uid, ann.company_key, ann.name_key, ann.company_name, ann.register_number, ann.court,
                     json.dumps(alert_payload, ensure_ascii=False), utcnow()))
                alert_id = cur.lastrowid
        return alert_id

    # -- register_search state -------------------------------------------------
    def register_seen(self, company_key: str) -> bool:
        return self.conn.execute("SELECT 1 FROM register_seen WHERE company_key=?", (company_key,)).fetchone() is not None

    def mark_register_seen(self, hit: Any, query: str) -> None:
        with self.conn:
            self.conn.execute("INSERT OR IGNORE INTO register_seen VALUES (?,?,?,?,?,?)",
                              (hit.company_key, hit.name, hit.court, hit.register_number, query, utcnow()))

    def search_plan(self, query: str) -> Optional[List[List[str]]]:
        row = self.conn.execute("SELECT plan FROM search_plans WHERE query=?", (query,)).fetchone()
        return json.loads(row["plan"]) if row else None

    def save_search_plan(self, query: str, plan: List[List[str]]) -> None:
        with self.conn:
            self.conn.execute("INSERT INTO search_plans (query, plan, updated_at) VALUES (?,?,?) "
                              "ON CONFLICT(query) DO UPDATE SET plan=excluded.plan, updated_at=excluded.updated_at",
                              (query, json.dumps(plan), utcnow()))

    def search_baselined(self, query: str) -> bool:
        row = self.conn.execute("SELECT baselined FROM search_plans WHERE query=?", (query,)).fetchone()
        return bool(row and row["baselined"])

    def mark_search_baselined(self, query: str) -> None:
        with self.conn:
            self.conn.execute("UPDATE search_plans SET baselined=1 WHERE query=?", (query,))

    def add_register_candidate(self, hit: Any, keyword: str) -> bool:
        with self.conn:
            cur = self.conn.execute(
                "INSERT OR IGNORE INTO register_candidates (company_key, name, court, register_type, "
                "register_number, land, seat, keyword, found_at) VALUES (?,?,?,?,?,?,?,?,?)",
                (hit.company_key, hit.name, hit.court, hit.register_type, hit.register_number, hit.land,
                 hit.seat, keyword, utcnow()))
        return cur.rowcount > 0

    def register_candidates(self) -> List[sqlite3.Row]:
        return list(self.conn.execute(
            "SELECT * FROM register_candidates WHERE status='pending' ORDER BY found_at"))

    def candidate_attempt(self, company_key: str, error: str) -> None:
        with self.conn:
            self.conn.execute("UPDATE register_candidates SET attempts=attempts+1, last_error=? WHERE company_key=?",
                              (error[:300], company_key))

    def candidate_done(self, company_key: str) -> None:
        with self.conn:
            self.conn.execute("UPDATE register_candidates SET status='done' WHERE company_key=?", (company_key,))

    def pending_alerts(self) -> List[sqlite3.Row]:
        return list(self.conn.execute("SELECT * FROM alerts WHERE status = 'pending' ORDER BY id"))

    def mark_alert(self, alert_id: int, ok: bool, error: str = "") -> None:
        if self.read_only:
            return
        with self.conn:
            if ok:
                self.conn.execute("UPDATE alerts SET status='sent', sent_at=?, attempts=attempts+1, "
                                  "last_error=NULL WHERE id=?", (utcnow(), alert_id))
            else:
                self.conn.execute("UPDATE alerts SET attempts=attempts+1, last_error=? WHERE id=?",
                                  (error[:500], alert_id))


# --------------------------------------------------------------------------
# Alerting
# --------------------------------------------------------------------------
def build_alert(ann: Announcement, ev: Evaluation, max_findings: int) -> Dict[str, Any]:
    return {
        "company_name": ann.company_name,
        "register_number": ann.register_number,
        "court": ann.court,
        "register_label": ann.register_label,
        "announcement_type": ann.announcement_type,
        "events": ev.events,
        "published": ann.published,
        "seat": ann.seat,
        "source": ann.source,
        "url": ann.url,
        "uid": ann.uid,
        "sector_hits": ev.sector_hits,
        "findings": [f.as_dict() for f in ev.findings[:max_findings]],
        "findings_total": len(ev.findings),
        "text": ann.text,
        "enrichment_text": ev.enrichment_text,
    }


def format_alert_console(alert: Dict[str, Any]) -> str:
    lines = [
        "=" * 78,
        f"ALERT  {alert['company_name']}",
        f"  Register : {alert['register_label']}",
        f"  Type     : {alert.get('announcement_type') or '-'}"
        + (f"  [{', '.join(alert['events'])}]" if alert.get("events") else ""),
        f"  Published: {alert.get('published') or '-'}   Source: {alert['source']}",
        f"  Sector   : {', '.join(alert['sector_hits'])}",
        "  Swiss connection:",
    ]
    for f in alert["findings"]:
        lines.append(f"    - [{f['origin']}] {f['summary']}")
        lines.append(f"        {f['context']}")
    lines.append("  Text:")
    lines += ["    " + ln for ln in truncate(alert["text"], 1500).splitlines()]
    return "\n".join(lines)


class DiscordNotifier:
    # Discord limits: title 256, description 4096, field value 1024, total 6000
    def __init__(self, cfg: Dict[str, Any], http_cfg: Dict[str, Any]) -> None:
        self.url = (os.environ.get(ENV_WEBHOOK) or cfg.get("webhook_url") or "").strip()
        self.username = cfg.get("username") or "Hydra-Radar"
        self.mention = cfg.get("mention") or ""
        self.max_text = min(int(cfg.get("max_text_chars", 3000)), 3500)
        self.attach = bool(cfg.get("attach_full_text", True))
        self.http = HttpClient({**http_cfg, "retries": 0, "user_agents": [f"Hydra-Radar/{__version__}"]},
                               RateLimiter(0, 1.0))

    @property
    def configured(self) -> bool:
        return bool(re.match(r"^https://(?:\w+\.)?discord(?:app)?\.com/api/webhooks/\d+/[\w\-]+", self.url))

    def build_payload(self, alert: Dict[str, Any]) -> Tuple[Dict[str, Any], Optional[str]]:
        connection_lines = []
        for f in alert["findings"]:
            tag = " (OpenCorporates)" if f.get("origin") == "opencorporates" else ""
            connection_lines.append(f"• **{discord_escape(f['summary'])}**{tag}\n  ↳ {discord_escape(f['context'])}")
        extra = alert.get("findings_total", 0) - len(alert["findings"])
        if extra > 0:
            connection_lines.append(f"… and {extra} more")
        connection = truncate("\n".join(connection_lines), 1024)

        text = alert["text"] or "(no text)"
        attach = None
        if len(text) > self.max_text and self.attach:
            attach = text + ("\n\n--- OpenCorporates ---\n" + alert["enrichment_text"]
                             if alert.get("enrichment_text") else "")
        description = "```\n" + truncate(text.replace("```", "'''"), self.max_text) + "\n```"

        register = alert["register_number"] or "n/a"
        fields = [
            {"name": "Company", "value": truncate(discord_escape(alert["company_name"]) or "n/a", 1024), "inline": True},
            {"name": "Register no.", "value": truncate(register, 1024), "inline": True},
            {"name": "Court", "value": truncate(alert.get("court") or "n/a", 1024), "inline": True},
            {"name": "🇨🇭 Swiss connection", "value": connection or "n/a", "inline": False},
            {"name": "Sector match", "value": truncate(", ".join(alert["sector_hits"]), 1024), "inline": True},
            {"name": "Announcement",
             "value": truncate(" / ".join(x for x in [alert.get("announcement_type") or "",
                                                      ", ".join(alert.get("events") or [])] if x) or "n/a", 1024),
             "inline": True},
        ]
        embed: Dict[str, Any] = {
            "title": truncate(f"🚨 Swiss link: {alert['company_name']}", 256),
            "description": description,
            "color": 0xD52B1E,
            "fields": fields,
            "footer": {"text": truncate(f"Hydra-Radar {__version__} · {alert['source']} · published "
                                        f"{alert.get('published') or '?'} · {alert['uid']}", 2048)},
            "timestamp": utcnow(),
        }
        if alert.get("url", "").startswith("http"):
            embed["url"] = alert["url"]
        # enforce the 6000 character embed budget by shrinking the description
        total = len(embed["title"]) + len(embed["description"]) + len(embed["footer"]["text"]) + \
            sum(len(f["name"]) + len(f["value"]) for f in fields)
        if total > 5900:
            over = total - 5900
            embed["description"] = "```\n" + truncate(text.replace("```", "'''"),
                                                     max(200, self.max_text - over)) + "\n```"
        payload: Dict[str, Any] = {"username": self.username, "embeds": [embed],
                                   "allowed_mentions": {"parse": ["users", "roles", "everyone"]}}
        if self.mention:
            payload["content"] = self.mention
        return payload, attach

    def send(self, alert: Dict[str, Any]) -> None:
        if not self.configured:
            raise NotifyError("Discord webhook URL not configured")
        payload, attachment = self.build_payload(alert)
        url = self.url + ("&" if "?" in self.url else "?") + "wait=true"
        for attempt in range(1, 6):
            try:
                if attachment:
                    fname = re.sub(r"[^\w\-]+", "_", alert["company_name"])[:60] or "registration"
                    resp = self.http.post(url, data={"payload_json": json.dumps(payload)},
                                          files={"files[0]": (f"{fname}.txt", attachment.encode("utf-8"),
                                                              "text/plain")})
                else:
                    resp = self.http.post(url, json=payload)
            except requests.RequestException as exc:
                if attempt == 5:
                    raise NotifyError(f"network error: {exc}") from exc
                time.sleep(2 ** attempt)
                continue
            if resp.status_code == 429:
                try:
                    wait = float(resp.json().get("retry_after", 2))
                except ValueError:
                    wait = 2.0
                wait = wait / 1000 if wait > 300 else wait  # old API versions return ms
                log.info("Discord rate limit, sleeping %.1fs", wait)
                time.sleep(min(wait, 60) + 0.25)
                continue
            if resp.status_code >= 500:
                time.sleep(2 ** attempt)
                continue
            if resp.ok:
                return
            raise NotifyError(f"Discord HTTP {resp.status_code}: {resp.text[:300]}")
        raise NotifyError("Discord: giving up after retries")

    def send_test(self) -> None:
        alert = {
            "company_name": "Hydra-Radar Testmeldung GmbH", "register_number": "HRB 00000",
            "court": "Amtsgericht Musterstadt", "register_label": "HRB 00000 · Amtsgericht Musterstadt",
            "announcement_type": "Test", "events": [], "published": dt.date.today().isoformat(),
            "seat": "", "source": "test", "url": "", "uid": "test", "sector_hits": ["Strom"],
            "findings": [Finding("person", "Geschäftsführer: Muster, Max (*01.01.1970) – residence: Zug / Schweiz",
                                 "", "Geschäftsführer: «Muster, Max, Zug / Schweiz, *01.01.1970»").as_dict()],
            "findings_total": 1, "text": "Webhook test – if you can read this, alerting works.",
            "enrichment_text": "",
        }
        self.send(alert)


# --------------------------------------------------------------------------
# Runner
# --------------------------------------------------------------------------
SOURCE_CLASSES = {
    "github_snapshots": GitHubSnapshotSource,
    "handelsregister": HandelsregisterSource,
    "register_search": RegisterSearchSource,
    "opencorporates": OpenCorporatesSource,
    "local": LocalInboxSource,
}


def resolve_path(value: str, base: Path) -> Path:
    p = Path(os.path.expanduser(value))
    return p if p.is_absolute() else (base / p)


def load_config(path: Path) -> Dict[str, Any]:
    if not path.is_file():
        raise ConfigError(f"config file not found: {path}")
    try:
        user_cfg = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ConfigError(f"{path}: invalid JSON ({exc})") from exc
    cfg = deep_merge(DEFAULT_CONFIG, user_cfg)
    base = path.resolve().parent
    cfg["database"]["path"] = str(resolve_path(cfg["database"]["path"], base))
    cfg["logging"]["dir"] = str(resolve_path(cfg["logging"]["dir"], base))
    cfg["run"]["lock_file"] = str(resolve_path(cfg["run"]["lock_file"], base))
    if cfg["detection"].get("swiss_places_file"):
        cfg["detection"]["swiss_places_file"] = str(resolve_path(cfg["detection"]["swiss_places_file"], base))
    local = cfg["sources"].get("local") or {}
    for key in ("inbox_dir", "archive_dir"):
        if local.get(key):
            local[key] = str(resolve_path(local[key], base))
    return cfg


def setup_logging(cfg: Dict[str, Any], verbose: bool, quiet: bool) -> None:
    root = logging.getLogger("hydra_radar")
    root.setLevel(logging.DEBUG)
    root.handlers.clear()
    fmt = logging.Formatter("%(asctime)s %(levelname)-7s %(message)s", "%Y-%m-%d %H:%M:%S")
    level = getattr(logging, str(cfg["logging"].get("level", "INFO")).upper(), logging.INFO)
    try:
        log_dir = Path(cfg["logging"]["dir"])
        log_dir.mkdir(parents=True, exist_ok=True)
        fh = logging.handlers.RotatingFileHandler(log_dir / "radar.log", maxBytes=int(cfg["logging"]["max_bytes"]),
                                                  backupCount=int(cfg["logging"]["backups"]), encoding="utf-8")
        fh.setLevel(logging.DEBUG if verbose else level)
        fh.setFormatter(fmt)
        root.addHandler(fh)
    except OSError as exc:
        print(f"warning: file logging disabled: {exc}", file=sys.stderr)
    ch = logging.StreamHandler(sys.stderr)
    # interactive: INFO; under cron (no TTY): only warnings, so cron mail stays quiet
    ch.setLevel(logging.DEBUG if verbose else logging.ERROR if quiet else
                logging.INFO if sys.stderr.isatty() else logging.WARNING)
    ch.setFormatter(fmt)
    root.addHandler(ch)


class RunLock:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.fh: Any = None

    def __enter__(self) -> "RunLock":
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.fh = open(self.path, "w")
        try:
            import fcntl
            fcntl.flock(self.fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except ImportError:  # non-POSIX: no locking
            pass
        except OSError:
            self.fh.close()
            raise
        self.fh.write(str(os.getpid()))
        self.fh.flush()
        return self

    def __exit__(self, *exc: Any) -> None:
        if self.fh:
            self.fh.close()


@dataclasses.dataclass
class Stats:
    seen: int = 0
    skipped: int = 0
    evaluated: int = 0
    sector: int = 0
    swiss: int = 0
    alerts_new: int = 0
    alerts_sent: int = 0
    alerts_failed: int = 0
    suppressed: int = 0
    source_errors: int = 0


def build_sources(cfg: Dict[str, Any], only: Sequence[str]) -> List[Source]:
    sources: List[Source] = []
    for name, scfg in cfg["sources"].items():
        if name not in SOURCE_CLASSES:
            log.warning("unknown source %r in config - ignored", name)
            continue
        if only and name not in only:
            continue
        if not only and not scfg.get("enabled"):
            continue
        sources.append(SOURCE_CLASSES[name](scfg, cfg["http"]))
    return sources


def deliver(db: Database, notifier: DiscordNotifier, alert_id: int, alert: Dict[str, Any], stats: Stats) -> None:
    try:
        notifier.send(alert)
    except NotifyError as exc:
        stats.alerts_failed += 1
        db.mark_alert(alert_id, False, str(exc))
        log.error("alert #%d for %s NOT delivered (will retry next run): %s", alert_id, alert["company_name"], exc)
        return
    stats.alerts_sent += 1
    db.mark_alert(alert_id, True)
    log.info("alert #%d sent: %s", alert_id, alert["company_name"])


def run(cfg: Dict[str, Any], args: argparse.Namespace) -> int:
    dry = args.dry_run
    db = Database(Path(cfg["database"]["path"]), read_only=dry)
    notifier = DiscordNotifier(cfg["discord"], cfg["http"])
    if not dry and not notifier.configured:
        raise ConfigError(f"discord.webhook_url is not a valid webhook URL (set it in config.json or ${ENV_WEBHOOK}),"
                          " or run with --dry-run")
    funnel = Funnel(cfg["detection"])
    stats = Stats()
    run_cfg = cfg["run"]

    today = dt.date.today()
    until = args.until or today
    since = args.since or (until - dt.timedelta(days=int(args.days if args.days is not None
                                                            else run_cfg["lookback_days"])))
    log.info("Hydra-Radar %s run started (%s .. %s)%s", __version__, since, until, " [DRY-RUN]" if dry else "")

    if not dry:
        for row in db.pending_alerts():
            log.info("retrying pending alert #%d (%s)", row["id"], row["company_name"])
            deliver(db, notifier, row["id"], json.loads(row["payload"]), stats)

    enricher: Optional[OpenCorporatesClient] = None
    oc_cfg = cfg["sources"].get("opencorporates") or {}
    if oc_cfg.get("enrich_candidates") and (oc_cfg.get("api_token") or os.environ.get(ENV_OC_TOKEN)) \
            and not args.no_enrich:
        enricher = OpenCorporatesClient(oc_cfg, cfg["http"])

    try:
        sources = build_sources(cfg, args.source or [])
    except ConfigError:
        raise
    if not sources:
        log.warning("no sources enabled - nothing to do")

    known = (lambda uid: False) if args.reprocess else db.is_processed
    for source in sources:
        source.attach_db(db, dry)
        processed: List[str] = []
        log.info("[%s] fetching", source.name)
        try:
            for ann in source.fetch(since, until, known):
                stats.seen += 1
                if known(ann.uid):
                    stats.skipped += 1
                    continue
                stats.evaluated += 1
                ev = funnel.evaluate(ann, enricher)
                if ev.sector_hits:
                    stats.sector += 1
                    log.debug("[%s] sector hit %s %s: %s", source.name, ann.register_label,
                              ann.company_name, ev.sector_hits)
                alert = None
                if ev.alert:
                    stats.swiss += 1
                    if run_cfg.get("require_event_match") and not ev.events:
                        log.info("[%s] %s: Swiss link but no Neueintragung/Gegenstand event - skipped "
                                 "(require_event_match)", source.name, ann.company_name)
                    elif not args.reprocess and (
                            (run_cfg.get("alert_once_per_company") and db.company_alerted(ann))
                            or db.uid_alerted(ann.uid)):
                        stats.suppressed += 1
                        log.info("[%s] %s already alerted earlier - suppressed", source.name, ann.company_name)
                    else:
                        alert = build_alert(ann, ev, int(run_cfg.get("max_findings_per_alert", 15)))
                if dry:
                    if alert:
                        stats.alerts_new += 1
                        print(format_alert_console(alert), flush=True)
                    continue
                alert_id = db.record(ann, ev, alert)
                processed.append(ann.uid)
                if alert and alert_id:
                    stats.alerts_new += 1
                    log.warning("SWISS LINK: %s (%s) - %s", ann.company_name, ann.register_label,
                                "; ".join(f.summary for f in ev.findings[:3]))
                    deliver(db, notifier, alert_id, alert, stats)
        except (SourceError, requests.RequestException) as exc:
            stats.source_errors += 1
            log.error("[%s] source failed: %s", source.name, exc)
        except Exception:
            stats.source_errors += 1
            log.exception("[%s] unexpected error", source.name)
        if not dry:
            source.commit(processed)

    log.info("run finished: seen=%d skipped(known)=%d evaluated=%d sector=%d swiss=%d new_alerts=%d "
             "sent=%d failed=%d suppressed=%d source_errors=%d", stats.seen, stats.skipped, stats.evaluated,
             stats.sector, stats.swiss, stats.alerts_new, stats.alerts_sent, stats.alerts_failed,
             stats.suppressed, stats.source_errors)
    db.close()
    return 1 if (stats.source_errors or stats.alerts_failed) else 0


def check_file(cfg: Dict[str, Any], path: str, enrich: bool) -> int:
    raw = Path(path).read_text(encoding="utf-8", errors="replace")
    if path.lower().endswith((".html", ".htm", ".xml")):
        raw = BeautifulSoup(raw, "lxml").get_text("\n")
    ann = Announcement(uid="check", source="check", text=raw,
                       company_name=LocalInboxSource.guess_company_name(normalize_text(raw)) or Path(path).stem)
    funnel = Funnel(cfg["detection"])
    oc_cfg = cfg["sources"].get("opencorporates") or {}
    enricher = OpenCorporatesClient(oc_cfg, cfg["http"]) if enrich else None
    ev = funnel.evaluate(ann, enricher)
    print(f"Company     : {ann.company_name}\nRegister    : {ann.register_label}")
    print(f"Step 1 sector: {'PASS ' + ', '.join(ev.sector_hits) if ev.sector_hits else 'no energy keyword'}")
    print(f"Events      : {', '.join(ev.events) or '-'}")
    if not ev.sector_hits:
        swiss = funnel.swiss_findings(ann.text)
        print(f"(Step 2 not reached; would have found {len(swiss)} Swiss signal(s))")
    for f in ev.findings:
        print(f"  [{f.kind}/{f.origin}] {f.summary}\n      {f.context}")
    print("ALERT" if ev.alert else "no alert")
    return 0


def main(argv: Optional[Sequence[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Hydra-Radar: energy-sector register monitor with Swiss-link detection")
    ap.add_argument("-c", "--config", default=str(BASE_DIR / "config.json"), help="path to config.json")
    ap.add_argument("--dry-run", action="store_true", help="print alerts instead of sending; DB is not modified")
    ap.add_argument("--days", type=int, help="look back N days (default: run.lookback_days)")
    ap.add_argument("--since", type=parse_date, help="start date (YYYY-MM-DD)")
    ap.add_argument("--until", type=parse_date, help="end date (YYYY-MM-DD, default today)")
    ap.add_argument("--source", action="append", choices=sorted(SOURCE_CLASSES),
                    help="only run this source (repeatable; ignores 'enabled')")
    ap.add_argument("--reprocess", action="store_true", help="ignore the dedup DB for processed/alerted checks")
    ap.add_argument("--no-enrich", action="store_true", help="skip OpenCorporates enrichment")
    ap.add_argument("--test-webhook", action="store_true", help="send a test message to Discord and exit")
    ap.add_argument("--check", metavar="FILE", help="run the detection funnel on a text/html file and exit")
    ap.add_argument("-v", "--verbose", action="store_true", help="debug logging")
    ap.add_argument("-q", "--quiet", action="store_true", help="only errors on stderr")
    ap.add_argument("--version", action="version", version=f"Hydra-Radar {__version__}")
    args = ap.parse_args(argv)

    try:
        cfg = load_config(Path(args.config))
    except ConfigError as exc:
        print(f"config error: {exc}", file=sys.stderr)
        return 2
    setup_logging(cfg, args.verbose, args.quiet)

    try:
        if args.check:
            return check_file(cfg, args.check, enrich=not args.no_enrich and bool(
                (cfg["sources"].get("opencorporates") or {}).get("enrich_candidates")
                and ((cfg["sources"]["opencorporates"].get("api_token")) or os.environ.get(ENV_OC_TOKEN))))
        if args.test_webhook:
            DiscordNotifier(cfg["discord"], cfg["http"]).send_test()
            print("test message sent")
            return 0
        with RunLock(Path(cfg["run"]["lock_file"])):
            return run(cfg, args)
    except ConfigError as exc:
        log.error("config error: %s", exc)
        return 2
    except NotifyError as exc:
        log.error("%s", exc)
        return 1
    except OSError as exc:
        if "lock" in str(exc).lower() or getattr(exc, "errno", None) in (11, 35):
            log.error("another Hydra-Radar run is still active (lock %s)", cfg["run"]["lock_file"])
            return 3
        raise
    except KeyboardInterrupt:
        log.warning("interrupted")
        return 130


if __name__ == "__main__":
    sys.exit(main())
