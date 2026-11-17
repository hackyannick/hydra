#!/usr/bin/env python3
"""
Build swiss_places.json - every Swiss locality / municipality with postcode(s)
and canton, plus a flag telling whether the same name also exists as a German
place (then Hydra-Radar only trusts it together with another Swiss signal).

Inputs (all MIT licensed npm packages, fetch with `npm pack <name>`):
  switzerland-postal-codes       data/postal-codes.tsv   (CH postcode -> locality, canton)
  @onebyte/swiss-postal-codes    data.json               (CH postcode -> municipality, canton)
  gemeindeverzeichnis            gemeinden.ndjson        (all German municipalities, Destatis)
  postleitzahlen                 data/ort.json           (German localities -> postcodes)

Usage:
  python3 tools/build_swiss_places.py --ch-tsv postal-codes.tsv --ch-communes data.json \
      --de-gemeinden gemeinden.ndjson --de-orte ort.json -o swiss_places.json
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import unicodedata
from collections import defaultdict
from pathlib import Path
from typing import Dict, Iterable, Set

CANTONS: Dict[str, list] = {
    "ZH": ["Zürich", "Zurich", "Zurigo"],
    "BE": ["Bern", "Berne", "Berna"],
    "LU": ["Luzern", "Lucerne", "Lucerna"],
    "UR": ["Uri"],
    "SZ": ["Schwyz", "Svitto"],
    "OW": ["Obwalden", "Obwald"],
    "NW": ["Nidwalden", "Nidwald"],
    "GL": ["Glarus", "Glaris", "Glarona"],
    "ZG": ["Zug", "Zoug", "Zugo"],
    "FR": ["Freiburg", "Fribourg", "Friburgo"],
    "SO": ["Solothurn", "Soleure", "Soletta"],
    "BS": ["Basel-Stadt", "Bâle-Ville", "Basilea Città"],
    "BL": ["Basel-Landschaft", "Basel-Land", "Baselland", "Bâle-Campagne", "Basilea Campagna"],
    "SH": ["Schaffhausen", "Schaffhouse", "Sciaffusa"],
    "AR": ["Appenzell Ausserrhoden", "Appenzell Rhodes-Extérieures", "Appenzello Esterno"],
    "AI": ["Appenzell Innerrhoden", "Appenzell Rhodes-Intérieures", "Appenzello Interno"],
    "SG": ["St. Gallen", "Sankt Gallen", "St.Gallen", "Saint-Gall", "San Gallo"],
    "GR": ["Graubünden", "Grisons", "Grigioni", "Grischun"],
    "AG": ["Aargau", "Argovie", "Argovia"],
    "TG": ["Thurgau", "Thurgovie", "Turgovia"],
    "TI": ["Tessin", "Ticino"],
    "VD": ["Waadt", "Vaud"],
    "VS": ["Wallis", "Valais", "Vallese"],
    "NE": ["Neuenburg", "Neuchâtel"],
    "GE": ["Genf", "Genève", "Geneva", "Ginevra"],
    "JU": ["Jura"],
}

GERMAN_SUFFIXES = re.compile(
    r"\s+(?:am|an\s+der|an\s+den|im|in|in\s+der|bei|ob\s+der|vor\s+der|unter|über|auf|a\.|i\.|b\.|v\.\s*d\.)\s.*$")


def nfc(s: str) -> str:
    return unicodedata.normalize("NFC", s).strip()


def ch_variants(name: str) -> Iterable[str]:
    """'Biel/Bienne' -> Biel, Bienne; 'Charmey (Gruyère)' -> Charmey (Gruyère), Charmey;
    'Zell (LU)' -> Zell."""
    name = nfc(name)
    for part in name.split("/"):
        part = part.strip()
        if not part:
            continue
        base = re.sub(r"\s*\([^)]*\)\s*$", "", part).strip()
        if base:
            yield base
        if base != part and not re.search(r"\([A-Z]{2}\)$", part):
            yield part


def de_variants(name: str) -> Iterable[str]:
    """'Freiburg im Breisgau, Stadt' -> 'Freiburg im Breisgau', 'Freiburg';
    'Baar (Schwaben)' -> 'Baar (Schwaben)', 'Baar'; 'Baar-Ebenhausen' -> also 'Baar'."""
    name = nfc(name.split(",")[0])
    out = {name}
    base = re.sub(r"\s*\([^)]*\)\s*$", "", name).strip()
    out.add(base)
    out.add(GERMAN_SUFFIXES.sub("", base).strip())
    if base.startswith(("Bad ", "Sankt ", "St. ")):
        out.add(base)
    return {o for o in out if o}


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--ch-tsv", required=True)
    ap.add_argument("--ch-communes", required=True)
    ap.add_argument("--de-gemeinden", required=True)
    ap.add_argument("--de-orte", required=True)
    ap.add_argument("-o", "--output", default="swiss_places.json")
    args = ap.parse_args()

    cantons_of: Dict[str, Set[str]] = defaultdict(set)
    plz_of: Dict[str, Set[str]] = defaultdict(set)

    for line in Path(args.ch_tsv).read_text(encoding="utf-8").splitlines():
        cols = line.split("\t")
        if len(cols) < 3 or not re.fullmatch(r"\d{4}", cols[0]):
            continue
        for v in ch_variants(cols[1]):
            cantons_of[v].add(cols[2])
            plz_of[v].add(cols[0])
    for plz, rec in json.loads(Path(args.ch_communes).read_text(encoding="utf-8")).items():
        if not re.fullmatch(r"\d{4}", plz):
            continue
        for v in ch_variants(rec["commune"]):
            cantons_of[v].add(rec["canton"])
            plz_of[v].add(plz)

    german: Set[str] = set()
    for line in Path(args.de_gemeinden).read_text(encoding="utf-8").splitlines():
        if line.strip():
            german.update(de_variants(json.loads(line)["name"]))
    for name in json.loads(Path(args.de_orte).read_text(encoding="utf-8")):
        german.update(de_variants(name))

    places = {}
    for name in sorted(cantons_of):
        if len(name) < 2:
            continue
        places[name] = {"c": "".join(sorted(cantons_of[name])) if len(cantons_of[name]) == 1
                        else ",".join(sorted(cantons_of[name])),
                        "p": sorted(plz_of[name]),
                        **({"de": 1} if name in german else {})}
    cantons = {code: {"names": names, "shared_de": [n for n in names if n in german]}
               for code, names in CANTONS.items()}
    data = {
        "_about": "Swiss localities/municipalities with postcodes and cantons. 'de': 1 = name also "
                  "exists as a German place. Generated by tools/build_swiss_places.py.",
        "_sources": ["npm switzerland-postal-codes 5.0.1 (MIT, W. Belle)",
                     "npm @onebyte/swiss-postal-codes 1.0.2 (MIT, Bassim)",
                     "npm gemeindeverzeichnis 0.1.0 (MIT, J. Tens; Destatis GV100)",
                     "npm postleitzahlen 1.0.0 (German localities, OSM via suche-postleitzahl.org)"],
        "_generated": dt.date.today().isoformat(),
        "cantons": cantons,
        "places": places,
    }
    Path(args.output).write_text(json.dumps(data, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")
    shared = sum(1 for p in places.values() if p.get("de"))
    print(f"{len(places)} Swiss place names ({shared} also German), "
          f"{len({z for p in places.values() for z in p['p']})} postcodes -> {args.output}")
    print("canton names shared with German places:",
          [n for c in cantons.values() for n in c["shared_de"]])


if __name__ == "__main__":
    main()
