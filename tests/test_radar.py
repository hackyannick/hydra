"""Offline test-suite for Hydra-Radar.  Run:  python3 -m unittest discover -s tests -v"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import shutil
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))

import radar  # noqa: E402

CFG = radar.load_config(ROOT / "config.json")
FIX = HERE / "fixtures"


def funnel() -> radar.Funnel:
    return radar.Funnel(CFG["detection"])


def ann(text: str, name: str = "Test Energie GmbH", **kw) -> radar.Announcement:
    return radar.Announcement(uid=kw.pop("uid", "t:" + radar.sha1(text)), source="test",
                              company_name=name, text=text, **kw)


class TermCompilation(unittest.TestCase):
    def test_word_mode_boundaries_and_case(self):
        (_, zug), = radar.compile_terms(["Zug"], "word")
        self.assertTrue(zug.search("Sitz in Zug."))
        self.assertTrue(zug.search("SITZ IN ZUG"))
        self.assertFalse(zug.search("Bezug von Gas"))
        self.assertFalse(zug.search("im Zuge der"))
        (_, ch), = radar.compile_terms(["CH-"], "word")
        self.assertTrue(ch.search("CH-6300 Zug"))
        self.assertFalse(ch.search("Bosch-Gruppe"))
        self.assertFalse(ch.search("ch-irgendwas"))

    def test_substring_mode_hits_compounds(self):
        (_, strom), = radar.compile_terms(["Strom"], "substring")
        self.assertTrue(strom.search("Ökostromvertrieb"))

    def test_bad_regex_raises_config_error(self):
        with self.assertRaises(radar.ConfigError):
            radar.compile_terms(["re:(unclosed"], "word")


class SectorFilter(unittest.TestCase):
    def test_energy_keywords(self):
        f = funnel()
        self.assertIn("Energieversorgung", f.sector_hits(ann("Gegenstand: Energieversorgung")))
        self.assertIn("Gas", f.sector_hits(ann("Handel mit Erdgas", name="X GmbH")))
        self.assertIn("Strom", f.sector_hits(ann("Lieferung von Ökostrom", name="X GmbH")))

    def test_company_name_counts(self):
        self.assertTrue(funnel().sector_hits(ann("Liste der Gesellschafter eingereicht.",
                                                 name="EVG Energieversorgung Gemünden GmbH")))

    def test_gastro_and_street_names_are_not_gas(self):
        f = funnel()
        for text in ("Betrieb einer Gaststätte", "Gasthof zur Post", "Hauptgasse 4", "Gastronomie",
                     "Pegasus Consulting", "Las Vegas Bar", "Stromberg Immobilien"):
            self.assertEqual(f.sector_hits(ann(text, name="Muster GmbH")), [], text)

    def test_biogas_survives_gast_exclusion(self):
        self.assertTrue(funnel().sector_hits(ann("Biogastechnik und Anlagenbau", name="X GmbH")))


class SwissDetection(unittest.TestCase):
    def kinds(self, text):
        return [(f.kind, f.summary) for f in funnel().swiss_findings(text)]

    def test_director_old_format(self):
        res = funnel().swiss_findings("Geschäftsführer: Keller, Urs, Zug / Schweiz, *14.02.1971; "
                                      "Huber, Anna, München, *02.09.1985.")
        persons = [f for f in res if f.kind == "person"]
        self.assertEqual(len(persons), 1)
        self.assertIn("Keller, Urs", persons[0].summary)
        self.assertIn("*14.02.1971", persons[0].summary)
        self.assertIn("Zug / Schweiz", persons[0].summary)
        self.assertTrue(persons[0].summary.startswith("Geschäftsführer"))

    def test_director_dob_first_no_spaces(self):
        res = funnel().swiss_findings("Prokura: Müller, Hans-Peter, *01.02.1970, Zürich/Schweiz")
        p = [f for f in res if f.kind == "person"]
        self.assertEqual(len(p), 1)
        self.assertIn("Müller, Hans-Peter", p[0].summary)
        self.assertIn("Zürich/Schweiz", p[0].summary)

    def test_director_city_only(self):
        res = funnel().swiss_findings("Vorstand: Rossi, Marco, Lugano, *03.03.1966")
        self.assertEqual([f.kind for f in res], ["person"])

    def test_entity_with_city_and_suffix_variants(self):
        for text, needle in [
            ("Gesellschafterin ist die Alpen Energie AG, Zug.", "Alpen Energie AG"),
            ("Gründerin: Helvetic Grid Holding AG mit Sitz in Stans", "Helvetic Grid Holding AG"),
            ("Alleingesellschafterin ist die Nordlicht Trading GmbH (Schweiz).", "Nordlicht Trading GmbH"),
            ("Muster Energie SA, CH-6900 Lugano", "Muster Energie SA"),
            ("die Gotthard Power AG nach schweizerischem Recht", "Gotthard Power AG"),
        ]:
            ents = [f for f in funnel().swiss_findings(text) if f.kind == "entity"]
            self.assertTrue(ents, text)
            self.assertIn(needle, ents[0].summary, text)
            self.assertNotIn("Gesellschafterin", ents[0].summary)

    def test_identifiers(self):
        kinds = dict(self.kinds("UID CHE-123.456.789, Tel. +41 41 123 45 67, www.beispiel.ch, 6300 Zug"))
        self.assertIn("identifier", kinds)
        summaries = " ".join(s for _, s in self.kinds(
            "UID CHE-123.456.789, Tel. +41 41 123 45 67, www.beispiel.ch, Bahnhofstr. 1, 6300 Zug"))
        for label in ("UID", "phone", "domain", "Swiss address"):
            self.assertIn(label, summaries)

    def test_false_positives(self):
        for text in ("Energieversorgung Sächsische Schweiz GmbH", "in der Sächsischen Schweiz",
                     "Lieferung Zug um Zug gegen Zahlung", "Im Zuge der Neuordnung",
                     "Bezug von Strom", "Bosch-Gruppe", "Geschäftsführer: Bernhard, Klaus, Bernau, *01.01.1970",
                     "Region Cham (Oberpfalz)", "Baden-Württemberg Amtsgericht Stuttgart HRB 1",
                     "Basel III Anforderungen", "Herr Schweizer, Stuttgart"):
            self.assertEqual(self.kinds(text), [], text)

    def test_ambiguous_city_needs_corroboration(self):
        self.assertEqual(self.kinds("Geschäftsanschrift: Marktplatz 1, 93413 Cham"), [])
        found = self.kinds("Gesellschafter mit Sitz in Cham, Kanton Zug, Schweiz")
        self.assertTrue(any("Cham" in s for _, s in found))

    def test_all_caps_text(self):
        self.assertTrue(self.kinds("GESELLSCHAFTERIN: ALPINE ENERGY AG, ZUG (SCHWEIZ)"))

    def test_keyword_dedup_and_count(self):
        res = [f for f in funnel().swiss_findings("Schweiz ... Schweiz ... Schweiz") if f.kind == "keyword"]
        self.assertEqual(len(res), 1)
        self.assertIn("3×", res[0].summary)


class FixtureFunnel(unittest.TestCase):
    def evaluate(self, name):
        text = (FIX / name).read_text(encoding="utf-8")
        a = ann(text, name=radar.LocalInboxSource.guess_company_name(radar.normalize_text(text)))
        return a, funnel().evaluate(a)

    def test_neueintragung_with_swiss_director_alerts(self):
        a, ev = self.evaluate("neueintragung_ch_director.txt")
        self.assertTrue(ev.alert)
        self.assertEqual(a.register_number, "HRB 287654")
        self.assertEqual(a.court, "Amtsgericht München")
        self.assertIn("Neueintragung", ev.events)
        self.assertEqual(ev.findings[0].summary,
                         "Geschäftsführer: Keller, Urs (*14.02.1971) – residence: Baar / Schweiz")

    def test_cross_border_merger_alerts(self):
        _, ev = self.evaluate("umwandlung_ch_ag.txt")
        self.assertTrue(ev.alert)
        kinds = {f.kind for f in ev.findings}
        self.assertTrue({"entity", "identifier"} <= kinds)

    def test_saxony_decoy_does_not_alert(self):
        _, ev = self.evaluate("false_positive_saxony.txt")
        self.assertTrue(ev.sector_hits)
        self.assertFalse(ev.alert, [f.summary for f in ev.findings])

    def test_gastro_with_swiss_director_stops_at_step1(self):
        _, ev = self.evaluate("gastro_no_sector.txt")
        self.assertEqual(ev.sector_hits, [])
        self.assertFalse(ev.alert)


class SnapshotMapping(unittest.TestCase):
    def test_rbk_record(self):
        data = json.loads((FIX / "snapshot_sample.json").read_text(encoding="utf-8"))
        a = radar.announcement_from_rbk(data["announcements"][0], "github_snapshots")
        self.assertEqual(a.uid, "hrbk:95001")
        self.assertEqual(a.register_number, "HRB 99881")
        self.assertEqual(a.court, "Amtsgericht Düsseldorf")
        self.assertTrue(a.company_key.startswith("reg|duesseldorf|hrb99881") or
                        a.company_key.startswith("reg|dusseldorf|hrb99881"))


class HandelsregisterParsing(unittest.TestCase):
    PAGE = """<html><body><form id="bekanntMachungenForm" name="bekanntMachungenForm" method="post">
      <input type="hidden" name="bekanntMachungenForm" value="bekanntMachungenForm"/>
      <input id="bekanntMachungenForm:datum_von_input" name="bekanntMachungenForm:datum_von_input" type="text" value=""/>
      <input id="bekanntMachungenForm:datum_bis_input" name="bekanntMachungenForm:datum_bis_input" type="text" value=""/>
      <input type="checkbox" name="bekanntMachungenForm:land" value="bw" checked="checked"/>
      <input type="checkbox" name="bekanntMachungenForm:other" value="x"/>
      <select name="bekanntMachungenForm:gericht_input"><option value="">alle</option><option value="M1" selected>München</option></select>
      <button id="bekanntMachungenForm:rrbSuche" name="bekanntMachungenForm:rrbSuche" type="submit">Suchen</button>
      <input type="hidden" name="javax.faces.ViewState" value="-123:456"/>
      <script id="bekanntMachungenForm:j_idt999" type="text/javascript">fireBekanntmachung2 = function() {return PrimeFaces.ab({s:"bekanntMachungenForm:j_idt999",f:"bekanntMachungenForm",pa:arguments[0]});}</script>
    </form></body></html>"""

    RESULT = """<partial-response><changes><update id="bekanntMachungenForm"><![CDATA[
      <form id="bekanntMachungenForm"><dl id="bekanntMachungenForm:datalistId_list" class="ui-datalist-data">
        <dt>13.11.2026</dt>
        <dd><ul>
          <li><a href="#" onclick="fireBekanntmachung2('Fri Nov 13 00:00:00 CET 2026', '95001');;PrimeFaces.ab({});return false;">
            <label>Registerbekanntmachung nach dem Umwandlungsgesetz<br/>Nordrhein-Westfalen Amtsgericht Düsseldorf HRB 99881<br/>Rheinische Energiehandel GmbH – Düsseldorf</label></a></li>
          <li><a href="#" onclick="fireBekanntmachung2('Fri Nov 13 00:00:00 CET 2026', '95002');return false;">
            <label>– gelöscht –<br/>Löschungsankündigung<br/>Bayern Amtsgericht München HRB 1234 früher Amtsgericht Augsburg<br/>Muster – Partner GmbH – München</label></a></li>
        </ul></dd>
      </dl></form>]]></update>
      <update id="j_id1:javax.faces.ViewState:0"><![CDATA[-999:111]]></update></changes></partial-response>"""

    DETAIL = """<partial-response><changes><update id="bekanntMachungenForm"><![CDATA[
      <div id="rrbPanel"><div id="rrbPanel_content">13.11.2026 (Bekanntmachungsdatum)<br/><br/>
      Nordrhein-Westfalen Amtsgericht Düsseldorf HRB 99881<br/>Text mit Zug (Schweiz).</div></div>]]></update>
      <update id="j_id1:javax.faces.ViewState:0"><![CDATA[-999:222]]></update></changes></partial-response>"""

    def test_form_serialisation(self):
        soup = radar.BeautifulSoup(self.PAGE, "lxml")
        form = soup.find("form", id="bekanntMachungenForm")
        data = radar.HandelsregisterSource.serialize_form(form)
        self.assertEqual(data["javax.faces.ViewState"], "-123:456")
        self.assertEqual(data["bekanntMachungenForm:land"], "bw")
        self.assertNotIn("bekanntMachungenForm:other", data)
        self.assertEqual(data["bekanntMachungenForm:gericht_input"], "M1")
        self.assertEqual(radar.HandelsregisterSource.find_remote_command(soup, self.PAGE),
                         "bekanntMachungenForm:j_idt999")

    def test_result_list_and_detail(self):
        html, vs = radar.HandelsregisterSource.parse_partial_response(self.RESULT)
        self.assertEqual(vs, "-999:111")
        entries = radar.HandelsregisterSource.parse_result_list(html)
        self.assertEqual(len(entries), 2)
        e0, e1 = entries
        self.assertEqual((e0["id"], e0["date"], e0["registernummer"], e0["company_name"], e0["company_seat"]),
                         ("95001", "2026-11-13", "HRB 99881", "Rheinische Energiehandel GmbH", "Düsseldorf"))
        self.assertEqual(e1["type"], "Löschungsankündigung")
        self.assertEqual(e1["company_name"], "Muster – Partner GmbH")
        text, vs2 = radar.HandelsregisterSource.parse_detail(self.DETAIL)
        self.assertEqual(vs2, "-999:222")
        self.assertIn("Zug (Schweiz)", text)
        self.assertTrue(text.startswith("13.11.2026"))


class _Hook(BaseHTTPRequestHandler):
    requests: list = []
    fail_first_with_429 = False

    def do_POST(self):  # noqa: N802
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        if _Hook.fail_first_with_429:
            _Hook.fail_first_with_429 = False
            self.send_response(429)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"retry_after": 0.05}')
            return
        _Hook.requests.append((self.path, self.headers.get("Content-Type", ""), body))
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b"{}")

    def log_message(self, *a):
        pass


class FakeDiscord:
    def __enter__(self):
        _Hook.requests = []
        self.srv = HTTPServer(("127.0.0.1", 0), _Hook)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        return self

    @property
    def url(self):
        return f"http://127.0.0.1:{self.srv.server_port}/api/webhooks/1/abc"

    def __exit__(self, *a):
        self.srv.shutdown()


def notifier_for(url):
    n = radar.DiscordNotifier({"webhook_url": url, "max_text_chars": 3000, "attach_full_text": True}, CFG["http"])
    n.http.limiter = radar.RateLimiter(0, 0)
    return n


class DiscordAlerts(unittest.TestCase):
    def alert(self, text_len=200):
        a = ann((FIX / "umwandlung_ch_ag.txt").read_text() + " x" * text_len, name="Rheinische Energiehandel GmbH")
        ev = funnel().evaluate(a)
        return radar.build_alert(a, ev, 15)

    def test_payload_respects_discord_limits(self):
        n = notifier_for("https://discord.com/api/webhooks/1/abc")
        payload, attach = n.build_payload(self.alert(5000))
        e = payload["embeds"][0]
        self.assertLessEqual(len(e["description"]), 4096)
        for fld in e["fields"]:
            self.assertLessEqual(len(fld["value"]), 1024)
        total = len(e["title"]) + len(e["description"]) + len(e["footer"]["text"]) + \
            sum(len(f["name"]) + len(f["value"]) for f in e["fields"])
        self.assertLessEqual(total, 6000)
        self.assertIsNotNone(attach)
        names = [f["name"] for f in e["fields"]]
        self.assertIn("🇨🇭 Swiss connection", names)
        self.assertIn("HRB 99881", json.dumps(payload, ensure_ascii=False))

    def test_send_json_multipart_and_429_retry(self):
        with FakeDiscord() as fd:
            n = notifier_for(fd.url)
            n.configured  # noqa: B018  (http URL not "configured" -> bypass below)
            n.__class__ = type("N", (radar.DiscordNotifier,), {"configured": property(lambda s: True)})
            _Hook.fail_first_with_429 = True
            n.send(self.alert(10))
            n.send(self.alert(5000))
        self.assertEqual(len(_Hook.requests), 2)
        (p1, ct1, b1), (p2, ct2, b2) = _Hook.requests
        self.assertIn("wait=true", p1)
        self.assertTrue(ct1.startswith("application/json"))
        self.assertIn("Helvetia Power Trading AG", json.loads(b1)["embeds"][0]["fields"][3]["value"])
        self.assertTrue(ct2.startswith("multipart/form-data"))
        self.assertIn(b'name="files[0]"', b2)


class EndToEnd(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        inbox = self.tmp / "inbox"
        inbox.mkdir()
        for f in FIX.glob("*.txt"):
            shutil.copy(f, inbox / f.name)
        self.cfg = radar.deep_merge(CFG, {
            "database": {"path": str(self.tmp / "db.sqlite3")},
            "run": {"lock_file": str(self.tmp / "lock")},
            "sources": {"github_snapshots": {"enabled": False},
                        "local": {"enabled": True, "inbox_dir": str(inbox), "archive_dir": str(inbox / "done")},
                        "opencorporates": {"enabled": False, "enrich_candidates": False}},
            "http": {"min_delay_seconds": 0},
        })

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def args(self, **kw):
        base = dict(dry_run=False, days=None, since=None, until=None, source=None, reprocess=False, no_enrich=True)
        base.update(kw)
        return argparse.Namespace(**base)

    def test_run_alerts_once_and_archives(self):
        orig = radar.DiscordNotifier.configured
        radar.DiscordNotifier.configured = property(lambda s: True)
        try:
            with FakeDiscord() as fd:
                self.cfg["discord"]["webhook_url"] = fd.url
                rc = radar.run(self.cfg, self.args())
                self.assertEqual(rc, 0)
                self.assertEqual(len(_Hook.requests), 2)  # director + merger
                # files archived, a second run finds nothing new
                self.assertEqual(list((self.tmp / "inbox").glob("*.txt")), [])
                for f in FIX.glob("*.txt"):  # re-drop same files: dedup by uid
                    shutil.copy(f, self.tmp / "inbox" / f.name)
                radar.run(self.cfg, self.args())
                self.assertEqual(len(_Hook.requests), 2)
        finally:
            radar.DiscordNotifier.configured = orig
        db = radar.Database(Path(self.cfg["database"]["path"]))
        rows = db.conn.execute("SELECT status, register_number FROM alerts ORDER BY id").fetchall()
        self.assertEqual([r["status"] for r in rows], ["sent", "sent"])
        self.assertEqual({r["register_number"] for r in rows}, {"HRB 287654", "HRB 99881"})
        self.assertEqual(db.conn.execute("SELECT COUNT(*) FROM processed").fetchone()[0], 4)

    def test_failed_delivery_is_retried_next_run(self):
        orig = radar.DiscordNotifier.configured
        radar.DiscordNotifier.configured = property(lambda s: True)
        try:
            self.cfg["discord"]["webhook_url"] = "http://127.0.0.1:9/api/webhooks/1/x"  # nothing listens
            orig_sleep = radar.time.sleep
            radar.time.sleep = lambda s: None
            try:
                rc = radar.run(self.cfg, self.args())
            finally:
                radar.time.sleep = orig_sleep
            self.assertEqual(rc, 1)
            db = radar.Database(Path(self.cfg["database"]["path"]))
            self.assertEqual(len(db.pending_alerts()), 2)
            db.close()
            with FakeDiscord() as fd:
                self.cfg["discord"]["webhook_url"] = fd.url
                self.assertEqual(radar.run(self.cfg, self.args()), 0)
                self.assertEqual(len(_Hook.requests), 2)
        finally:
            radar.DiscordNotifier.configured = orig

    def test_dry_run_writes_nothing(self):
        rc = radar.run(self.cfg, self.args(dry_run=True))
        self.assertEqual(rc, 0)
        db = radar.Database(Path(self.cfg["database"]["path"]))
        self.assertEqual(db.conn.execute("SELECT COUNT(*) FROM processed").fetchone()[0], 0)
        self.assertEqual(len(list((self.tmp / "inbox").glob("*.txt"))), 4)


if __name__ == "__main__":
    unittest.main()
