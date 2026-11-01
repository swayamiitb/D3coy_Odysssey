"""SACHET connector: India's national CAP alert feed in, SACHET-compatible CAP warnings out, and a hardened CAP ingest.

Three parts, independent of each other:

1. **Reader.** NDMA's SACHET publishes a public-domain RSS feed of CAP 1.2 alerts (IMD, SDMAs, CWC, INCOIS). Odyssey
   reads it read-only every 15 minutes (snapshot-backed, like the other feeds), infers the states each alert concerns
   (sender office, state name, district name, script of the text; every inference carries its basis), and matches them
   to the operators in those states. The point for a cyber early-warning system: *is this outage the weather, or an
   attack?* A disaster alert on an operator's state is context for its warnings, and an attack landing during a
   disaster is worse.
2. **Writer.** Odyssey's own warnings rendered as CAP 1.2, one `<info>` per language, the format SACHET publishes, so
   routing them through an authorised agency is configuration, not redevelopment. Drills and red-team runs are always
   `status=Exercise`. "SACHET-compatible", never "connected to SACHET".
3. **Guard.** `POST /api/sensor/cap` accepts CAP from any upstream and treats every message as hostile until proven
   otherwise: DTDs and entities refused before parsing (XXE, billion laughs), size cap, well-formedness, required
   fields, an allow-list of authorised senders, replay of an identifier, stale messages, and a flood cap. Every
   decision is a hash-chained ledger event. No dependency beyond the standard library and httpx.
"""

from __future__ import annotations

import collections
import datetime as dt
import html
import json
import re
import sqlite3
import threading
import time
import unicodedata
import xml.etree.ElementTree as ET
from email.utils import parsedate_to_datetime
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from .engine.ledger import Ledger

ROOT = Path(__file__).resolve().parents[2]
RAW = ROOT / "data" / "raw"
CAP_NS = "urn:oasis:names:tc:emergency:cap:1.2"
RSS_URL = "https://sachet.ndma.gov.in/cap_public_website/rss/rss_india.xml"
FEED_HOST = "sachet.ndma.gov.in"
SNAPSHOT_RSS = RAW / "sachet_rss.xml"
SNAPSHOT_CAP = RAW / "sachet_cap_sample.xml"
FEED_INTERVAL_S = 900
MAX_XML_BYTES = 2 * 1024 * 1024
RATE_WINDOW_S, RATE_MAX = 60, 30               # inbound CAP messages per source per minute
SEVERITY = {"Compromise": "Extreme", "Critical": "Severe", "High": "Moderate", "Medium": "Minor", "Watch": "Minor"}
URGENCY = {"Compromise": "Immediate", "Critical": "Immediate", "High": "Expected", "Medium": "Future", "Watch": "Future"}
OWN_SENDER = "odyssey@ncew.local"
TRUSTED_DOMAINS = ("ndma.gov.in", "imd.gov.in", "mausam.imd.gov.in", "cwc.gov.in", "incois.gov.in", "cert-in.org.in")
TRUSTED_PREFIXES = ("IMD-", "CWC-", "INCOIS-", "SDMA-", "NDMA")
REFUSALS = ("rate_limited", "oversize", "xxe", "malformed", "missing_fields", "untrusted_sender", "replay", "stale")

# Regional offices named in the feed's author/sender fields -> state. Explainable, not exhaustive.
OFFICES = {
    "chennai": "Tamil Nadu", "kolkata": "West Bengal", "hyderabad": "Telangana", "mumbai": "Maharashtra", "nagpur": "Maharashtra",
    "pune": "Maharashtra", "ahmedabad": "Gujarat", "bengaluru": "Karnataka", "bangalore": "Karnataka",
    "thiruvananthapuram": "Kerala", "bhubaneswar": "Odisha", "jaipur": "Rajasthan", "lucknow": "Uttar Pradesh",
    "new delhi": "Delhi", "delhi": "Delhi", "amaravati": "Andhra Pradesh", "visakhapatnam": "Andhra Pradesh",
    "guwahati": "Assam", "patna": "Bihar", "ranchi": "Jharkhand", "raipur": "Chhattisgarh", "bhopal": "Madhya Pradesh",
    "chandigarh": "Punjab", "shimla": "Himachal Pradesh", "srinagar": "Jammu and Kashmir", "dehradun": "Uttarakhand",
    "goa": "Goa", "agartala": "Tripura", "shillong": "Meghalaya", "imphal": "Manipur", "aizawl": "Mizoram",
    "kohima": "Nagaland", "gangtok": "Sikkim", "itanagar": "Arunachal Pradesh", "port blair": "Andaman and Nicobar Islands",
}
STATES = ["Andhra Pradesh", "Arunachal Pradesh", "Assam", "Bihar", "Chhattisgarh", "Goa", "Gujarat", "Haryana", "Himachal Pradesh",
          "Jharkhand", "Karnataka", "Kerala", "Madhya Pradesh", "Maharashtra", "Manipur", "Meghalaya", "Mizoram", "Nagaland", "Odisha",
          "Punjab", "Rajasthan", "Sikkim", "Tamil Nadu", "Telangana", "Tripura", "Uttar Pradesh", "Uttarakhand", "West Bengal",
          "Delhi", "Jammu and Kashmir", "Ladakh", "Puducherry", "Chandigarh", "Andaman and Nicobar Islands", "Lakshadweep"]
# Districts and cities of the states the constituency's operators sit in (an alert naming one of them concerns that state).
DISTRICTS = {
    "Andhra Pradesh": ["Visakhapatnam", "Vijayawada", "Guntur", "Nellore", "Kurnool", "Tirupati", "Kadapa", "Anantapur", "Krishna",
                       "Prakasam", "Srikakulam", "Vizianagaram", "East Godavari", "West Godavari", "Chittoor", "Eluru", "Kakinada",
                       "Rajahmundry", "Ongole", "Nandyal", "Bapatla", "Palnadu", "Annamayya", "Konaseema"],
    "Delhi": ["New Delhi", "North Delhi", "South Delhi", "East Delhi", "West Delhi", "Central Delhi", "Shahdara"],
    "Gujarat": ["Ahmedabad", "Surat", "Vadodara", "Rajkot", "Bhavnagar", "Jamnagar", "Kutch", "Kachchh", "Gandhinagar", "Junagadh", "Anand",
                "Bharuch", "Navsari", "Valsad", "Porbandar", "Amreli", "Mehsana", "Banaskantha", "Sabarkantha", "Morbi", "Gir Somnath",
                "Devbhumi Dwarka", "Dahod", "Panchmahal", "Kheda", "Surendranagar", "Patan", "Narmada", "Tapi", "Dang", "Botad", "Aravalli"],
    "Karnataka": ["Bengaluru", "Bangalore", "Mysuru", "Mysore", "Mangaluru", "Mangalore", "Hubballi", "Belagavi", "Belgaum", "Udupi",
                  "Dakshina Kannada", "Uttara Kannada", "Shivamogga", "Tumakuru", "Ballari", "Kalaburagi", "Chikkamagaluru", "Hassan",
                  "Kodagu", "Davangere", "Raichur", "Bidar", "Vijayapura", "Bagalkot", "Chitradurga", "Mandya", "Kolar", "Chikkaballapur",
                  "Ramanagara", "Yadgir", "Koppal", "Gadag", "Haveri", "Dharwad", "Chamarajanagar"],
    "Kerala": ["Thiruvananthapuram", "Kochi", "Ernakulam", "Kozhikode", "Thrissur", "Kollam", "Alappuzha", "Kottayam", "Palakkad",
               "Malappuram", "Kannur", "Kasaragod", "Wayanad", "Idukki", "Pathanamthitta"],
    "Maharashtra": ["Mumbai", "Pune", "Nagpur", "Thane", "Nashik", "Aurangabad", "Sambhajinagar", "Raigad", "Ratnagiri", "Sindhudurg",
                    "Kolhapur", "Solapur", "Satara", "Sangli", "Palghar", "Ahmednagar", "Ahilyanagar", "Jalgaon", "Dhule", "Nanded", "Latur",
                    "Amravati", "Akola", "Chandrapur", "Gondia", "Wardha", "Yavatmal", "Buldhana", "Washim", "Hingoli", "Parbhani", "Beed",
                    "Osmanabad", "Dharashiv", "Jalna", "Nandurbar", "Bhandara", "Gadchiroli"],
    "Odisha": ["Bhubaneswar", "Cuttack", "Puri", "Ganjam", "Balasore", "Baleswar", "Kendrapara", "Jagatsinghpur", "Khordha", "Mayurbhanj",
               "Sambalpur", "Sundargarh", "Koraput", "Rayagada", "Kalahandi", "Bhadrak", "Jajpur", "Dhenkanal", "Angul", "Bargarh",
               "Jharsuguda", "Gajapati", "Nayagarh", "Kandhamal", "Malkangiri", "Nabarangpur", "Nuapada", "Bolangir", "Balangir", "Boudh",
               "Subarnapur", "Deogarh", "Keonjhar", "Kendujhar"],
    "Rajasthan": ["Jaipur", "Jodhpur", "Udaipur", "Kota", "Bikaner", "Ajmer", "Alwar", "Bharatpur", "Sikar", "Jaisalmer", "Barmer", "Jhunjhunu",
                  "Churu", "Sri Ganganagar", "Ganganagar", "Hanumangarh", "Bhilwara", "Chittorgarh", "Pali", "Nagaur", "Tonk", "Banswara",
                  "Dungarpur", "Jalore", "Sirohi", "Bundi", "Baran", "Jhalawar", "Dausa", "Karauli", "Sawai Madhopur", "Dholpur", "Pratapgarh",
                  "Rajsamand"],
    "Tamil Nadu": ["Chennai", "Coimbatore", "Madurai", "Tiruchirappalli", "Trichy", "Salem", "Tirunelveli", "Vellore", "Erode", "Tiruppur",
                   "Thanjavur", "Kanchipuram", "Tiruvallur", "Chengalpattu", "Cuddalore", "Nagapattinam", "Thoothukudi", "Kanyakumari",
                   "Dindigul", "Villupuram", "Viluppuram", "Krishnagiri", "Dharmapuri", "Namakkal", "Karur", "Pudukkottai", "Ramanathapuram",
                   "Sivaganga", "Sivagangai", "Virudhunagar", "Tenkasi", "Nilgiris", "Mayiladuthurai", "Ariyalur", "Perambalur", "Kallakurichi",
                   "Ranipet", "Tirupattur", "Tirupathur", "Theni", "Tiruvannamalai", "Tiruvarur"],
    "Telangana": ["Hyderabad", "Warangal", "Nizamabad", "Karimnagar", "Khammam", "Nalgonda", "Mahbubnagar", "Mahabubnagar", "Adilabad", "Medak",
                  "Rangareddy", "Ranga Reddy", "Sangareddy", "Siddipet", "Suryapet", "Nagarkurnool", "Peddapalli", "Mancherial", "Jagtial",
                  "Jangaon", "Bhadradri", "Kothagudem", "Kamareddy", "Nirmal", "Medchal", "Vikarabad", "Wanaparthy", "Yadadri", "Mulugu",
                  "Narayanpet", "Jogulamba", "Gadwal", "Rajanna", "Sircilla", "Mahabubabad", "Hanamkonda", "Jayashankar", "Bhupalpally",
                  "Komaram Bheem", "Asifabad"],
    "Uttar Pradesh": ["Lucknow", "Kanpur", "Varanasi", "Prayagraj", "Allahabad", "Agra", "Meerut", "Ghaziabad", "Noida", "Gautam Buddha Nagar",
                      "Gorakhpur", "Bareilly", "Aligarh", "Moradabad", "Saharanpur", "Jhansi", "Mathura", "Ayodhya", "Faizabad", "Firozabad",
                      "Muzaffarnagar", "Bulandshahr", "Rampur", "Shahjahanpur", "Sitapur", "Hardoi", "Unnao", "Rae Bareli", "Raebareli",
                      "Sultanpur", "Azamgarh", "Basti", "Deoria", "Ballia", "Mirzapur", "Sonbhadra", "Banda", "Lalitpur", "Etawah", "Mainpuri",
                      "Bijnor", "Amroha", "Sambhal", "Badaun", "Budaun", "Pilibhit", "Lakhimpur", "Kheri", "Bahraich", "Gonda", "Barabanki",
                      "Amethi", "Pratapgarh", "Jaunpur", "Ghazipur", "Chandauli", "Bhadohi", "Kaushambi", "Fatehpur", "Hamirpur", "Mahoba",
                      "Jalaun", "Auraiya", "Kannauj", "Farrukhabad", "Hathras", "Etah", "Kasganj", "Shamli", "Baghpat", "Hapur", "Mau",
                      "Kushinagar", "Maharajganj", "Siddharthnagar", "Sant Kabir Nagar", "Ambedkar Nagar", "Shravasti", "Balrampur"],
    "West Bengal": ["Kolkata", "Howrah", "Hooghly", "Darjeeling", "Jalpaiguri", "Siliguri", "Malda", "Murshidabad", "Nadia", "Bardhaman",
                    "Burdwan", "Birbhum", "Bankura", "Purulia", "Jhargram", "Paschim Medinipur", "Purba Medinipur", "Midnapore", "Medinipur",
                    "North 24 Parganas", "South 24 Parganas", "24 Parganas", "Cooch Behar", "Alipurduar", "Uttar Dinajpur", "Dakshin Dinajpur",
                    "Kalimpong", "Paschim Bardhaman", "Purba Bardhaman"],
}
# The script a non-English alert is written in points at the states that use it (a weak hint; stated as such).
SCRIPTS = {"TELUGU": ["Andhra Pradesh", "Telangana"], "BENGALI": ["West Bengal"], "TAMIL": ["Tamil Nadu"], "KANNADA": ["Karnataka"],
           "MALAYALAM": ["Kerala"], "GUJARATI": ["Gujarat"], "ORIYA": ["Odisha"]}

_DISTRICT_RX = {state: re.compile(r"(?<![A-Za-z])(" + "|".join(sorted((re.escape(d) for d in ds), key=len, reverse=True)) + r")(?![A-Za-z])", re.I)
                for state, ds in DISTRICTS.items()}
_STATE_RX = re.compile(r"(?<![A-Za-z])(" + "|".join(sorted((re.escape(s) for s in STATES), key=len, reverse=True)) + r")(?![A-Za-z])", re.I)


# ----------------------------------------------------------------------------------------------------- parsing
def safe_parse(data: bytes | str) -> ET.Element:
    """XXE and entity-expansion defence without a dependency: refuse any DTD, then parse with the standard library.
    CAP never carries a DTD, so nothing legitimate is lost; expat does not fetch external entities on its own."""
    raw = data if isinstance(data, bytes) else data.encode("utf-8")
    if len(raw) > MAX_XML_BYTES:
        raise ValueError("oversize")
    low = raw[:65536].lower() if len(raw) > 65536 else raw.lower()
    if b"<!doctype" in low or b"<!entity" in low or b"<!doctype" in raw.lower() or b"<!entity" in raw.lower():
        raise ValueError("xxe")
    try:
        return ET.fromstring(raw)
    except ET.ParseError as exc:
        raise ValueError("malformed") from exc


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _child(el: ET.Element, name: str) -> ET.Element | None:
    for c in el:
        if _local(c.tag) == name:
            return c
    return None


def _text(el: ET.Element | None, name: str) -> str:
    c = _child(el, name) if el is not None else None
    return (c.text or "").strip() if c is not None else ""


def _iso(d: dt.datetime | None) -> str | None:
    return d.astimezone(dt.timezone.utc).isoformat().replace("+00:00", "Z") if d else None


def _when(s: str | None) -> dt.datetime | None:
    if not s:
        return None
    try:
        d = dt.datetime.fromisoformat(s.replace("Z", "+00:00"))
        return d if d.tzinfo else d.replace(tzinfo=dt.timezone.utc)
    except ValueError:
        pass
    try:
        return parsedate_to_datetime(s)
    except (TypeError, ValueError):
        return None


def parse_cap(data: bytes | str) -> dict:
    """A CAP 1.2 alert as a dict; raises ValueError('malformed') when the root is not a CAP alert."""
    root = safe_parse(data)
    if _local(root.tag) != "alert":
        raise ValueError("malformed")
    infos = []
    for info in (c for c in root if _local(c.tag) == "info"):
        areas = [_text(a, "areaDesc") for a in info if _local(a.tag) == "area"]
        infos.append({"language": _text(info, "language") or "en-US", "category": _text(info, "category"), "event": _text(info, "event"),
                      "urgency": _text(info, "urgency"), "severity": _text(info, "severity"), "certainty": _text(info, "certainty"),
                      "headline": _text(info, "headline"), "description": _text(info, "description"), "instruction": _text(info, "instruction"),
                      "expires": _text(info, "expires") or None, "areas": [a for a in areas if a]})
    return {"identifier": _text(root, "identifier"), "sender": _text(root, "sender"), "sent": _text(root, "sent"), "status": _text(root, "status"),
            "msgType": _text(root, "msgType"), "scope": _text(root, "scope"), "references": _text(root, "references"),
            "expires": next((i["expires"] for i in infos if i["expires"]), None), "infos": infos,
            "namespace": root.tag[1:].split("}")[0] if root.tag.startswith("{") else None}


def parse_rss(data: bytes | str) -> list[dict]:
    root = safe_parse(data)
    channel = _child(root, "channel") or root
    items = []
    for it in (c for c in channel if _local(c.tag) == "item"):
        link = _text(it, "link")
        guid = _text(it, "guid")
        ident = guid or (parse_qs(urlparse(link).query).get("identifier") or [""])[0]
        pub = _when(_text(it, "pubDate"))
        items.append({"identifier": ident, "title": html.unescape(_text(it, "title")), "description": html.unescape(_text(it, "description")),
                      "category": _text(it, "category"), "author": _text(it, "author"), "link": link, "published": _iso(pub)})
    return items


# ---------------------------------------------------------------------------------------------- state inference
def _scripts_of(text: str) -> set[str]:
    out = set()
    for ch in text[:400]:
        if ch.isalpha() and ord(ch) > 0x2000:
            try:
                name = unicodedata.name(ch).split(" ")[0]
            except ValueError:
                continue
            if name in SCRIPTS:
                out.add(name)
    return out


def infer_states(title: str, author: str = "", areas: list[str] | None = None, sender: str = "") -> list[dict]:
    """Which states an alert concerns, each with the basis of the inference and a confidence."""
    found: dict[str, dict] = {}

    def add(state, basis, conf):
        cur = found.get(state)
        if cur is None or conf > cur["confidence"]:
            found[state] = {"state": state, "basis": basis, "confidence": conf}

    text = " ".join([title or ""] + list(areas or []))
    for m in _STATE_RX.finditer(text):
        add(m.group(1).title().replace(" And ", " and "), f"state named: {m.group(1)}", 0.95)
    for src in (author or "", sender or ""):
        low = src.lower()
        for state in STATES:
            if state.lower() in low and ("sdma" in low or "disaster" in low):
                add(state, f"sender: {src.strip()}", 0.9)
        for office, state in OFFICES.items():
            if re.search(r"(?<![a-z])" + re.escape(office) + r"(?![a-z])", low):
                add(state, f"sender office: {src.strip()}", 0.85)
    for state, rx in _DISTRICT_RX.items():
        m = rx.search(text)
        if m:
            add(state, f"district named: {m.group(1)}", 0.75)
    if not found:
        for script in _scripts_of(text):
            for state in SCRIPTS[script]:
                add(state, f"text in {script.title()} script", 0.4)
    return sorted(found.values(), key=lambda x: -x["confidence"])


def match_orgs(states: list[dict], orgs: list[dict]) -> list[dict]:
    names = {s["state"]: s for s in states}
    return [{"org_id": o["id"], "name": o["name"], "sector": o["sector"], "state": o["state"], "basis": names[o["state"]]["basis"],
             "confidence": names[o["state"]]["confidence"]} for o in orgs if o.get("state") in names]


# ------------------------------------------------------------------------------------------------------ writer
def write_cap(alert: dict, infos: list[dict], status: str = "Exercise", sender: str = OWN_SENDER, scope: str = "Restricted",
              now: dt.datetime | None = None) -> str:
    """Odyssey's warning as CAP 1.2, one <info> per language. Every text node is escaped. `alert` needs identifier,
    tier, event, areas (list of str) and may carry references/web/contact; each info needs language, headline,
    description, instruction."""
    now = now or dt.datetime.now(dt.timezone.utc)
    ist = now.astimezone(dt.timezone(dt.timedelta(hours=5, minutes=30)))
    e = html.escape
    tier = alert.get("tier", "High")
    lines = [f'<?xml version="1.0" encoding="UTF-8"?>', f'<alert xmlns="{CAP_NS}">',
             f"  <identifier>{e(alert['identifier'])}</identifier>", f"  <sender>{e(sender)}</sender>",
             f"  <sent>{ist.strftime('%Y-%m-%dT%H:%M:%S+05:30')}</sent>", f"  <status>{e(status)}</status>", "  <msgType>Alert</msgType>",
             f"  <source>Odyssey National Cyber Early Warning (prototype)</source>", f"  <scope>{e(scope)}</scope>"]
    if scope == "Restricted":
        lines.append(f"  <restriction>{e(alert.get('restriction', 'For the addressed operator and its sector CSIRT'))}</restriction>")
    if alert.get("note"):
        lines.append(f"  <note>{e(alert['note'])}</note>")
    if alert.get("references"):
        lines.append(f"  <references>{e(alert['references'])}</references>")
    expires = (now + dt.timedelta(hours=alert.get("expires_hours") or 24)).astimezone(ist.tzinfo).strftime("%Y-%m-%dT%H:%M:%S+05:30")
    for info in infos:
        lines += [f"  <info>", f"    <language>{e(info.get('language', 'en-IN'))}</language>", "    <category>Security</category>",
                  f"    <event>{e(alert.get('event', 'Cyber threat warning'))}</event>", "    <responseType>Prepare</responseType>",
                  f"    <urgency>{URGENCY.get(tier, 'Expected')}</urgency>", f"    <severity>{SEVERITY.get(tier, 'Moderate')}</severity>",
                  f"    <certainty>{e(alert.get('certainty', 'Likely'))}</certainty>", f"    <expires>{expires}</expires>",
                  f"    <senderName>{e(alert.get('sender_name', 'Odyssey (SACHET-compatible prototype, not NDMA)'))}</senderName>",
                  f"    <headline>{e(info.get('headline', ''))}</headline>", f"    <description>{e(info.get('description', ''))}</description>",
                  f"    <instruction>{e(info.get('instruction', ''))}</instruction>"]
        if alert.get("web"):
            lines.append(f"    <web>{e(alert['web'])}</web>")
        if alert.get("contact"):
            lines.append(f"    <contact>{e(alert['contact'])}</contact>")
        for k, v in (alert.get("parameters") or {}).items():
            lines += ["    <parameter>", f"      <valueName>{e(str(k))}</valueName>", f"      <value>{e(str(v))}</value>", "    </parameter>"]
        for area in alert.get("areas") or ["India"]:
            lines += ["    <area>", f"      <areaDesc>{e(area)}</areaDesc>", "    </area>"]
        lines.append("  </info>")
    lines.append("</alert>")
    return "\n".join(lines)


# ------------------------------------------------------------------------------------------------------- guard
def sender_allowed(sender: str) -> bool:
    s = (sender or "").strip()
    if not s:
        return False
    if s == OWN_SENDER or s.startswith(TRUSTED_PREFIXES):
        return True
    low = s.lower()
    m = re.search(r"[\w.+-]+@([\w.-]+)", low)
    if m:
        dom = m.group(1).strip(".")
        return any(dom == d or dom.endswith("." + d) for d in TRUSTED_DOMAINS)
    return any(low == d or low.endswith("." + d) for d in TRUSTED_DOMAINS)


class CapGuard:
    def __init__(self, connect, now: dt.datetime | None = None):
        self.connect = connect
        self.lock = threading.Lock()
        self.feed = {"status": "snapshot", "fetched_at": None, "last_try": None, "items": [], "detail": "not read yet", "ms": None}
        self.next_feed = 0.0
        self.window: dict[str, collections.deque] = collections.defaultdict(lambda: collections.deque(maxlen=RATE_MAX * 2))
        self.counts = collections.Counter()
        conn = connect()
        try:
            self.ensure(conn)
            self.seen = {r[0] for r in conn.execute("SELECT identifier FROM cap_ingest WHERE accepted = 1")}
            for reason, n in conn.execute("SELECT COALESCE(reason, 'accepted'), COUNT(*) FROM cap_ingest GROUP BY reason"):
                self.counts[reason] += n
        finally:
            conn.close()

    @staticmethod
    def ensure(conn: sqlite3.Connection) -> None:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS cap_ingest (
                id INTEGER PRIMARY KEY, ts TEXT NOT NULL, accepted INTEGER NOT NULL, reason TEXT, detail TEXT, identifier TEXT,
                sender TEXT, status TEXT, msg_type TEXT, event TEXT, severity TEXT, areas TEXT, states TEXT, orgs TEXT,
                source_ip TEXT, redteam TEXT, bytes INTEGER, raw TEXT);
        """)
        conn.commit()

    # ---- the reader
    def _orgs(self, conn) -> list[dict]:
        return [dict(zip(("id", "name", "sector", "state"), r)) for r in conn.execute("SELECT id, name, sector, state FROM orgs")]

    @staticmethod
    def _fetch(url: str) -> bytes:
        import httpx
        r = httpx.get(url, timeout=20, follow_redirects=False, headers={"User-Agent": "Odyssey-EWS/0.2 (research; read-only)"})
        r.raise_for_status()
        return r.content

    def read_feed(self, live: bool = True, now: dt.datetime | None = None, fetch=None, force: bool = False) -> dict:
        """The SACHET feed with states and operators inferred per alert; live every 15 min, snapshot otherwise."""
        now = now or dt.datetime.now(dt.timezone.utc)
        with self.lock:
            due = force or time.time() >= self.next_feed or not self.feed["items"]
        if due:
            data, status, detail, ms = None, "snapshot", "", None
            if live:
                t0 = time.perf_counter()
                try:
                    data = (fetch or self._fetch)(RSS_URL)
                    status, detail, ms = "fresh", f"{RSS_URL} read live", round((time.perf_counter() - t0) * 1000)
                except Exception as exc:  # noqa: BLE001 - a feed outage is reported, never fatal
                    status, detail = "offline", f"{type(exc).__name__}: {str(exc)[:100]}; serving the snapshot"
            if data is None and SNAPSHOT_RSS.exists():
                data = SNAPSHOT_RSS.read_bytes()
                detail = detail or f"snapshot {SNAPSHOT_RSS.name}"
            items = []
            if data:
                try:
                    items = parse_rss(data)
                except ValueError as exc:
                    status, detail = "offline", f"feed unreadable ({exc}); nothing to show"
            conn = self.connect()
            try:
                orgs = self._orgs(conn)
            finally:
                conn.close()
            for it in items:
                it["states"] = infer_states(it["title"], it["author"])
                it["orgs"] = match_orgs(it["states"], orgs)
            with self.lock:
                self.feed = {"status": status, "fetched_at": _iso(now) if status == "fresh" else self.feed.get("fetched_at"), "last_try": _iso(now),
                             "items": items, "detail": detail, "ms": ms, "source": "NDMA SACHET public CAP feed (public domain)",
                             "provenance": "REAL", "url": RSS_URL}
                self.next_feed = time.time() + FEED_INTERVAL_S
        with self.lock:
            f = dict(self.feed)
        f["count"] = len(f["items"])
        f["matched"] = sum(1 for i in f["items"] if i["orgs"])
        f["by_state"] = dict(collections.Counter(s["state"] for i in f["items"] for s in i["states"][:1]).most_common(12))
        return f

    def fetch_cap(self, url: str, fetch=None) -> dict:
        """One alert's full CAP message; only from SACHET itself (or loopback for tests), DTDs refused, size capped."""
        u = urlparse(url)
        host = (u.hostname or "").lower()
        if not ((u.scheme == "https" and host == FEED_HOST) or host in ("127.0.0.1", "localhost")):
            raise ValueError("Odyssey fetches CAP only from sachet.ndma.gov.in")
        data = (fetch or self._fetch)(url)
        cap = parse_cap(data)
        areas = [a for i in cap["infos"] for a in i["areas"]]
        cap["states"] = infer_states(" ".join(i["headline"] or i["event"] for i in cap["infos"]), cap["sender"], areas, cap["sender"])
        return cap

    # ---- the guard
    def ingest(self, data: bytes | str, source_ip: str | None = None, redteam: str | None = None,
               now: dt.datetime | None = None) -> dict:
        """Validate, don't trust. The decision ladder, in order: flood, size and DTD, well-formed CAP, required fields,
        authorised sender, replay, stale. Every outcome is written to the ledger."""
        now = now or dt.datetime.now(dt.timezone.utc)
        raw = data if isinstance(data, bytes) else (data or "").encode("utf-8")
        key = source_ip or "unknown"
        with self.lock:
            w = self.window[key]
            cutoff = time.time() - RATE_WINDOW_S
            while w and w[0] < cutoff:
                w.popleft()
            flooded = len(w) >= RATE_MAX
            w.append(time.time())
        cap: dict = {}
        reason = detail = None
        if flooded:
            reason, detail = "rate_limited", f"more than {RATE_MAX} messages in {RATE_WINDOW_S} s from {key}"
        else:
            try:
                cap = parse_cap(raw)
            except ValueError as exc:
                reason = str(exc)
                detail = {"oversize": f"{len(raw)} bytes exceeds {MAX_XML_BYTES}", "xxe": "DTD / entity declaration refused before parsing",
                          "malformed": "not a well-formed CAP 1.2 alert"}.get(reason, reason)
        if reason is None:
            if not (cap.get("identifier") and cap.get("sender") and cap.get("sent")):
                reason, detail = "missing_fields", "identifier, sender and sent are required"
            elif cap.get("namespace") not in (CAP_NS, None):
                reason, detail = "malformed", f"unexpected namespace {cap['namespace']}"
            elif not sender_allowed(cap["sender"]):
                reason, detail = "untrusted_sender", f"{cap['sender'][:80]} is not an authorised agency"
            else:
                with self.lock:
                    replay = cap["identifier"] in self.seen
                if replay:
                    reason, detail = "replay", f"identifier {cap['identifier'][:80]} was already accepted"
                else:
                    exp = _when(cap.get("expires"))
                    if exp and exp < now:
                        reason, detail = "stale", f"expired at {cap['expires']}"
        accepted = reason is None
        states = infer_states(" ".join(i["headline"] or i["event"] for i in cap.get("infos", [])), cap.get("sender", ""),
                              [a for i in cap.get("infos", []) for a in i["areas"]], cap.get("sender", "")) if accepted else []
        conn = self.connect()
        try:
            self.ensure(conn)
            orgs = match_orgs(states, self._orgs(conn)) if accepted else []
            info0 = (cap.get("infos") or [{}])[0]
            conn.execute("""INSERT INTO cap_ingest (ts, accepted, reason, detail, identifier, sender, status, msg_type, event, severity, areas, states,
                            orgs, source_ip, redteam, bytes, raw) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                         (_iso(now), int(accepted), reason, detail, (cap.get("identifier") or "")[:120], (cap.get("sender") or "")[:120],
                          cap.get("status"), cap.get("msgType"), (info0.get("event") or "")[:120], info0.get("severity"),
                          json.dumps([a for i in cap.get("infos", []) for a in i["areas"]][:12]), json.dumps(states), json.dumps(orgs),
                          source_ip, redteam, len(raw), raw[:4000].decode("utf-8", "replace") if accepted else None))
            conn.commit()
            Ledger(conn=conn).append(ts=_iso(now), kind=f"cap.ingest.{'accepted' if accepted else 'refused'}",
                                     subject=(cap.get("identifier") or f"cap:{key}")[:120], source="CAP_INGEST",
                                     provenance="SIM" if redteam else "REAL",
                                     payload={"identifier": cap.get("identifier"), "sender": (cap.get("sender") or "")[:120], "reason": reason, "detail": detail,
                                              "source_ip": source_ip, "redteam": redteam, "event": info0.get("event"), "severity": info0.get("severity"),
                                              "status": cap.get("status"), "states": [s["state"] for s in states], "orgs": [o["org_id"] for o in orgs],
                                              "bytes": len(raw)})
            conn.commit()
        finally:
            conn.close()
        with self.lock:
            if accepted:
                self.seen.add(cap["identifier"])
            self.counts["accepted" if accepted else reason] += 1
        return {"accepted": accepted, "reason": reason, "detail": detail, "identifier": cap.get("identifier"), "sender": cap.get("sender"),
                "event": info0.get("event") if cap else None, "severity": info0.get("severity") if cap else None, "states": states, "orgs": orgs,
                "redteam": redteam}

    def decisions(self, limit: int = 30, conn=None) -> list[dict]:
        own = conn is None
        conn = conn or self.connect()
        try:
            self.ensure(conn)
            cur = conn.cursor()
            cur.row_factory = sqlite3.Row
            out = []
            for r in cur.execute("SELECT * FROM cap_ingest ORDER BY id DESC LIMIT ?", (limit,)):
                d = dict(r)
                d["accepted"] = bool(d["accepted"])
                for k in ("areas", "states", "orgs"):
                    d[k] = json.loads(d[k] or "[]")
                d.pop("raw", None)
                out.append(d)
            return out
        finally:
            if own:
                conn.close()

    def inbound_alerts(self, limit: int = 20) -> list[dict]:
        return [d for d in self.decisions(200) if d["accepted"]][:limit]

    def status(self) -> dict:
        f = self.read_feed(live=False) if self.feed["items"] else dict(self.feed, count=0, matched=0, by_state={})
        with self.lock:
            counts = dict(self.counts)
        return {"feed": {k: v for k, v in f.items() if k != "items"}, "ingest": {"accepted": counts.get("accepted", 0),
                "refused": {r: counts.get(r, 0) for r in REFUSALS}, "total": sum(counts.values())},
                "trusted": {"domains": list(TRUSTED_DOMAINS), "prefixes": list(TRUSTED_PREFIXES), "own": OWN_SENDER},
                "limits": {"max_bytes": MAX_XML_BYTES, "rate_per_minute": RATE_MAX}, "how": "validate, don't trust: flood, DTD and size, "
                "well-formed CAP, required fields, authorised sender, replay, stale; every decision in the audit trail"}


ENGINE: CapGuard | None = None
