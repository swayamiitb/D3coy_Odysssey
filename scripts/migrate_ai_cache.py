"""One-off: move AI briefs/translations from the old in-database tables (data/ews.db: briefs, translations) into
the content-addressed cache (data/cache.db), keyed exactly as the API now computes keys.
Run with the API stopped, before rebuilding data/ews.db.
"""

import json
import sqlite3
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from backend.app import cache, main  # noqa: E402
from backend.app.ai.narrate import SYSTEM, build_facts  # noqa: E402


def main_() -> int:
    db = sqlite3.connect(ROOT / "data" / "ews.db")
    tables = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    moved = {"brief": 0, "translate": 0}
    if "briefs" in tables:
        for org, cve, model, created, body in db.execute("SELECT org_id, cve_id, model, created, body FROM briefs"):
            detail = main.alert_detail(org, cve)
            cache.put("brief", cache.key_of("brief", model, SYSTEM, build_facts(detail)), json.loads(body), created,
                      f"{org}:{cve}")
            moved["brief"] += 1
    if "translations" in tables:
        for org, cve, lang, created, body in db.execute("SELECT org_id, cve_id, lang, created, body FROM translations"):
            b = json.loads(body)
            texts = [b["headline"]["source"]] + [x["source"] for x in b["why_it_matters"] + b["what_to_do"]]
            detail = main.alert_detail(org, cve)
            protect = sorted({a["label"] for a in detail["assets"]} | {detail["org"]["name"]})
            cache.put("translate", cache.key_of("translate", lang, texts, protect), b, created, f"{org}:{cve}:{lang}")
            moved["translate"] += 1
    print("migrated", moved)
    return 0


if __name__ == "__main__":
    sys.exit(main_())
